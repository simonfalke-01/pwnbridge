package recovery

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/simonfalke-01/pwnbridge/internal/fsutil"
)

const (
	MaxArchiveEntries = 1_000_000
	MaxArchiveName    = 4096
	MaxArchiveLink    = 4096
	archiveTrailer    = "PWNBRIDGE-RECOVERY-ARCHIVE-V1\n"
	progressByteStep  = 256 << 10
	progressItemStep  = 64
)

var archiveEpoch = time.Unix(0, 0).UTC()

var (
	ErrUnverified        = errors.New("recovery copy has no recorded digest")
	ErrIntegrityMismatch = errors.New("recovery copy does not match its recorded integrity metadata")
)

// ArchiveSummary describes the deterministic stream and its root object.
type ArchiveSummary struct {
	SHA256      string `json:"sha256"`
	Kind        string `json:"kind"`
	Size        int64  `json:"size"`
	Items       int64  `json:"items"`
	Mode        uint32 `json:"mode"`
	ArchiveSize int64  `json:"archive_size"`
}

// ArchiveProgress reports source content consumed while producing the
// deterministic archive. Bytes excludes tar headers and padding; Items counts
// regular files, directories, and symbolic links after they are inspected.
type ArchiveProgress struct {
	Bytes int64
	Items int64
}

// Observation is an opaque identity captured while a source archive is read.
type Observation struct {
	info os.FileInfo
}

type archiveWriter struct {
	tar            *tar.Writer
	items          int64
	size           int64
	processedBytes int64
	reportedBytes  int64
	reportedItems  int64
	root           ArchiveSummary
	topInfo        os.FileInfo
	progress       func(ArchiveProgress)
}

type countingHashWriter struct {
	target io.Writer
	hash   hash.Hash
	bytes  int64
}

func (w *countingHashWriter) Write(data []byte) (int, error) {
	n, err := w.target.Write(data)
	if n > 0 {
		_, _ = w.hash.Write(data[:n])
		w.bytes += int64(n)
	}
	return n, err
}

// WriteArchive emits a deterministic, uncompressed tar stream for one rooted
// object. It supports regular files, directories, and symbolic links only.
func WriteArchive(rootPath, name string, output io.Writer) (ArchiveSummary, *Observation, error) {
	return WriteArchiveProgress(rootPath, name, output, nil)
}

// WriteArchiveProgress is WriteArchive with optional monotonic source progress.
// The callback runs synchronously and should return quickly.
func WriteArchiveProgress(rootPath, name string, output io.Writer, progress func(ArchiveProgress)) (ArchiveSummary, *Observation, error) {
	if err := ValidateRelative(name); err != nil {
		return ArchiveSummary{}, nil, err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return ArchiveSummary{}, nil, fmt.Errorf("open archive root: %w", err)
	}
	defer root.Close()
	digest := sha256.New()
	stream := &countingHashWriter{target: output, hash: digest}
	writer := &archiveWriter{tar: tar.NewWriter(stream), progress: progress}
	if err := writer.writeNode(root, name, ".", true); err != nil {
		// Do not close the tar writer after a source failure. Close emits valid end
		// markers, which could make an already-written directory prefix appear to
		// the receiver as a complete archive. An unterminated stream is rejected.
		return ArchiveSummary{}, nil, err
	}
	writer.reportProgress(true)
	if err := writer.tar.Close(); err != nil {
		return ArchiveSummary{}, nil, fmt.Errorf("finish recovery archive: %w", err)
	}
	if n, err := io.WriteString(stream, archiveTrailer); err != nil || n != len(archiveTrailer) {
		return ArchiveSummary{}, nil, fmt.Errorf("write recovery archive trailer: %w", errors.Join(err, io.ErrShortWrite))
	}
	writer.root.SHA256 = hex.EncodeToString(digest.Sum(nil))
	writer.root.ArchiveSize = stream.bytes
	return writer.root, &Observation{info: writer.topInfo}, nil
}

// Digest computes the deterministic archive identity without retaining bytes.
func Digest(rootPath, name string) (ArchiveSummary, error) {
	return DigestContext(context.Background(), rootPath, name)
}

// DigestContext computes the deterministic archive identity and stops archive
// generation when the caller cancels the scan.
func DigestContext(ctx context.Context, rootPath, name string) (ArchiveSummary, error) {
	return DigestContextProgress(ctx, rootPath, name, nil)
}

// DigestContextProgress computes the deterministic identity while reporting
// source content consumed. Cancellation remains enforced by the archive output
// boundary, including during large regular-file reads.
func DigestContextProgress(ctx context.Context, rootPath, name string, progress func(ArchiveProgress)) (ArchiveSummary, error) {
	if err := ctx.Err(); err != nil {
		return ArchiveSummary{}, err
	}
	summary, _, err := WriteArchiveProgress(rootPath, name, contextWriter{ctx: ctx, target: io.Discard}, progress)
	return summary, err
}

type contextWriter struct {
	ctx    context.Context
	target io.Writer
}

func (w contextWriter) Write(data []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	return w.target.Write(data)
}

// Verify checks one inventory entry against its recorded deterministic digest
// and structural metadata. It never writes or repairs recovery state.
func Verify(ctx context.Context, rootPath string, entry Entry) error {
	return VerifyProgress(ctx, rootPath, entry, nil)
}

// VerifyProgress is Verify with optional monotonic source progress.
func VerifyProgress(ctx context.Context, rootPath string, entry Entry, progress func(ArchiveProgress)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateRelative(entry.ID); err != nil {
		return fmt.Errorf("invalid recovery ID: %w", err)
	}
	if entry.SHA256 == "" {
		return ErrUnverified
	}
	if !validDigest(entry.SHA256) {
		return errors.New("recovery copy has an invalid recorded digest")
	}
	summary, err := DigestContextProgress(ctx, rootPath, entry.ID, progress)
	if err != nil {
		return fmt.Errorf("read recovery copy: %w", err)
	}
	if summary.SHA256 != entry.SHA256 || summary.Kind != entry.Kind || summary.Size != entry.Size || summary.Items != entry.Items || summary.Mode != entry.Mode {
		return ErrIntegrityMismatch
	}
	return nil
}

func (w *archiveWriter) writeNode(root *os.Root, name, archiveName string, top bool) error {
	if w.items >= MaxArchiveEntries {
		return fmt.Errorf("recovery archive exceeds %d entries", MaxArchiveEntries)
	}
	if len(archiveName) > MaxArchiveName {
		return fmt.Errorf("recovery archive path exceeds %d bytes", MaxArchiveName)
	}
	info, err := root.Lstat(name)
	if err != nil {
		return fmt.Errorf("inspect archive source %q: %w", name, err)
	}
	w.items++
	w.reportProgress(false)
	if top {
		w.topInfo = info
		w.root.Mode = uint32(info.Mode().Perm())
	}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		target, err := root.Readlink(name)
		if err != nil {
			return fmt.Errorf("read archive link %q: %w", name, err)
		}
		if len(target) > MaxArchiveLink {
			return fmt.Errorf("archive link %q exceeds %d bytes", name, MaxArchiveLink)
		}
		latest, err := root.Lstat(name)
		if err != nil || !sameObservedFile(info, latest) {
			return fmt.Errorf("archive link %q changed while it was read", name)
		}
		if err := w.tar.WriteHeader(archiveHeader(archiveName, info.Mode().Perm(), tar.TypeSymlink, 0, target)); err != nil {
			return err
		}
		w.size += int64(len(target))
		w.processedBytes += int64(len(target))
		w.reportProgress(false)
		if top {
			w.root.Kind = "symlink"
		}
	case info.IsDir():
		if err := w.writeDirectory(root, name, archiveName, info); err != nil {
			return err
		}
		if top {
			w.root.Kind = "directory"
		}
	case info.Mode().IsRegular():
		if err := w.writeRegular(root, name, archiveName, info); err != nil {
			return err
		}
		w.size += info.Size()
		if top {
			w.root.Kind = "regular"
		}
	default:
		return fmt.Errorf("refuse to archive special file %q", name)
	}
	w.root.Size = w.size
	w.root.Items = w.items
	return nil
}

func (w *archiveWriter) writeDirectory(root *os.Root, name, archiveName string, expected os.FileInfo) error {
	directory, err := root.OpenRoot(name)
	if err != nil {
		return fmt.Errorf("open archive directory %q: %w", name, err)
	}
	defer directory.Close()
	opened, err := directory.Lstat(".")
	if err != nil || !opened.IsDir() || !os.SameFile(expected, opened) {
		return fmt.Errorf("archive directory %q changed while it was opened", name)
	}
	if err := w.tar.WriteHeader(archiveHeader(archiveName, expected.Mode().Perm(), tar.TypeDir, 0, "")); err != nil {
		return err
	}
	entries, err := fs.ReadDir(directory.FS(), ".")
	if err != nil {
		return fmt.Errorf("read archive directory %q: %w", name, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if !fs.ValidPath(entry.Name()) || strings.Contains(entry.Name(), "/") {
			return fmt.Errorf("archive directory %q contains an invalid name", name)
		}
		childArchive := entry.Name()
		if archiveName != "." {
			childArchive = path.Join(archiveName, entry.Name())
		}
		if err := w.writeNode(directory, entry.Name(), childArchive, false); err != nil {
			return err
		}
	}
	latest, err := directory.Lstat(".")
	if err != nil || !sameObservedFile(opened, latest) {
		return fmt.Errorf("archive directory %q changed while it was read", name)
	}
	return nil
}

func (w *archiveWriter) writeRegular(root *os.Root, name, archiveName string, expected os.FileInfo) error {
	file, err := root.OpenFile(name, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open archive file %q: %w", name, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(expected, opened) || opened.Size() != expected.Size() {
		return fmt.Errorf("archive file %q changed while it was opened", name)
	}
	if err := w.tar.WriteHeader(archiveHeader(archiveName, expected.Mode().Perm(), tar.TypeReg, opened.Size(), "")); err != nil {
		return err
	}
	reader := io.Reader(file)
	if w.progress != nil {
		reader = archiveProgressReader{source: file, writer: w}
	}
	if _, err := io.CopyN(w.tar, reader, opened.Size()); err != nil {
		return fmt.Errorf("read archive file %q: %w", name, err)
	}
	latest, err := file.Stat()
	if err != nil || !sameObservedFile(opened, latest) {
		return fmt.Errorf("archive file %q changed while it was read", name)
	}
	return nil
}

type archiveProgressReader struct {
	source io.Reader
	writer *archiveWriter
}

func (r archiveProgressReader) Read(data []byte) (int, error) {
	n, err := r.source.Read(data)
	if n > 0 {
		r.writer.processedBytes += int64(n)
		r.writer.reportProgress(false)
	}
	return n, err
}

func (w *archiveWriter) reportProgress(force bool) {
	if w.progress == nil {
		return
	}
	if force && w.processedBytes == w.reportedBytes && w.items == w.reportedItems {
		return
	}
	if !force && w.processedBytes-w.reportedBytes < progressByteStep && w.items-w.reportedItems < progressItemStep {
		return
	}
	w.reportedBytes, w.reportedItems = w.processedBytes, w.items
	w.progress(ArchiveProgress{Bytes: w.processedBytes, Items: w.items})
}

func archiveHeader(name string, mode os.FileMode, kind byte, size int64, link string) *tar.Header {
	return &tar.Header{
		Typeflag: kind, Name: name, Linkname: link, Size: size, Mode: int64(mode.Perm()),
		ModTime: archiveEpoch, AccessTime: archiveEpoch, ChangeTime: archiveEpoch,
		Format: tar.FormatGNU,
	}
}

type countingHashReader struct {
	source io.Reader
	hash   hash.Hash
	bytes  int64
}

func (r *countingHashReader) Read(data []byte) (int, error) {
	n, err := r.source.Read(data)
	if n > 0 {
		_, _ = r.hash.Write(data[:n])
		r.bytes += int64(n)
	}
	return n, err
}

type extractedDirectory struct {
	name string
	mode os.FileMode
}

// ExtractArchive validates and durably extracts the deterministic archive
// subset below one exclusive destination. It stops at tar end markers without
// waiting for the underlying stream to close so a bidirectional ACK can follow.
func ExtractArchive(input io.Reader, destinationRoot, destinationPath string) (ArchiveSummary, error) {
	if err := ValidateRelative(destinationPath); err != nil {
		return ArchiveSummary{}, err
	}
	if err := os.MkdirAll(destinationRoot, 0o700); err != nil {
		return ArchiveSummary{}, fmt.Errorf("create extraction root: %w", err)
	}
	root, err := os.OpenRoot(destinationRoot)
	if err != nil {
		return ArchiveSummary{}, fmt.Errorf("open extraction root: %w", err)
	}
	defer root.Close()
	if _, err := root.Lstat(destinationPath); err == nil {
		return ArchiveSummary{}, fmt.Errorf("destination %q already exists", destinationPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return ArchiveSummary{}, err
	}
	if parent := filepath.Dir(destinationPath); parent != "." {
		if err := root.MkdirAll(parent, 0o700); err != nil {
			return ArchiveSummary{}, err
		}
	}
	digest := sha256.New()
	stream := &countingHashReader{source: input, hash: digest}
	reader := tar.NewReader(stream)
	types := map[string]string{}
	var directories []extractedDirectory
	var summary ArchiveSummary
	owned := false
	cleanup := func(extractErr error) (ArchiveSummary, error) {
		if owned {
			if removeErr := root.RemoveAll(destinationPath); removeErr != nil {
				return ArchiveSummary{}, errors.Join(extractErr, fmt.Errorf("remove partial extraction %q: %w", destinationPath, removeErr))
			}
			_ = syncRootDirectory(root, filepath.Dir(destinationPath))
		}
		return ArchiveSummary{}, extractErr
	}
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return cleanup(fmt.Errorf("read recovery archive: %w", err))
		}
		if summary.Items >= MaxArchiveEntries {
			return cleanup(fmt.Errorf("recovery archive exceeds %d entries", MaxArchiveEntries))
		}
		if err := validateArchiveHeader(header, summary.Items == 0, types); err != nil {
			return cleanup(err)
		}
		archiveName := header.Name
		target := destinationPath
		if archiveName != "." {
			target = filepath.Join(destinationPath, filepath.FromSlash(archiveName))
		}
		created, err := extractHeader(reader, root, target, header, &directories)
		if summary.Items == 0 && created {
			owned = true
		}
		if err != nil {
			return cleanup(err)
		}
		if summary.Items == 0 {
			summary.Kind = headerKind(header.Typeflag)
			// validateArchiveHeader proved this value is in [0, 0777].
			summary.Mode = uint32(header.Mode) // #nosec G115
		}
		types[archiveName] = headerKind(header.Typeflag)
		summary.Items++
		if header.Typeflag == tar.TypeReg {
			summary.Size += header.Size
		} else if header.Typeflag == tar.TypeSymlink {
			summary.Size += int64(len(header.Linkname))
		}
	}
	if summary.Items == 0 {
		return cleanup(errors.New("recovery archive is empty"))
	}
	trailer := make([]byte, len(archiveTrailer))
	if _, err := io.ReadFull(stream, trailer); err != nil || !bytes.Equal(trailer, []byte(archiveTrailer)) {
		return cleanup(errors.New("recovery archive is incomplete or has an invalid trailer"))
	}
	for index := len(directories) - 1; index >= 0; index-- {
		directory := directories[index]
		if err := root.Chmod(directory.name, directory.mode); err != nil {
			return cleanup(fmt.Errorf("set extracted directory mode %q: %w", directory.name, err))
		}
		if err := syncRootDirectory(root, directory.name); err != nil {
			return cleanup(err)
		}
	}
	if err := syncRootDirectoryChain(root, filepath.Dir(destinationPath)); err != nil {
		return cleanup(err)
	}
	summary.SHA256 = hex.EncodeToString(digest.Sum(nil))
	summary.ArchiveSize = stream.bytes
	return summary, nil
}

func validateArchiveHeader(header *tar.Header, first bool, types map[string]string) error {
	if header == nil {
		return errors.New("recovery archive contains a nil header")
	}
	if len(header.Name) > MaxArchiveName || header.Name == "" {
		return errors.New("recovery archive contains an invalid path length")
	}
	if first {
		if header.Name != "." {
			return errors.New("recovery archive does not begin with its root entry")
		}
	} else {
		if header.Name == "." || !fs.ValidPath(header.Name) || path.Clean(header.Name) != header.Name {
			return fmt.Errorf("recovery archive path %q is not local and canonical", header.Name)
		}
		parent := path.Dir(header.Name)
		if parent == "." {
			parent = "."
		}
		if types[parent] != "directory" {
			return fmt.Errorf("recovery archive parent %q is not a preceding directory", parent)
		}
	}
	if _, exists := types[header.Name]; exists {
		return fmt.Errorf("recovery archive path %q appears more than once", header.Name)
	}
	if header.Format != tar.FormatGNU || header.Mode < 0 || header.Mode > 0o777 || header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" || header.Devmajor != 0 || header.Devminor != 0 || len(header.PAXRecords) != 0 || !header.ModTime.Equal(archiveEpoch) || !header.AccessTime.Equal(archiveEpoch) || !header.ChangeTime.Equal(archiveEpoch) {
		return fmt.Errorf("recovery archive header %q contains unsupported metadata", header.Name)
	}
	switch header.Typeflag {
	case tar.TypeReg:
		if header.Size < 0 || header.Linkname != "" {
			return fmt.Errorf("recovery archive file %q has invalid metadata", header.Name)
		}
	case tar.TypeDir:
		if header.Size != 0 || header.Linkname != "" {
			return fmt.Errorf("recovery archive directory %q has invalid metadata", header.Name)
		}
	case tar.TypeSymlink:
		if header.Size != 0 || len(header.Linkname) > MaxArchiveLink {
			return fmt.Errorf("recovery archive link %q has invalid metadata", header.Name)
		}
	default:
		return fmt.Errorf("recovery archive path %q has unsupported type %d", header.Name, header.Typeflag)
	}
	return nil
}

func extractHeader(reader *tar.Reader, root *os.Root, target string, header *tar.Header, directories *[]extractedDirectory) (bool, error) {
	// validateArchiveHeader proved this value is in [0, 0777].
	mode := os.FileMode(header.Mode) // #nosec G115
	switch header.Typeflag {
	case tar.TypeReg:
		file, err := root.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			return false, fmt.Errorf("create extracted file %q: %w", target, err)
		}
		if _, err := io.CopyN(file, reader, header.Size); err != nil {
			_ = file.Close()
			return true, fmt.Errorf("write extracted file %q: %w", target, err)
		}
		if err := file.Chmod(mode); err != nil {
			_ = file.Close()
			return true, err
		}
		if err := fsutil.SyncFile(file); err != nil {
			_ = file.Close()
			return true, fmt.Errorf("sync extracted file %q: %w", target, err)
		}
		if err := file.Close(); err != nil {
			return true, err
		}
		return true, syncRootDirectory(root, filepath.Dir(target))
	case tar.TypeDir:
		if err := root.Mkdir(target, mode); err != nil {
			return false, fmt.Errorf("create extracted directory %q: %w", target, err)
		}
		*directories = append(*directories, extractedDirectory{name: target, mode: mode})
		return true, nil
	case tar.TypeSymlink:
		if err := root.Symlink(header.Linkname, target); err != nil {
			return false, fmt.Errorf("create extracted link %q: %w", target, err)
		}
		return true, syncRootDirectory(root, filepath.Dir(target))
	default:
		return false, errors.New("unreachable archive type")
	}
}

func headerKind(kind byte) string {
	switch kind {
	case tar.TypeReg:
		return "regular"
	case tar.TypeDir:
		return "directory"
	case tar.TypeSymlink:
		return "symlink"
	default:
		return "unknown"
	}
}

// VerifyAndRemove regenerates the deterministic digest, binds the top object
// identity to the streamed observation, and removes through a held root.
func VerifyAndRemove(rootPath, name, expectedDigest string, observed *Observation) error {
	if observed == nil || observed.info == nil || !validDigest(expectedDigest) {
		return errors.New("invalid recovery removal verification")
	}
	current, currentObservation, err := WriteArchive(rootPath, name, io.Discard)
	if err != nil {
		return fmt.Errorf("verify remote loser: %w", err)
	}
	if current.SHA256 != expectedDigest || !os.SameFile(observed.info, currentObservation.info) {
		return errors.New("remote loser changed after it was streamed; it was not removed")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	latest, err := root.Lstat(name)
	if err != nil || !sameObservedFile(observed.info, latest) {
		return errors.New("remote loser changed before removal; it was not removed")
	}
	if err := root.RemoveAll(name); err != nil {
		return fmt.Errorf("remove verified remote loser %q: %w", name, err)
	}
	return syncRootDirectoryChain(root, filepath.Dir(name))
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}
