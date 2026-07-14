package recovery

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/simonfalke-01/pwnbridge/internal/fsutil"
)

const (
	manifestName     = "manifest.json"
	manifestSchema   = 1
	maxManifestBytes = 1 << 20
	prunePrefix      = ".pwnbridge-prune-"
)

// Entry describes one independently restorable recovery copy.
type Entry struct {
	ID           string    `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	Winner       string    `json:"winner"`
	Loser        string    `json:"loser"`
	OriginalPath string    `json:"original_path"`
	Kind         string    `json:"kind"`
	Size         int64     `json:"size"`
	Items        int64     `json:"items"`
	Mode         uint32    `json:"mode"`
	SHA256       string    `json:"sha256,omitempty"`
	Legacy       bool      `json:"legacy,omitempty"`
}

// Archive is the whole retention unit created by one conflict resolution.
// Size is logical content bytes and does not claim filesystem allocation.
type Archive struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Entries   int       `json:"entries"`
	Size      int64     `json:"size"`
	Items     int64     `json:"items"`
	Legacy    bool      `json:"legacy,omitempty"`
}

// PruneResult describes an archive that has been removed from the visible
// catalog. CleanupPending means its hidden tombstone may still consume space.
type PruneResult struct {
	Archive        Archive `json:"archive"`
	CleanupPending bool    `json:"cleanup_pending,omitempty"`
}

type manifest struct {
	Schema    int             `json:"schema"`
	CreatedAt time.Time       `json:"created_at"`
	Winner    string          `json:"winner"`
	Entries   []manifestEntry `json:"entries"`
}

type manifestEntry struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Size   int64  `json:"size"`
	Items  int64  `json:"items"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256,omitempty"`
}

// ArchiveName returns a sortable, nanosecond-qualified UTC recovery directory.
func ArchiveName(now time.Time) string {
	return now.UTC().Format("20060102T150405.000000000Z")
}

// BackupID returns the stable identifier and relative storage path for an entry.
func BackupID(archive, winner, originalPath string) (string, error) {
	if _, err := parseArchiveTime(archive); err != nil {
		return "", err
	}
	if winner != "local" && winner != "remote" {
		return "", errors.New("recovery winner must be local or remote")
	}
	if err := ValidateRelative(originalPath); err != nil {
		return "", fmt.Errorf("invalid recovery path: %w", err)
	}
	return filepath.Join(archive, winner+"-winner", originalPath), nil
}

// ValidateRelative requires a non-empty, canonical path contained by a root.
func ValidateRelative(name string) error {
	if name == "" || strings.IndexByte(name, 0) >= 0 || !filepath.IsLocal(name) {
		return errors.New("path must be non-empty, relative, and contained by the project")
	}
	if cleaned := filepath.Clean(name); cleaned == "." || cleaned != name {
		return errors.New("path must be canonical and may not contain dot components")
	}
	return nil
}

// Copy copies one regular file, directory tree, or symbolic link between held
// filesystem roots. The destination must not already exist.
func Copy(sourceRoot, sourcePath, destinationRoot, destinationPath string) error {
	return copyWithHooks(sourceRoot, sourcePath, destinationRoot, destinationPath, copyHooks{syncFile: fsutil.SyncFile})
}

type copyHooks struct {
	afterInspect       func(string)
	afterDirectoryOpen func(string)
	syncFile           func(*os.File) error
}

func copyWithHooks(sourceRoot, sourcePath, destinationRoot, destinationPath string, hooks copyHooks) error {
	if err := ValidateRelative(sourcePath); err != nil {
		return fmt.Errorf("invalid source: %w", err)
	}
	if err := ValidateRelative(destinationPath); err != nil {
		return fmt.Errorf("invalid destination: %w", err)
	}
	source, err := os.OpenRoot(sourceRoot)
	if err != nil {
		return fmt.Errorf("open source root: %w", err)
	}
	defer source.Close()
	if err := os.MkdirAll(destinationRoot, 0o700); err != nil {
		return fmt.Errorf("create destination root: %w", err)
	}
	destination, err := os.OpenRoot(destinationRoot)
	if err != nil {
		return fmt.Errorf("open destination root: %w", err)
	}
	defer destination.Close()
	if _, err := destination.Lstat(destinationPath); err == nil {
		return fmt.Errorf("destination %q already exists", destinationPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect destination %q: %w", destinationPath, err)
	}
	if parent := filepath.Dir(destinationPath); parent != "." {
		if err := destination.MkdirAll(parent, 0o700); err != nil {
			return fmt.Errorf("create destination parents: %w", err)
		}
	}
	owned := false
	if err := copyNode(source, sourcePath, destination, destinationPath, true, &owned, hooks); err != nil {
		if owned {
			if cleanupErr := destination.RemoveAll(destinationPath); cleanupErr != nil {
				return errors.Join(err, fmt.Errorf("remove partial destination %q: %w", destinationPath, cleanupErr))
			}
			_ = syncRootDirectory(destination, filepath.Dir(destinationPath))
		}
		return err
	}
	return syncRootDirectoryChain(destination, filepath.Dir(destinationPath))
}

func copyNode(source *os.Root, sourcePath string, destination *os.Root, destinationPath string, top bool, owned *bool, hooks copyHooks) error {
	info, err := source.Lstat(sourcePath)
	if err != nil {
		return fmt.Errorf("inspect source %q: %w", sourcePath, err)
	}
	if hooks.afterInspect != nil {
		hooks.afterInspect(sourcePath)
	}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		target, err := source.Readlink(sourcePath)
		if err != nil {
			return fmt.Errorf("read source link %q: %w", sourcePath, err)
		}
		latest, err := source.Lstat(sourcePath)
		if err != nil || !sameObservedFile(info, latest) {
			return fmt.Errorf("source link %q changed while it was read", sourcePath)
		}
		if err := destination.Symlink(target, destinationPath); err != nil {
			return fmt.Errorf("create destination link %q: %w", destinationPath, err)
		}
		if top {
			*owned = true
		}
		return syncRootDirectory(destination, filepath.Dir(destinationPath))
	case info.IsDir():
		return copyDirectory(source, sourcePath, info, destination, destinationPath, top, owned, hooks)
	case info.Mode().IsRegular():
		return copyRegular(source, sourcePath, info, destination, destinationPath, top, owned, hooks)
	default:
		return fmt.Errorf("refuse to copy special file %q", sourcePath)
	}
}

func copyDirectory(source *os.Root, sourcePath string, expected os.FileInfo, destination *os.Root, destinationPath string, top bool, owned *bool, hooks copyHooks) error {
	directory, err := source.OpenRoot(sourcePath)
	if err != nil {
		return fmt.Errorf("open source directory %q: %w", sourcePath, err)
	}
	defer directory.Close()
	opened, err := directory.Lstat(".")
	if err != nil || !opened.IsDir() || !os.SameFile(expected, opened) {
		return fmt.Errorf("source directory %q changed while it was opened", sourcePath)
	}
	if hooks.afterDirectoryOpen != nil {
		hooks.afterDirectoryOpen(sourcePath)
	}
	entries, err := fs.ReadDir(directory.FS(), ".")
	if err != nil {
		return fmt.Errorf("read source directory %q: %w", sourcePath, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	if err := destination.Mkdir(destinationPath, expected.Mode().Perm()); err != nil {
		return fmt.Errorf("create destination directory %q: %w", destinationPath, err)
	}
	if top {
		*owned = true
	}
	for _, entry := range entries {
		if !fs.ValidPath(entry.Name()) || strings.Contains(entry.Name(), "/") {
			return fmt.Errorf("source directory %q contains an invalid name", sourcePath)
		}
		if err := copyNode(directory, entry.Name(), destination, filepath.Join(destinationPath, entry.Name()), false, owned, hooks); err != nil {
			return err
		}
	}
	latest, err := directory.Lstat(".")
	if err != nil || !sameObservedFile(opened, latest) {
		return fmt.Errorf("source directory %q changed while it was copied", sourcePath)
	}
	if err := destination.Chmod(destinationPath, expected.Mode().Perm()); err != nil {
		return fmt.Errorf("set destination directory mode %q: %w", destinationPath, err)
	}
	return syncRootDirectory(destination, destinationPath)
}

func copyRegular(source *os.Root, sourcePath string, expected os.FileInfo, destination *os.Root, destinationPath string, top bool, owned *bool, hooks copyHooks) error {
	in, err := source.OpenFile(sourcePath, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open source file %q: %w", sourcePath, err)
	}
	defer in.Close()
	opened, err := in.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(expected, opened) || opened.Size() != expected.Size() {
		return fmt.Errorf("source file %q changed while it was opened", sourcePath)
	}
	out, err := destination.OpenFile(destinationPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, expected.Mode().Perm())
	if err != nil {
		return fmt.Errorf("create destination file %q: %w", destinationPath, err)
	}
	if top {
		*owned = true
	}
	if _, err := io.CopyN(out, in, opened.Size()); err != nil {
		_ = out.Close()
		return fmt.Errorf("copy source file %q: %w", sourcePath, err)
	}
	latest, err := in.Stat()
	if err != nil || !sameObservedFile(opened, latest) {
		_ = out.Close()
		return fmt.Errorf("source file %q changed while it was copied", sourcePath)
	}
	if err := out.Chmod(expected.Mode().Perm()); err != nil {
		_ = out.Close()
		return fmt.Errorf("set destination file mode %q: %w", destinationPath, err)
	}
	if err := hooks.syncFile(out); err != nil {
		_ = out.Close()
		return fmt.Errorf("sync destination file %q: %w", destinationPath, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close destination file %q: %w", destinationPath, err)
	}
	return syncRootDirectory(destination, filepath.Dir(destinationPath))
}

func sameObservedFile(before, after os.FileInfo) bool {
	return after != nil && os.SameFile(before, after) && before.Mode() == after.Mode() && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}

// RemoveAll removes a relative path without allowing traversal outside root.
func RemoveAll(rootPath, name string) error {
	return removeAll(rootPath, name, nil)
}

func removeAll(rootPath, name string, afterOpen func()) error {
	if err := ValidateRelative(name); err != nil {
		return err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return fmt.Errorf("open removal root: %w", err)
	}
	defer root.Close()
	if afterOpen != nil {
		afterOpen()
	}
	if err := root.RemoveAll(name); err != nil {
		return fmt.Errorf("remove %q: %w", name, err)
	}
	return syncRootDirectoryChain(root, filepath.Dir(name))
}

// Record adds one completed backup to its archive manifest. Callers must do
// this before deleting the losing endpoint copy.
func Record(rootPath, archive, winner, originalPath string) (Entry, error) {
	id, err := BackupID(archive, winner, originalPath)
	if err != nil {
		return Entry{}, err
	}
	summary, err := Digest(rootPath, id)
	if err != nil {
		return Entry{}, fmt.Errorf("digest recovery copy: %w", err)
	}
	return RecordSummary(rootPath, archive, winner, originalPath, summary)
}

// RecordSummary records a stream that has already been durably extracted and
// hashed by ExtractArchive. Structural metadata is checked against local state.
func RecordSummary(rootPath, archive, winner, originalPath string, summary ArchiveSummary) (Entry, error) {
	id, err := BackupID(archive, winner, originalPath)
	if err != nil {
		return Entry{}, err
	}
	if !validDigest(summary.SHA256) || !validKind(summary.Kind) || summary.Size < 0 || summary.Items < 1 || summary.Mode > 0o777 {
		return Entry{}, errors.New("invalid recovery archive summary")
	}
	if err := os.MkdirAll(rootPath, 0o700); err != nil {
		return Entry{}, err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return Entry{}, err
	}
	defer root.Close()
	createdAt, _ := parseArchiveTime(archive)
	described, err := describe(root, id)
	if err != nil {
		return Entry{}, fmt.Errorf("describe recovery copy: %w", err)
	}
	described.ID = id
	described.CreatedAt = createdAt
	described.Winner = winner
	described.Loser = opposite(winner)
	described.OriginalPath = originalPath
	described.SHA256 = summary.SHA256
	if described.Kind != summary.Kind || described.Size != summary.Size || described.Items != summary.Items || described.Mode != summary.Mode {
		return Entry{}, errors.New("recovery copy does not match its archive summary")
	}
	manifestPath := filepath.Join(archive, manifestName)
	current := manifest{Schema: manifestSchema, CreatedAt: createdAt, Winner: winner}
	if manifestInfo, err := root.Lstat(manifestPath); err == nil {
		if !manifestInfo.Mode().IsRegular() {
			return Entry{}, fmt.Errorf("recovery manifest %q is not a regular file", manifestPath)
		}
		if err := readManifest(root, manifestPath, &current); err != nil {
			return Entry{}, err
		}
		if !current.CreatedAt.Equal(createdAt) || current.Winner != winner {
			return Entry{}, errors.New("recovery manifest does not match its archive")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Entry{}, err
	}
	for _, existing := range current.Entries {
		if existing.Path == originalPath {
			return Entry{}, fmt.Errorf("recovery path %q is already recorded", originalPath)
		}
	}
	current.Entries = append(current.Entries, manifestEntry{
		Path: originalPath, Kind: described.Kind, Size: described.Size,
		Items: described.Items, Mode: described.Mode, SHA256: described.SHA256,
	})
	if err := writeManifest(root, manifestPath, current); err != nil {
		return Entry{}, err
	}
	return described, nil
}

// List returns manifest entries and conservative leaf entries from legacy
// pre-manifest recovery archives.
func List(rootPath string) ([]Entry, error) {
	return list(rootPath, true)
}

// ListForVerification returns recorded manifest metadata without requiring the
// current copy to match it. Catalog structure remains strict; Verify performs
// each current-content check so one damaged entry does not hide later results.
func ListForVerification(rootPath string) ([]Entry, error) {
	return list(rootPath, false)
}

// ListArchives aggregates strict catalog entries into whole conflict-resolution
// archives. It uses recorded manifest metadata so damaged entry content remains
// visible as a retention unit and can still be diagnosed with Verify.
func ListArchives(rootPath string) ([]Archive, error) {
	entries, err := ListForVerification(rootPath)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]*Archive)
	for _, entry := range entries {
		archiveID, _, ok := strings.Cut(entry.ID, string(filepath.Separator))
		createdAt, timeErr := parseArchiveTime(archiveID)
		if !ok || timeErr != nil || !createdAt.Equal(entry.CreatedAt) {
			return nil, fmt.Errorf("invalid recovery archive ID %q", entry.ID)
		}
		archive := byID[archiveID]
		if archive == nil {
			archive = &Archive{ID: archiveID, CreatedAt: createdAt}
			byID[archiveID] = archive
		}
		if archive.Entries == math.MaxInt || entry.Size > math.MaxInt64-archive.Size || entry.Items > math.MaxInt64-archive.Items {
			return nil, fmt.Errorf("recovery archive %q totals overflow", archiveID)
		}
		archive.Entries++
		archive.Size += entry.Size
		archive.Items += entry.Items
		archive.Legacy = archive.Legacy || entry.Legacy
	}
	archives := make([]Archive, 0, len(byID))
	for _, archive := range byID {
		archives = append(archives, *archive)
	}
	sort.Slice(archives, func(i, j int) bool {
		if archives[i].CreatedAt.Equal(archives[j].CreatedAt) {
			return archives[i].ID < archives[j].ID
		}
		return archives[i].CreatedAt.After(archives[j].CreatedAt)
	})
	return archives, nil
}

type pruneHooks struct {
	afterRename   func(string, string)
	syncDirectory func(*os.Root, string) error
}

// PruneArchives durably removes complete selected archives from the visible
// catalog before reclaiming their content. Callers should hold the workspace
// lock for selection and this operation.
func PruneArchives(ctx context.Context, rootPath string, selected []Archive) ([]PruneResult, error) {
	return pruneArchives(ctx, rootPath, selected, pruneHooks{syncDirectory: syncRootDirectory})
}

func pruneArchives(ctx context.Context, rootPath string, selected []Archive, hooks pruneHooks) ([]PruneResult, error) {
	if hooks.syncDirectory == nil {
		hooks.syncDirectory = syncRootDirectory
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	current, err := ListArchives(rootPath)
	if err != nil {
		return nil, err
	}
	available := make(map[string]Archive, len(current))
	for _, archive := range current {
		available[archive.ID] = archive
	}
	seen := make(map[string]bool, len(selected))
	for _, archive := range selected {
		if seen[archive.ID] {
			return nil, fmt.Errorf("duplicate recovery archive %q", archive.ID)
		}
		seen[archive.ID] = true
		if actual, ok := available[archive.ID]; !ok || actual != archive {
			return nil, fmt.Errorf("recovery archive %q changed after selection", archive.ID)
		}
	}

	root, err := os.OpenRoot(rootPath)
	if errors.Is(err, os.ErrNotExist) && len(selected) == 0 {
		return []PruneResult{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open recovery root for pruning: %w", err)
	}
	defer root.Close()
	rootInfo, err := root.Lstat(".")
	if err != nil {
		return nil, fmt.Errorf("inspect recovery root for pruning: %w", err)
	}
	rootDevice, ok := fileDevice(rootInfo)
	if !ok {
		return nil, errors.New("recovery root has unavailable filesystem identity")
	}
	if err := cleanPruneTombstones(ctx, root, rootDevice, hooks.syncDirectory); err != nil {
		return nil, fmt.Errorf("clean stale recovery prune data: %w", err)
	}

	results := make([]PruneResult, 0, len(selected))
	for _, archive := range selected {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		info, err := root.Lstat(archive.ID)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return results, fmt.Errorf("recovery archive %q is not a directory", archive.ID)
		}
		if device, ok := fileDevice(info); !ok || device != rootDevice {
			return results, fmt.Errorf("recovery archive %q crosses a filesystem boundary", archive.ID)
		}
		tombstone, err := newPruneTombstone(root, archive.ID)
		if err != nil {
			return results, err
		}
		if err := root.Rename(archive.ID, tombstone); err != nil {
			return results, fmt.Errorf("stage recovery archive %q for pruning: %w", archive.ID, err)
		}
		if err := hooks.syncDirectory(root, "."); err != nil {
			rollbackRenameErr := root.Rename(tombstone, archive.ID)
			if rollbackRenameErr == nil {
				rollbackSyncErr := hooks.syncDirectory(root, ".")
				if rollbackSyncErr != nil {
					return results, errors.Join(fmt.Errorf("sync staged recovery archive %q: %w", archive.ID, err), fmt.Errorf("sync restored visible archive: %w", rollbackSyncErr))
				}
				return results, fmt.Errorf("sync staged recovery archive %q: %w", archive.ID, err)
			}
			results = append(results, PruneResult{Archive: archive, CleanupPending: true})
			return results, errors.Join(fmt.Errorf("sync staged recovery archive %q: %w", archive.ID, err), fmt.Errorf("restore visible archive: %w", rollbackRenameErr))
		}
		if hooks.afterRename != nil {
			hooks.afterRename(archive.ID, tombstone)
		}
		result := PruneResult{Archive: archive}
		if err := removeTreeContext(ctx, root, tombstone, rootDevice); err != nil {
			result.CleanupPending = true
			results = append(results, result)
			return results, fmt.Errorf("reclaim recovery archive %q: %w", archive.ID, err)
		}
		if err := hooks.syncDirectory(root, "."); err != nil {
			results = append(results, result)
			return results, fmt.Errorf("sync pruned recovery archive %q: %w", archive.ID, err)
		}
		results = append(results, result)
	}
	return results, nil
}

func newPruneTombstone(root *os.Root, archive string) (string, error) {
	if _, err := parseArchiveTime(archive); err != nil {
		return "", err
	}
	for range 8 {
		random := make([]byte, 12)
		if _, err := rand.Read(random); err != nil {
			return "", err
		}
		name := prunePrefix + archive + "-" + hex.EncodeToString(random)
		if _, err := root.Lstat(name); errors.Is(err, os.ErrNotExist) {
			return name, nil
		} else if err != nil {
			return "", err
		}
	}
	return "", errors.New("could not allocate a unique recovery prune name")
}

func cleanPruneTombstones(ctx context.Context, root *os.Root, rootDevice uint64, syncDirectory func(*os.Root, string) error) error {
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !validPruneTombstone(entry.Name()) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := root.Lstat(entry.Name())
		if err != nil {
			return err
		}
		device, ok := fileDevice(info)
		if !ok || device != rootDevice {
			return fmt.Errorf("prune tombstone %q crosses a filesystem boundary", entry.Name())
		}
		if err := removeTreeContext(ctx, root, entry.Name(), rootDevice); err != nil {
			return err
		}
		if err := syncDirectory(root, "."); err != nil {
			return err
		}
	}
	return nil
}

func validPruneTombstone(name string) bool {
	value, ok := strings.CutPrefix(name, prunePrefix)
	if !ok {
		return false
	}
	separator := strings.LastIndexByte(value, '-')
	if separator < 0 || len(value)-separator-1 != 24 {
		return false
	}
	for _, character := range value[separator+1:] {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	_, err := parseArchiveTime(value[:separator])
	return err == nil
}

func removeTreeContext(ctx context.Context, root *os.Root, name string, device uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if currentDevice, ok := fileDevice(info); !ok || currentDevice != device {
		return fmt.Errorf("refuse to cross filesystem boundary at %q", name)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return root.Remove(name)
	}
	directory, err := root.OpenRoot(name)
	if err != nil {
		return err
	}
	opened, err := directory.Lstat(".")
	if err != nil || !opened.IsDir() || !os.SameFile(info, opened) {
		directory.Close()
		return fmt.Errorf("prune directory %q changed while it was opened", name)
	}
	entries, err := fs.ReadDir(directory.FS(), ".")
	if err == nil {
		for _, entry := range entries {
			if !fs.ValidPath(entry.Name()) || strings.Contains(entry.Name(), "/") {
				err = fmt.Errorf("prune directory %q contains an invalid name", name)
				break
			}
			if err = removeTreeContext(ctx, directory, entry.Name(), device); err != nil {
				break
			}
		}
	}
	if err == nil {
		latest, statErr := root.Lstat(name)
		if statErr != nil || !latest.IsDir() || !os.SameFile(opened, latest) {
			err = fmt.Errorf("prune directory %q changed while it was removed", name)
		}
	}
	closeErr := directory.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	return root.Remove(name)
}

func fileDevice(info os.FileInfo) (uint64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(stat.Dev), true
}

func list(rootPath string, requireCurrentMetadata bool) ([]Entry, error) {
	root, err := os.OpenRoot(rootPath)
	if errors.Is(err, os.ErrNotExist) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open recovery root: %w", err)
	}
	defer root.Close()
	archives, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, fmt.Errorf("read recovery root: %w", err)
	}
	var result []Entry
	for _, archiveEntry := range archives {
		if !archiveEntry.IsDir() {
			continue
		}
		archive := archiveEntry.Name()
		createdAt, err := parseArchiveTime(archive)
		if err != nil {
			continue
		}
		manifestPath := filepath.Join(archive, manifestName)
		manifestInfo, manifestErr := root.Lstat(manifestPath)
		switch {
		case manifestErr == nil:
			if !manifestInfo.Mode().IsRegular() {
				return nil, fmt.Errorf("recovery manifest %q is not a regular file", manifestPath)
			}
			var stored manifest
			if err := readManifest(root, manifestPath, &stored); err != nil {
				return nil, err
			}
			entries, err := manifestEntries(root, archive, createdAt, stored, requireCurrentMetadata)
			if err != nil {
				return nil, err
			}
			result = append(result, entries...)
		case errors.Is(manifestErr, os.ErrNotExist):
			entries, err := legacyEntries(root, archive, createdAt)
			if err != nil {
				return nil, err
			}
			result = append(result, entries...)
		default:
			return nil, manifestErr
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	return result, nil
}

func manifestEntries(root *os.Root, archive string, createdAt time.Time, stored manifest, requireCurrentMetadata bool) ([]Entry, error) {
	if stored.Schema != manifestSchema || !stored.CreatedAt.Equal(createdAt) || (stored.Winner != "local" && stored.Winner != "remote") {
		return nil, fmt.Errorf("invalid recovery manifest in %q", archive)
	}
	seen := make(map[string]bool, len(stored.Entries))
	entries := make([]Entry, 0, len(stored.Entries))
	for _, item := range stored.Entries {
		id, err := BackupID(archive, stored.Winner, item.Path)
		if err != nil || seen[item.Path] || item.Size < 0 || item.Items < 1 || !validKind(item.Kind) || item.Mode > 0o777 || item.SHA256 != "" && !validDigest(item.SHA256) {
			return nil, fmt.Errorf("invalid recovery manifest entry in %q", archive)
		}
		seen[item.Path] = true
		current := Entry{Kind: item.Kind, Size: item.Size, Items: item.Items, Mode: item.Mode}
		if requireCurrentMetadata {
			current, err = describe(root, id)
			if err != nil {
				return nil, fmt.Errorf("inspect recovery entry %q: %w", id, err)
			}
			if current.Kind != item.Kind || current.Size != item.Size || current.Items != item.Items || current.Mode != item.Mode {
				return nil, fmt.Errorf("recovery entry %q no longer matches its manifest", id)
			}
		}
		current.ID = id
		current.CreatedAt = createdAt
		current.Winner = stored.Winner
		current.Loser = opposite(stored.Winner)
		current.OriginalPath = item.Path
		current.SHA256 = item.SHA256
		entries = append(entries, current)
	}
	return entries, nil
}

func legacyEntries(root *os.Root, archive string, createdAt time.Time) ([]Entry, error) {
	var entries []Entry
	err := fs.WalkDir(root.FS(), archive, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == archive {
			return nil
		}
		rel, err := filepath.Rel(archive, name)
		if err != nil {
			return err
		}
		components := strings.Split(rel, string(filepath.Separator))
		if len(components) == 1 {
			if components[0] != "local-winner" && components[0] != "remote-winner" {
				if entry.IsDir() {
					return fs.SkipDir
				}
			}
			return nil
		}
		winner := strings.TrimSuffix(components[0], "-winner")
		if winner != "local" && winner != "remote" {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			children, err := fs.ReadDir(root.FS(), name)
			if err != nil {
				return err
			}
			if len(children) != 0 {
				return nil
			}
		}
		original := filepath.Join(components[1:]...)
		current, err := describe(root, name)
		if err != nil {
			return err
		}
		current.ID = name
		current.CreatedAt = createdAt
		current.Winner = winner
		current.Loser = opposite(winner)
		current.OriginalPath = original
		current.Legacy = true
		entries = append(entries, current)
		return nil
	})
	return entries, err
}

func describe(root *os.Root, name string) (Entry, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return Entry{}, err
	}
	result := Entry{Mode: uint32(info.Mode().Perm())}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		target, err := root.Readlink(name)
		if err != nil {
			return Entry{}, err
		}
		result.Kind, result.Size, result.Items = "symlink", int64(len(target)), 1
	case info.Mode().IsRegular():
		result.Kind, result.Size, result.Items = "regular", info.Size(), 1
	case info.IsDir():
		result.Kind, result.Items = "directory", 1
		err := fs.WalkDir(root.FS(), name, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if path == name {
				return nil
			}
			entryInfo, err := entry.Info()
			if err != nil {
				return err
			}
			result.Items++
			switch {
			case entryInfo.Mode()&os.ModeSymlink != 0:
				target, err := root.Readlink(path)
				if err != nil {
					return err
				}
				result.Size += int64(len(target))
			case entryInfo.Mode().IsRegular():
				result.Size += entryInfo.Size()
			case entryInfo.IsDir():
			default:
				return fmt.Errorf("recovery tree contains special file %q", path)
			}
			return nil
		})
		if err != nil {
			return Entry{}, err
		}
	default:
		return Entry{}, fmt.Errorf("recovery entry %q is a special file", name)
	}
	return result, nil
}

// Restore copies an inventory entry to an explicit, non-existing local target.
func Restore(recoveryRoot, id, destinationRoot, destinationPath string) (Entry, error) {
	if err := ValidateRelative(id); err != nil {
		return Entry{}, fmt.Errorf("invalid recovery ID: %w", err)
	}
	if err := ValidateRelative(destinationPath); err != nil {
		return Entry{}, fmt.Errorf("invalid restore destination: %w", err)
	}
	entries, err := List(recoveryRoot)
	if err != nil {
		return Entry{}, err
	}
	for _, entry := range entries {
		if entry.ID != id {
			continue
		}
		if entry.SHA256 != "" {
			summary, err := Digest(recoveryRoot, id)
			if err != nil {
				return Entry{}, fmt.Errorf("verify recovery content: %w", err)
			}
			if summary.SHA256 != entry.SHA256 {
				return Entry{}, errors.New("recovery content does not match its recorded SHA-256 digest")
			}
		}
		if err := Copy(recoveryRoot, id, destinationRoot, destinationPath); err != nil {
			return Entry{}, err
		}
		if entry.SHA256 != "" {
			copied, err := Digest(destinationRoot, destinationPath)
			if err == nil && copied.SHA256 != entry.SHA256 {
				err = errors.New("restored content does not match its recorded SHA-256 digest")
			}
			if err != nil {
				cleanupErr := RemoveAll(destinationRoot, destinationPath)
				return Entry{}, errors.Join(fmt.Errorf("verify restored content: %w", err), cleanupErr)
			}
		}
		return entry, nil
	}
	return Entry{}, fmt.Errorf("recovery ID %q was not found; run `pwnbridge sync recovery list`", id)
}

func readManifest(root *os.Root, name string, destination *manifest) error {
	expected, err := root.Lstat(name)
	if err != nil || !expected.Mode().IsRegular() || expected.Size() > maxManifestBytes {
		return fmt.Errorf("invalid recovery manifest %q", name)
	}
	file, err := root.OpenFile(name, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open recovery manifest %q: %w", name, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(expected, info) || info.Size() > maxManifestBytes {
		return fmt.Errorf("invalid recovery manifest %q", name)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxManifestBytes+1))
	if err != nil {
		return fmt.Errorf("read recovery manifest %q: %w", name, err)
	}
	if int64(len(data)) > maxManifestBytes {
		return fmt.Errorf("recovery manifest %q exceeds its size limit", name)
	}
	latest, err := file.Stat()
	if err != nil || !sameObservedFile(info, latest) {
		return fmt.Errorf("recovery manifest %q changed while it was read", name)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode recovery manifest %q: %w", name, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode recovery manifest %q: trailing data", name)
	}
	return nil
}

func writeManifest(root *os.Root, name string, value manifest) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > maxManifestBytes {
		return errors.New("recovery manifest exceeds its size limit")
	}
	parent := filepath.Dir(name)
	if err := root.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	temporary := filepath.Join(parent, ".manifest-"+hex.EncodeToString(random))
	file, err := root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			_ = root.Remove(temporary)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := fsutil.SyncFile(file); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := root.Rename(temporary, name); err != nil {
		return err
	}
	keep = true
	return syncRootDirectory(root, parent)
}

func syncRootDirectoryChain(root *os.Root, name string) error {
	for directory := filepath.Clean(name); ; directory = filepath.Dir(directory) {
		if err := syncRootDirectory(root, directory); err != nil {
			return err
		}
		if directory == "." {
			return nil
		}
	}
}

func syncRootDirectory(root *os.Root, name string) error {
	if name == "" {
		name = "."
	}
	directory, err := root.Open(name)
	if err != nil {
		return fmt.Errorf("open destination directory %q: %w", name, err)
	}
	syncErr := fsutil.SyncFile(directory)
	closeErr := directory.Close()
	if syncErr != nil {
		return fmt.Errorf("sync destination directory %q: %w", name, syncErr)
	}
	return closeErr
}

func parseArchiveTime(name string) (time.Time, error) {
	for _, layout := range []string{"20060102T150405.000000000Z", "20060102T150405Z"} {
		if value, err := time.Parse(layout, name); err == nil {
			return value, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid recovery archive %q", name)
}

func validKind(kind string) bool {
	return kind == "regular" || kind == "directory" || kind == "symlink"
}

func opposite(endpoint string) string {
	if endpoint == "local" {
		return "remote"
	}
	return "local"
}
