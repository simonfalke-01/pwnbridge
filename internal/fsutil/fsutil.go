package fsutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func AtomicWrite(path string, data []byte, mode os.FileMode) error {
	return atomicWrite(path, data, mode, atomicWriteHooks{
		syncFile: syncDurable, rename: os.Rename, syncDirectories: syncDirectoryChain,
	})
}

type atomicWriteHooks struct {
	syncFile        func(*os.File) error
	rename          func(string, string) error
	syncDirectories func(string, string) error
}

func atomicWrite(path string, data []byte, mode os.FileMode, hooks atomicWriteHooks) error {
	parent := filepath.Dir(path)
	existingParent, err := nearestExistingDirectory(parent)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create parent for %s: %w", path, err)
	}
	f, err := os.CreateTemp(parent, ".pwnbridge-tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	name := f.Name()
	temporaryExists := true
	defer func() {
		if temporaryExists {
			_ = os.Remove(name)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := hooks.syncFile(f); err != nil {
		f.Close()
		return fmt.Errorf("sync temporary file for %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := hooks.rename(name, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	temporaryExists = false
	if err := hooks.syncDirectories(parent, existingParent); err != nil {
		return fmt.Errorf("sync directories after replacing %s: %w", path, err)
	}
	return nil
}

func nearestExistingDirectory(path string) (string, error) {
	for directory := filepath.Clean(path); ; directory = filepath.Dir(directory) {
		info, err := os.Stat(directory)
		if err == nil {
			if !info.IsDir() {
				return "", fmt.Errorf("parent path %s is not a directory", directory)
			}
			return directory, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect parent %s: %w", directory, err)
		}
		if next := filepath.Dir(directory); next == directory {
			return "", fmt.Errorf("no existing parent directory for %s", path)
		}
	}
}

func syncDirectoryChain(path, stop string) error {
	return syncDirectoryChainWith(path, stop, syncDirectory)
}

func syncDirectoryChainWith(path, stop string, syncOne func(string) error) error {
	stop = filepath.Clean(stop)
	for directory := filepath.Clean(path); ; directory = filepath.Dir(directory) {
		if err := syncOne(directory); err != nil {
			return err
		}
		if directory == stop {
			return nil
		}
		if next := filepath.Dir(directory); next == directory {
			return fmt.Errorf("directory %s is not beneath durability root %s", path, stop)
		}
	}
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory %s: %w", path, err)
	}
	syncErr := syncDurable(directory)
	closeErr := directory.Close()
	if syncErr != nil {
		return fmt.Errorf("sync directory %s: %w", path, syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close directory %s: %w", path, closeErr)
	}
	return nil
}

// SyncFile commits a file through the platform's durability primitive.
func SyncFile(file *os.File) error { return syncDurable(file) }

// SyncDirectory commits directory-entry changes in path.
func SyncDirectory(path string) error { return syncDirectory(path) }

func WriteJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return AtomicWrite(path, append(data, '\n'), 0o600)
}

// ReadFileLimit reads a regular file through a close-on-exec, non-blocking
// descriptor. Symbolic links are allowed for user-selected inputs such as
// configuration files, but FIFOs, devices, sockets, and directories fail
// before any read can block.
func ReadFileLimit(path string, maximum int64) ([]byte, error) {
	file, info, err := openRegularFile(path, false)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readFileLimit(file, info, path, maximum)
}

// ReadPrivateFileLimit additionally requires an owner-private file owned by
// the current user and refuses to follow the final path component.
func ReadPrivateFileLimit(path string, maximum int64) ([]byte, error) {
	file, info, err := openRegularFile(path, true)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readFileLimit(file, info, path, maximum)
}

// OpenPrivateAppendFile opens or creates an owner-private regular file without
// following the final path component. Non-blocking open rejects special files
// before they can stall a caller. The returned size is the existing file size.
func OpenPrivateAppendFile(path string, maximum int64) (*os.File, int64, error) {
	if maximum < 0 {
		return nil, 0, fmt.Errorf("invalid limit for %s", path)
	}
	flags := unix.O_WRONLY | unix.O_APPEND | unix.O_CREAT | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOFOLLOW
	fd, err := unix.Open(path, flags, 0o600)
	if err != nil {
		return nil, 0, fmt.Errorf("open %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, 0, fmt.Errorf("open %s: invalid file descriptor", path)
	}
	opened, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, 0, err
	}
	if !ownerPrivateRegular(opened) {
		file.Close()
		return nil, 0, fmt.Errorf("%s is not an owner-private regular file", path)
	}
	if opened.Size() > maximum {
		file.Close()
		return nil, 0, fmt.Errorf("%s exceeds %d-byte limit", path, maximum)
	}
	current, err := os.Lstat(path)
	if err != nil {
		file.Close()
		return nil, 0, err
	}
	if !os.SameFile(current, opened) {
		file.Close()
		return nil, 0, fmt.Errorf("%s changed while it was being opened", path)
	}
	return file, opened.Size(), nil
}

// OpenPrivateRotatingAppendFile opens an owner-private log relative to an
// owner-private directory descriptor. If the existing log exceeds maximum, it
// is atomically renamed to name+".previous" before a new log is opened. Both
// the directory and file refuse final-component symbolic links, and special
// files fail without blocking.
func OpenPrivateRotatingAppendFile(directory, name string, maximum int64) (*os.File, bool, error) {
	if maximum < 0 || name == "" || name == "." || name == ".." || filepath.Base(name) != name || !filepath.IsLocal(name) {
		return nil, false, fmt.Errorf("invalid private append file %q", name)
	}
	directoryFile, err := openPrivateDirectory(directory)
	if err != nil {
		return nil, false, err
	}
	defer directoryFile.Close()
	directoryFD := int(directoryFile.Fd())

	file, stat, err := openPrivateAppendFileAt(directoryFD, directory, name)
	if err != nil {
		return nil, false, err
	}
	if stat.Size <= maximum {
		return file, false, nil
	}

	previous := name + ".previous"
	if err := unix.Renameat(directoryFD, name, directoryFD, previous); err != nil {
		file.Close()
		return nil, false, fmt.Errorf("rotate %s: %w", filepath.Join(directory, name), err)
	}
	var rotated unix.Stat_t
	if err := unix.Fstatat(directoryFD, previous, &rotated, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		file.Close()
		return nil, false, fmt.Errorf("verify rotated %s: %w", filepath.Join(directory, previous), err)
	}
	if !sameUnixFile(stat, &rotated) {
		file.Close()
		return nil, false, fmt.Errorf("%s changed while it was being rotated", filepath.Join(directory, name))
	}
	if err := file.Close(); err != nil {
		return nil, false, fmt.Errorf("close rotated %s: %w", filepath.Join(directory, previous), err)
	}
	file, stat, err = openPrivateAppendFileAt(directoryFD, directory, name)
	if err != nil {
		return nil, false, err
	}
	if stat.Size > maximum {
		file.Close()
		return nil, false, fmt.Errorf("%s exceeds %d-byte limit after rotation", filepath.Join(directory, name), maximum)
	}
	return file, true, nil
}

// ValidatePrivateDirectory verifies that path itself, rather than a symbolic
// link target, is a directory owned by the current user with no group/other
// permissions.
func ValidatePrivateDirectory(path string) error {
	file, err := openPrivateDirectory(path)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close private directory %s: %w", path, err)
	}
	return nil
}

// ReadPrivateDirectoryLimit reads an owner-private directory through the
// validated descriptor and refuses unbounded catalogs. The final path
// component is never followed when it is a symbolic link.
func ReadPrivateDirectoryLimit(path string, maximum int) ([]os.DirEntry, error) {
	if maximum < 0 {
		return nil, fmt.Errorf("invalid entry limit for %s", path)
	}
	file, err := openPrivateDirectory(path)
	if err != nil {
		return nil, err
	}
	entries, readErr := file.ReadDir(maximum + 1)
	closeErr := file.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, errors.Join(readErr, closeErr)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(entries) > maximum {
		return nil, fmt.Errorf("directory %s exceeds %d-entry limit", path, maximum)
	}
	return entries, nil
}

// PrivateDirectoryNonEmpty checks an owner-private directory without reading
// or allocating its complete contents.
func PrivateDirectoryNonEmpty(path string) (bool, error) {
	file, err := openPrivateDirectory(path)
	if err != nil {
		return false, err
	}
	_, readErr := file.Readdirnames(1)
	closeErr := file.Close()
	if errors.Is(readErr, io.EOF) {
		return false, closeErr
	}
	if readErr != nil {
		return false, errors.Join(readErr, closeErr)
	}
	return true, closeErr
}

func openPrivateDirectory(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open private directory %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open private directory %s: invalid file descriptor", path)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("inspect private directory %s: %w", path, err)
	}
	if !ownerPrivateDirectory(info) {
		file.Close()
		return nil, fmt.Errorf("%s is not an owner-private directory", path)
	}
	return file, nil
}

func openPrivateAppendFileAt(directoryFD int, directory, name string) (*os.File, *unix.Stat_t, error) {
	path := filepath.Join(directory, name)
	flags := unix.O_WRONLY | unix.O_APPEND | unix.O_CREAT | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOFOLLOW
	fd, err := unix.Openat(directoryFD, name, flags, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, nil, fmt.Errorf("open %s: invalid file descriptor", path)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("inspect %s: %w", path, err)
	}
	if !ownerPrivateRegular(info) {
		file.Close()
		return nil, nil, fmt.Errorf("%s is not an owner-private regular file", path)
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("inspect %s descriptor: %w", path, err)
	}
	var current unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("inspect current %s: %w", path, err)
	}
	if !sameUnixFile(&opened, &current) {
		file.Close()
		return nil, nil, fmt.Errorf("%s changed while it was being opened", path)
	}
	return file, &opened, nil
}

func sameUnixFile(first, second *unix.Stat_t) bool {
	return first.Dev == second.Dev && first.Ino == second.Ino
}

func ReadJSONLimit(path string, maximum int64, value any) error {
	data, err := ReadFileLimit(path, maximum)
	if err != nil {
		return err
	}
	return decodeJSON(data, path, value)
}

// ReadPrivateJSONLimit opens private state without following the final path
// link, validates the opened descriptor, and then verifies that the path still
// names that descriptor. Non-blocking open lets non-regular files fail closed
// instead of hanging before their type can be checked.
func ReadPrivateJSONLimit(path string, maximum int64, value any) error {
	data, err := ReadPrivateFileLimit(path, maximum)
	if err != nil {
		return err
	}
	return decodeJSON(data, path, value)
}

func openRegularFile(path string, private bool) (*os.File, os.FileInfo, error) {
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK
	if private {
		flags |= unix.O_NOFOLLOW
	}
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, nil, fmt.Errorf("open %s: invalid file descriptor", path)
	}
	opened, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	if !opened.Mode().IsRegular() {
		file.Close()
		return nil, nil, fmt.Errorf("%s is not a regular file", path)
	}
	if !private {
		return file, opened, nil
	}
	if !ownerPrivateRegular(opened) {
		file.Close()
		return nil, nil, fmt.Errorf("%s is not an owner-private regular file", path)
	}
	current, err := os.Lstat(path)
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	if !os.SameFile(current, opened) {
		file.Close()
		return nil, nil, fmt.Errorf("%s changed while it was being opened", path)
	}
	return file, opened, nil
}

func ownerPrivateRegular(info os.FileInfo) bool {
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid()
}

func ownerPrivateDirectory(info os.FileInfo) bool {
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid()
}

func readFileLimit(file *os.File, info os.FileInfo, path string, maximum int64) ([]byte, error) {
	maxInt := int64(^uint(0) >> 1)
	if maximum < 0 || maximum > maxInt-int64(bytes.MinRead)-1 {
		return nil, fmt.Errorf("invalid limit for %s", path)
	}
	if info.Size() > maximum {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", path, maximum)
	}
	capacity := info.Size() + int64(bytes.MinRead)
	if maximumCapacity := maximum + 1 + int64(bytes.MinRead); capacity > maximumCapacity {
		capacity = maximumCapacity
	}
	buffer := bytes.NewBuffer(make([]byte, 0, int(capacity)))
	_, err := io.Copy(buffer, io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	data := buffer.Bytes()
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", path, maximum)
	}
	return data, nil
}

func decodeJSON(data []byte, path string, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode %s: trailing JSON value", path)
	}
	return nil
}
