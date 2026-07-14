package filesnapshot

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/simonfalke-01/pwnbridge/internal/protocol"
)

const maximumLinkTargetBytes = 1 << 20

// Capture opens relative beneath root one component at a time. It never
// follows symbolic links and uses non-blocking descriptors so special files
// can be classified without waiting for a peer.
func Capture(root, relative string, maximum int64) (protocol.FileSnapshot, error) {
	components, err := pathComponents(relative)
	if err != nil {
		return protocol.FileSnapshot{}, err
	}
	if !filepath.IsAbs(root) {
		return protocol.FileSnapshot{}, errors.New("snapshot root must be absolute")
	}
	if maximum < 0 || maximum > protocol.MaxConflictPreviewBytes {
		return protocol.FileSnapshot{}, errors.New("invalid snapshot content limit")
	}

	rootFile, err := openDirectory(root)
	if err != nil {
		return protocol.FileSnapshot{}, fmt.Errorf("open snapshot root: %w", err)
	}
	current := rootFile
	defer func() { _ = current.Close() }()
	for _, component := range components[:len(components)-1] {
		next, openErr := openDirectoryAt(current, component)
		if openErr != nil {
			return protocol.FileSnapshot{}, fmt.Errorf("open snapshot parent %q: %w", component, openErr)
		}
		_ = current.Close()
		current = next
	}

	name := components[len(components)-1]
	file, err := openEntryAt(current, name)
	if errors.Is(err, unix.ENOENT) {
		return protocol.FileSnapshot{Kind: "missing"}, nil
	}
	if errors.Is(err, unix.ELOOP) {
		target, linkErr := readLinkAt(current, name)
		if linkErr != nil {
			return protocol.FileSnapshot{}, fmt.Errorf("read snapshot link: %w", linkErr)
		}
		return protocol.FileSnapshot{Kind: "symlink", LinkTarget: target}, nil
	}
	if err != nil {
		return protocol.FileSnapshot{}, fmt.Errorf("open snapshot entry: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return protocol.FileSnapshot{}, err
	}
	snapshot := protocol.FileSnapshot{Size: info.Size(), Mode: uint32(info.Mode().Perm())}
	switch {
	case info.Mode().IsRegular():
		snapshot.Kind = "regular"
		if info.Size() > maximum {
			snapshot.Omitted = true
			return snapshot, nil
		}
		capacity := info.Size() + int64(bytes.MinRead)
		maximumCapacity := maximum + 1 + int64(bytes.MinRead)
		if capacity > maximumCapacity {
			capacity = maximumCapacity
		}
		buffer := bytes.NewBuffer(make([]byte, 0, int(capacity)))
		_, readErr := io.Copy(buffer, io.LimitReader(file, maximum+1))
		if readErr != nil {
			return protocol.FileSnapshot{}, readErr
		}
		content := buffer.Bytes()
		after, statErr := file.Stat()
		if statErr != nil {
			return protocol.FileSnapshot{}, statErr
		}
		if int64(len(content)) > maximum {
			if after.Size() <= maximum {
				return protocol.FileSnapshot{}, errors.New("snapshot file changed while it was being read")
			}
			snapshot.Size = after.Size()
			snapshot.Omitted = true
			return snapshot, nil
		}
		if int64(len(content)) != info.Size() || after.Size() != info.Size() || after.Mode().Perm() != info.Mode().Perm() || !after.ModTime().Equal(info.ModTime()) {
			return protocol.FileSnapshot{}, errors.New("snapshot file changed while it was being read")
		}
		snapshot.Content = content
		digest := sha256.Sum256(content)
		snapshot.SHA256 = fmt.Sprintf("%x", digest)
		return snapshot, nil
	case info.IsDir():
		snapshot.Kind = "directory"
	default:
		snapshot.Kind = "special"
	}
	return snapshot, nil
}

func pathComponents(relative string) ([]string, error) {
	if relative == "" || strings.IndexByte(relative, 0) >= 0 || filepath.IsAbs(relative) {
		return nil, errors.New("snapshot path must be a non-empty relative path")
	}
	clean := filepath.Clean(relative)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, errors.New("snapshot path escapes its root")
	}
	components := strings.Split(clean, string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return nil, errors.New("snapshot path has an invalid component")
		}
	}
	return components, nil
}

func openDirectory(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	return fileFromDescriptor(fd, path, err)
}

func openDirectoryAt(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	return fileFromDescriptor(fd, name, err)
}

func openEntryAt(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	return fileFromDescriptor(fd, name, err)
}

func fileFromDescriptor(fd int, name string, err error) (*os.File, error) {
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("invalid snapshot file descriptor")
	}
	return file, nil
}

func readLinkAt(parent *os.File, name string) (string, error) {
	for size := 256; size <= maximumLinkTargetBytes; size *= 2 {
		buffer := make([]byte, size)
		n, err := unix.Readlinkat(int(parent.Fd()), name, buffer)
		if err != nil {
			return "", err
		}
		if n < len(buffer) {
			return string(buffer[:n]), nil
		}
	}
	return "", errors.New("symbolic link target exceeds limit")
}
