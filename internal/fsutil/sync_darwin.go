//go:build darwin

package fsutil

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func syncDurable(file *os.File) error {
	_, err := unix.FcntlInt(file.Fd(), unix.F_FULLFSYNC, 0)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.ENOTTY) {
		return file.Sync()
	}
	return err
}
