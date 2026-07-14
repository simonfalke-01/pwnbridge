//go:build !darwin

package fsutil

import "os"

func syncDurable(file *os.File) error {
	return file.Sync()
}
