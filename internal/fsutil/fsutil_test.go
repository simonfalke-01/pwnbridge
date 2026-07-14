package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReadJSONLimitAndStrictFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "value.json")
	type value struct {
		Name string `json:"name"`
	}
	if err := os.WriteFile(path, []byte(`{"name":"ok"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var got value
	if err := ReadJSONLimit(path, 64, &got); err != nil || got.Name != "ok" {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	if err := os.WriteFile(path, []byte(`{"name":"ok","unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReadJSONLimit(path, 64, &got); err == nil {
		t.Fatal("unknown field was accepted")
	}
	if err := os.WriteFile(path, []byte(`{"name":"ok"}{"name":"second"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReadJSONLimit(path, 64, &got); err == nil {
		t.Fatal("trailing JSON value was accepted")
	}
	if err := os.WriteFile(path, []byte(`{"name":"`+strings.Repeat("x", 100)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReadJSONLimit(path, 64, &got); err == nil {
		t.Fatal("oversized JSON was accepted")
	}
}

func TestAtomicWriteDurabilityOrderAndFailureBoundaries(t *testing.T) {
	t.Run("ordered commit", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "new", "nested", "state")
		var events []string
		err := atomicWrite(path, []byte("new"), 0o640, atomicWriteHooks{
			syncFile: func(file *os.File) error {
				events = append(events, "sync-file")
				return file.Sync()
			},
			rename: func(oldPath, newPath string) error {
				events = append(events, "rename")
				return os.Rename(oldPath, newPath)
			},
			syncDirectories: func(parent, stop string) error {
				events = append(events, "sync-directories")
				if data, readErr := os.ReadFile(path); readErr != nil || string(data) != "new" {
					t.Fatalf("directory sync ran before committed content was visible: %q, %v", data, readErr)
				}
				return syncDirectoryChain(parent, stop)
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(events, ",") != "sync-file,rename,sync-directories" {
			t.Fatalf("durability order = %v", events)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o640 {
			t.Fatalf("committed mode = %o", info.Mode().Perm())
		}
	})

	t.Run("file sync failure is pre-commit", func(t *testing.T) {
		testAtomicWriteFailure(t, "old", func(path string) error {
			sentinel := errors.New("sync failed")
			err := atomicWrite(path, []byte("new"), 0o600, atomicWriteHooks{
				syncFile: func(*os.File) error { return sentinel },
				rename: func(string, string) error {
					t.Fatal("rename followed failed file sync")
					return nil
				},
				syncDirectories: func(string, string) error {
					t.Fatal("directory sync followed failed file sync")
					return nil
				},
			})
			if !errors.Is(err, sentinel) {
				t.Fatalf("file sync error = %v", err)
			}
			return err
		})
	})

	t.Run("rename failure is pre-commit", func(t *testing.T) {
		testAtomicWriteFailure(t, "old", func(path string) error {
			sentinel := errors.New("rename failed")
			err := atomicWrite(path, []byte("new"), 0o600, atomicWriteHooks{
				syncFile: func(file *os.File) error { return file.Sync() },
				rename:   func(string, string) error { return sentinel },
				syncDirectories: func(string, string) error {
					t.Fatal("directory sync followed failed rename")
					return nil
				},
			})
			if !errors.Is(err, sentinel) {
				t.Fatalf("rename error = %v", err)
			}
			return err
		})
	})

	t.Run("directory sync failure is post-commit", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "state")
		if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		sentinel := errors.New("directory sync failed")
		err := atomicWrite(path, []byte("new"), 0o600, atomicWriteHooks{
			syncFile:        func(file *os.File) error { return file.Sync() },
			rename:          os.Rename,
			syncDirectories: func(string, string) error { return sentinel },
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("directory sync error = %v", err)
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil || string(data) != "new" {
			t.Fatalf("post-rename error lost committed content: %q, %v", data, readErr)
		}
		assertNoAtomicTemps(t, root)
	})
}

func testAtomicWriteFailure(t *testing.T, want string, run func(string) error) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "state")
	if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(path); err == nil {
		t.Fatal("injected atomic-write failure was ignored")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != want {
		t.Fatalf("pre-commit failure changed target: %q, %v", data, err)
	}
	assertNoAtomicTemps(t, root)
}

func assertNoAtomicTemps(t *testing.T, root string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(root, ".pwnbridge-tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("atomic write leaked temporary files: %v", matches)
	}
}

func TestSyncDirectoryChainIncludesNewAncestors(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "one", "two")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	var synced []string
	if err := syncDirectoryChainWith(parent, root, func(path string) error {
		synced = append(synced, path)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{parent, filepath.Join(root, "one"), root}
	if strings.Join(synced, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("synced directories = %v, want %v", synced, want)
	}
}

func TestBoundedRegularFileReaders(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadFileLimit(link, 5); err != nil || string(data) != "value" {
		t.Fatalf("bounded user file read = %q, %v", data, err)
	}
	if _, err := ReadPrivateFileLimit(link, 5); err == nil {
		t.Fatal("private reader followed a symbolic link")
	}
	if data, err := ReadPrivateFileLimit(target, 5); err != nil || string(data) != "value" {
		t.Fatalf("bounded private file read = %q, %v", data, err)
	}
	if err := os.Chmod(target, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateFileLimit(target, 5); err == nil {
		t.Fatal("private reader accepted group-readable data")
	}
	if _, err := ReadFileLimit(target, 4); err == nil {
		t.Fatal("bounded reader accepted oversized data")
	}
}

func TestBoundedRegularFileReaderRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := ReadFileLimit(path, 64); err == nil {
		t.Fatal("bounded reader accepted a FIFO")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("FIFO rejection took %v", elapsed)
	}
}

func TestOpenPrivateAppendFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bootstrap.log")
	file, size, err := OpenPrivateAppendFile(path, 8)
	if err != nil {
		t.Fatal(err)
	}
	if size != 0 {
		t.Fatalf("new append file size = %d", size)
	}
	if _, err := file.WriteString("abc"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	file, size, err = OpenPrivateAppendFile(path, 8)
	if err != nil {
		t.Fatal(err)
	}
	if size != 3 {
		t.Fatalf("existing append file size = %d", size)
	}
	if _, err := file.WriteString("de"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "abcde" {
		t.Fatalf("appended data = %q, %v", data, err)
	}
	if _, _, err := OpenPrivateAppendFile(path, 4); err == nil {
		t.Fatal("oversized append file was accepted")
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenPrivateAppendFile(path, 8); err == nil {
		t.Fatal("group-readable append file was accepted")
	}
	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenPrivateAppendFile(link, 8); err == nil {
		t.Fatal("append file symbolic link was accepted")
	}
	fifo := filepath.Join(dir, "fifo.log")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, _, err := OpenPrivateAppendFile(fifo, 8); err == nil {
		t.Fatal("append FIFO was accepted")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("append FIFO rejection took %v", elapsed)
	}
}

func TestOpenPrivateRotatingAppendFile(t *testing.T) {
	t.Run("create append and rotate", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		file, rotated, err := OpenPrivateRotatingAppendFile(directory, "daemon.log", 4)
		if err != nil {
			t.Fatal(err)
		}
		if rotated {
			t.Fatal("new log reported a rotation")
		}
		if _, err := file.WriteString("abc"); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		file, rotated, err = OpenPrivateRotatingAppendFile(directory, "daemon.log", 4)
		if err != nil {
			t.Fatal(err)
		}
		if rotated {
			t.Fatal("small log reported a rotation")
		}
		if _, err := file.WriteString("de"); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		file, rotated, err = OpenPrivateRotatingAppendFile(directory, "daemon.log", 4)
		if err != nil {
			t.Fatal(err)
		}
		if !rotated {
			t.Fatal("oversized log was not rotated")
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if data, err := os.ReadFile(filepath.Join(directory, "daemon.log.previous")); err != nil || string(data) != "abcde" {
			t.Fatalf("rotated data = %q, %v", data, err)
		}
		if data, err := os.ReadFile(filepath.Join(directory, "daemon.log")); err != nil || len(data) != 0 {
			t.Fatalf("new log data = %q, %v", data, err)
		}
		if info, err := os.Stat(filepath.Join(directory, "daemon.log")); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("new log mode = %v, %v", info.Mode().Perm(), err)
		}
	})

	t.Run("replace previous symlink without following", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "daemon.log"), []byte("oversized"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(directory, "daemon.log.previous")); err != nil {
			t.Fatal(err)
		}
		file, rotated, err := OpenPrivateRotatingAppendFile(directory, "daemon.log", 4)
		if err != nil {
			t.Fatal(err)
		}
		file.Close()
		if !rotated {
			t.Fatal("oversized log was not rotated")
		}
		if data, err := os.ReadFile(target); err != nil || string(data) != "outside" {
			t.Fatalf("symlink target changed to %q, %v", data, err)
		}
		if data, err := os.ReadFile(filepath.Join(directory, "daemon.log.previous")); err != nil || string(data) != "oversized" {
			t.Fatalf("previous log = %q, %v", data, err)
		}
	})

	t.Run("reject unsafe entries promptly", func(t *testing.T) {
		for _, test := range []struct {
			name  string
			setup func(*testing.T, string)
		}{
			{name: "symlink", setup: func(t *testing.T, path string) {
				target := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}},
			{name: "fifo", setup: func(t *testing.T, path string) {
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			}},
			{name: "directory", setup: func(t *testing.T, path string) {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}},
			{name: "group-readable", setup: func(t *testing.T, path string) {
				if err := os.WriteFile(path, nil, 0o640); err != nil {
					t.Fatal(err)
				}
			}},
		} {
			t.Run(test.name, func(t *testing.T) {
				directory := t.TempDir()
				if err := os.Chmod(directory, 0o700); err != nil {
					t.Fatal(err)
				}
				test.setup(t, filepath.Join(directory, "daemon.log"))
				started := time.Now()
				if _, _, err := OpenPrivateRotatingAppendFile(directory, "daemon.log", 4); err == nil {
					t.Fatal("unsafe log was accepted")
				}
				if elapsed := time.Since(started); elapsed > time.Second {
					t.Fatalf("unsafe log rejection took %v", elapsed)
				}
			})
		}
	})

	t.Run("reject unsafe directory and name", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := ValidatePrivateDirectory(directory); err == nil {
			t.Fatal("non-private directory validation succeeded")
		}
		if _, _, err := OpenPrivateRotatingAppendFile(directory, "daemon.log", 4); err == nil {
			t.Fatal("non-private directory was accepted")
		}
		privateDirectory := t.TempDir()
		if err := os.Chmod(privateDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := ValidatePrivateDirectory(privateDirectory); err != nil {
			t.Fatalf("private directory validation failed: %v", err)
		}
		link := filepath.Join(t.TempDir(), "linked-directory")
		if err := os.Symlink(privateDirectory, link); err != nil {
			t.Fatal(err)
		}
		if err := ValidatePrivateDirectory(link); err == nil {
			t.Fatal("linked directory validation succeeded")
		}
		if _, _, err := OpenPrivateRotatingAppendFile(link, "daemon.log", 4); err == nil {
			t.Fatal("linked directory was accepted")
		}
		if _, _, err := OpenPrivateRotatingAppendFile(t.TempDir(), "../daemon.log", 4); err == nil {
			t.Fatal("non-local name was accepted")
		}
	})

	t.Run("preserve log when rotation destination is a directory", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "daemon.log")
		if err := os.WriteFile(path, []byte("oversized"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(directory, "daemon.log.previous"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, _, err := OpenPrivateRotatingAppendFile(directory, "daemon.log", 4); err == nil {
			t.Fatal("rotation over a directory succeeded")
		}
		if data, err := os.ReadFile(path); err != nil || string(data) != "oversized" {
			t.Fatalf("source log changed to %q, %v", data, err)
		}
	})
}

func BenchmarkFileReaders1KiB(b *testing.B) {
	path := filepath.Join(b.TempDir(), "state")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 1024)), 0o600); err != nil {
		b.Fatal(err)
	}
	b.Run("os.ReadFile", func(b *testing.B) {
		for range b.N {
			if _, err := os.ReadFile(path); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("bounded-regular", func(b *testing.B) {
		for range b.N {
			if _, err := ReadFileLimit(path, 1<<20); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("bounded-private", func(b *testing.B) {
		for range b.N {
			if _, err := ReadPrivateFileLimit(path, 1<<20); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestPrivateDirectoryInventoryIsBoundedAndNoFollow(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if entries, err := ReadPrivateDirectoryLimit(directory, 1); err != nil || len(entries) != 0 {
		t.Fatalf("empty inventory = %#v, %v", entries, err)
	}
	if nonEmpty, err := PrivateDirectoryNonEmpty(directory); err != nil || nonEmpty {
		t.Fatalf("empty check = %t, %v", nonEmpty, err)
	}
	for _, name := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(directory, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ReadPrivateDirectoryLimit(directory, 1); err == nil || !strings.Contains(err.Error(), "1-entry limit") {
		t.Fatalf("oversized directory was accepted: %v", err)
	}
	if nonEmpty, err := PrivateDirectoryNonEmpty(directory); err != nil || !nonEmpty {
		t.Fatalf("non-empty check = %t, %v", nonEmpty, err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(directory, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateDirectoryLimit(alias, 10); err == nil {
		t.Fatal("symbolic-link directory was followed")
	}
	if _, err := PrivateDirectoryNonEmpty(alias); err == nil {
		t.Fatal("symbolic-link directory was inspected")
	}
}

func BenchmarkAppendOpen(b *testing.B) {
	path := filepath.Join(b.TempDir(), "bootstrap.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		b.Fatal(err)
	}
	b.Run("plain", func(b *testing.B) {
		for b.Loop() {
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				b.Fatal(err)
			}
			if err := file.Close(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("private-bounded", func(b *testing.B) {
		for b.Loop() {
			file, _, err := OpenPrivateAppendFile(path, 16<<20)
			if err != nil {
				b.Fatal(err)
			}
			if err := file.Close(); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkPrivateRotatingAppendOpen(b *testing.B) {
	directory := b.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(directory, "daemon.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		b.Fatal(err)
	}
	b.Run("reuse", func(b *testing.B) {
		for b.Loop() {
			file, rotated, err := OpenPrivateRotatingAppendFile(directory, "daemon.log", 5<<20)
			if err != nil {
				b.Fatal(err)
			}
			if rotated {
				b.Fatal("unexpected rotation")
			}
			if err := file.Close(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("rotate", func(b *testing.B) {
		for b.Loop() {
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				b.Fatal(err)
			}
			file, rotated, err := OpenPrivateRotatingAppendFile(directory, "daemon.log", 0)
			if err != nil {
				b.Fatal(err)
			}
			if !rotated {
				b.Fatal("expected rotation")
			}
			if err := file.Close(); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkAtomicWrite1KiB(b *testing.B) {
	path := filepath.Join(b.TempDir(), "state")
	data := []byte(strings.Repeat("x", 1024))
	b.ResetTimer()
	for range b.N {
		if err := AtomicWrite(path, data, 0o600); err != nil {
			b.Fatal(err)
		}
	}
}
