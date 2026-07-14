package filesnapshot

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/protocol"
)

func TestCaptureRegularMissingAndOversized(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "file"), []byte("content"), 0o640); err != nil {
		t.Fatal(err)
	}
	snapshot, err := Capture(root, "nested/file", protocol.MaxConflictPreviewBytes)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Kind != "regular" || string(snapshot.Content) != "content" || snapshot.Size != 7 || snapshot.Mode != 0o640 || len(snapshot.SHA256) != 64 || snapshot.Omitted {
		t.Fatalf("regular snapshot = %#v", snapshot)
	}
	missing, err := Capture(root, "nested/missing", protocol.MaxConflictPreviewBytes)
	if err != nil || missing.Kind != "missing" {
		t.Fatalf("missing snapshot = %#v, %v", missing, err)
	}
	oversized, err := Capture(root, "nested/file", 3)
	if err != nil || !oversized.Omitted || oversized.Content != nil || oversized.SHA256 != "" {
		t.Fatalf("oversized snapshot = %#v, %v", oversized, err)
	}
}

func TestCaptureDoesNotFollowSymlinksOrEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	link, err := Capture(root, "link", protocol.MaxConflictPreviewBytes)
	if err != nil {
		t.Fatal(err)
	}
	if link.Kind != "symlink" || link.LinkTarget != filepath.Join(outside, "secret") || len(link.Content) != 0 {
		t.Fatalf("link snapshot = %#v", link)
	}
	if err := os.Symlink(outside, filepath.Join(root, "parent")); err != nil {
		t.Fatal(err)
	}
	if _, err := Capture(root, "parent/secret", protocol.MaxConflictPreviewBytes); err == nil {
		t.Fatal("symlink parent was followed")
	}
	for _, path := range []string{"", ".", "..", "../secret", filepath.Join(outside, "secret"), "a\x00b"} {
		if _, err := Capture(root, path, protocol.MaxConflictPreviewBytes); err == nil {
			t.Fatalf("unsafe path %q was accepted", path)
		}
	}
}

func TestCaptureClassifiesFIFOWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		snapshot, err := Capture(root, "fifo", protocol.MaxConflictPreviewBytes)
		if err == nil && snapshot.Kind != "special" {
			err = errors.New("FIFO was not classified as special")
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("FIFO snapshot blocked")
	}
}

func TestCaptureRejectsInvalidLimitsAndRoots(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file"), []byte(strings.Repeat("x", 8)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, maximum := range []int64{-1, protocol.MaxConflictPreviewBytes + 1} {
		if _, err := Capture(root, "file", maximum); err == nil {
			t.Fatalf("limit %d was accepted", maximum)
		}
	}
	if _, err := Capture("relative", "file", 1); err == nil {
		t.Fatal("relative root was accepted")
	}
}

func BenchmarkCapture1MiB(b *testing.B) {
	root := b.TempDir()
	path := filepath.Join(root, "file")
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), protocol.MaxConflictPreviewBytes), 0o600); err != nil {
		b.Fatal(err)
	}
	b.Run("plain-read", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			data, err := os.ReadFile(path)
			if err != nil || len(data) != protocol.MaxConflictPreviewBytes {
				b.Fatalf("read %d bytes: %v", len(data), err)
			}
		}
	})
	b.Run("descriptor-snapshot", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			snapshot, err := Capture(root, "file", protocol.MaxConflictPreviewBytes)
			if err != nil || len(snapshot.Content) != protocol.MaxConflictPreviewBytes {
				b.Fatalf("capture %d bytes: %v", len(snapshot.Content), err)
			}
		}
	})
}
