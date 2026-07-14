package recovery

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestArchiveRoundTripDigestAndVerifiedRemoval(t *testing.T) {
	source := t.TempDir()
	destination := t.TempDir()
	if err := os.MkdirAll(filepath.Join(source, "tree", "empty"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "tree", "payload"), []byte("artifact"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("payload", filepath.Join(source, "tree", "link")); err != nil {
		t.Fatal(err)
	}
	var stream bytes.Buffer
	written, observation, err := WriteArchive(source, "tree", &stream)
	if err != nil {
		t.Fatal(err)
	}
	if written.Kind != "directory" || written.Items != 4 || written.Size != int64(len("artifactpayload")) || written.ArchiveSize != int64(stream.Len()) || !validDigest(written.SHA256) {
		t.Fatalf("written summary = %#v", written)
	}
	extracted, err := ExtractArchive(&stream, destination, "recovered/tree")
	if err != nil {
		t.Fatal(err)
	}
	if extracted != written {
		t.Fatalf("extracted = %#v, written = %#v", extracted, written)
	}
	digest, err := Digest(destination, "recovered/tree")
	if err != nil || digest.SHA256 != written.SHA256 {
		t.Fatalf("restored digest = %#v, %v", digest, err)
	}
	data, err := os.ReadFile(filepath.Join(destination, "recovered", "tree", "payload"))
	if err != nil || string(data) != "artifact" {
		t.Fatalf("payload = %q, %v", data, err)
	}
	if target, err := os.Readlink(filepath.Join(destination, "recovered", "tree", "link")); err != nil || target != "payload" {
		t.Fatalf("link = %q, %v", target, err)
	}
	if err := VerifyAndRemove(source, "tree", written.SHA256, observation); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(source, "tree")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("verified source remains: %v", err)
	}
}

func TestArchiveDigestIsDeterministicAndDetectsChanges(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "payload")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	var first, second bytes.Buffer
	initial, observation, err := WriteArchive(root, "payload", &first)
	if err != nil {
		t.Fatal(err)
	}
	repeated, _, err := WriteArchive(root, "payload", &second)
	if err != nil || initial != repeated || !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatalf("archive is not deterministic: %#v / %#v / %v", initial, repeated, err)
	}
	if err := os.WriteFile(path, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAndRemove(root, "payload", initial.SHA256, observation); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("changed source removal returned %v", err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "other" {
		t.Fatalf("changed source was removed: %q, %v", data, err)
	}
}

func TestVerifyChecksEverySupportedKindAndRecordedMetadata(t *testing.T) {
	tests := []struct {
		name   string
		create func(string) error
		mutate func(string) error
	}{
		{
			name:   "regular",
			create: func(name string) error { return os.WriteFile(name, []byte("first"), 0o640) },
			mutate: func(name string) error { return os.WriteFile(name, []byte("other"), 0o640) },
		},
		{
			name: "directory",
			create: func(name string) error {
				if err := os.Mkdir(name, 0o750); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(name, "payload"), []byte("first"), 0o600)
			},
			mutate: func(name string) error { return os.WriteFile(filepath.Join(name, "payload"), []byte("other"), 0o600) },
		},
		{
			name:   "symlink",
			create: func(name string) error { return os.Symlink("first", name) },
			mutate: func(name string) error {
				if err := os.Remove(name); err != nil {
					return err
				}
				return os.Symlink("other", name)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			archive := ArchiveName(time.Now())
			id, err := BackupID(archive, "local", test.name)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, id)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := test.create(path); err != nil {
				t.Fatal(err)
			}
			entry, err := Record(root, archive, "local", test.name)
			if err != nil {
				t.Fatal(err)
			}
			if err := Verify(context.Background(), root, entry); err != nil {
				t.Fatalf("valid recovery copy failed verification: %v", err)
			}
			metadata := entry
			metadata.Mode ^= 0o100
			if err := Verify(context.Background(), root, metadata); !errors.Is(err, ErrIntegrityMismatch) {
				t.Fatalf("metadata mismatch returned %v", err)
			}
			if err := test.mutate(path); err != nil {
				t.Fatal(err)
			}
			if err := Verify(context.Background(), root, entry); !errors.Is(err, ErrIntegrityMismatch) {
				t.Fatalf("content mismatch returned %v", err)
			}
		})
	}
}

func TestVerifyDistinguishesUnverifiedAndCancellation(t *testing.T) {
	if err := Verify(context.Background(), t.TempDir(), Entry{ID: "legacy"}); !errors.Is(err, ErrUnverified) {
		t.Fatalf("digest-free entry returned %v", err)
	}
	if err := Verify(context.Background(), t.TempDir(), Entry{ID: "../escape", SHA256: strings.Repeat("a", 64)}); err == nil {
		t.Fatal("invalid verification ID was accepted")
	}
	if err := Verify(context.Background(), t.TempDir(), Entry{ID: "entry", SHA256: "invalid"}); err == nil {
		t.Fatal("invalid recorded digest was accepted")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "payload"), []byte("valuable"), 0o600); err != nil {
		t.Fatal(err)
	}
	summary, err := Digest(root, "payload")
	if err != nil {
		t.Fatal(err)
	}
	entry := Entry{ID: "payload", Kind: summary.Kind, Size: summary.Size, Items: summary.Items, Mode: summary.Mode, SHA256: summary.SHA256}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Verify(ctx, root, entry); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled verification returned %v", err)
	}
	if _, err := DigestContext(ctx, root, "payload"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled digest returned %v", err)
	}
	missing := entry
	missing.ID = "missing"
	if err := Verify(context.Background(), root, missing); err == nil || !strings.Contains(err.Error(), "read recovery copy") {
		t.Fatalf("unreadable recovery copy returned %v", err)
	}
}

func TestArchiveProgressIsMonotonicAndMatchesDeterministicSummary(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "tree"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tree", "payload"), bytes.Repeat([]byte("p"), 96<<10), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tree", "empty"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("payload", filepath.Join(root, "tree", "link")); err != nil {
		t.Fatal(err)
	}

	var progressStream bytes.Buffer
	var updates []ArchiveProgress
	summary, _, err := WriteArchiveProgress(root, "tree", &progressStream, func(update ArchiveProgress) {
		if len(updates) > 0 {
			previous := updates[len(updates)-1]
			if update.Bytes < previous.Bytes || update.Items < previous.Items {
				t.Fatalf("non-monotonic archive progress: %#v after %#v", update, previous)
			}
		}
		updates = append(updates, update)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) == 0 || updates[len(updates)-1] != (ArchiveProgress{Bytes: summary.Size, Items: summary.Items}) {
		t.Fatalf("final progress = %#v, summary = %#v", updates, summary)
	}

	var ordinaryStream bytes.Buffer
	ordinary, _, err := WriteArchive(root, "tree", &ordinaryStream)
	if err != nil {
		t.Fatal(err)
	}
	if ordinary != summary || !bytes.Equal(ordinaryStream.Bytes(), progressStream.Bytes()) {
		t.Fatal("progress changed deterministic archive output")
	}

	entry := Entry{ID: "tree", Kind: summary.Kind, Size: summary.Size, Items: summary.Items, Mode: summary.Mode, SHA256: summary.SHA256}
	var verified ArchiveProgress
	if err := VerifyProgress(context.Background(), root, entry, func(update ArchiveProgress) { verified = update }); err != nil {
		t.Fatal(err)
	}
	if verified != (ArchiveProgress{Bytes: summary.Size, Items: summary.Items}) {
		t.Fatalf("verification progress = %#v", verified)
	}
}

func TestVerifyProgressPreservesMidStreamCancellation(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "large"), bytes.Repeat([]byte("x"), 2<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	summary, err := Digest(root, "large")
	if err != nil {
		t.Fatal(err)
	}
	entry := Entry{ID: "large", Kind: summary.Kind, Size: summary.Size, Items: summary.Items, Mode: summary.Mode, SHA256: summary.SHA256}
	ctx, cancel := context.WithCancel(context.Background())
	var last ArchiveProgress
	err = VerifyProgress(ctx, root, entry, func(update ArchiveProgress) {
		last = update
		if update.Bytes > 0 {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled verification returned %v", err)
	}
	if last.Bytes <= 0 || last.Bytes >= summary.Size || last.Items != 1 {
		t.Fatalf("cancelled progress = %#v, summary = %#v", last, summary)
	}
}

func TestVerifiedRemovalCannotFollowReplacementParent(t *testing.T) {
	fixture := t.TempDir()
	root := filepath.Join(fixture, "root")
	outside := filepath.Join(fixture, "outside")
	if err := os.MkdirAll(filepath.Join(root, "safe", "victim"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(outside, "victim"), 0o700); err != nil {
		t.Fatal(err)
	}
	summary, observation, err := WriteArchive(root, filepath.Join("safe", "victim"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(root, "safe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "safe")); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAndRemove(root, filepath.Join("safe", "victim"), summary.SHA256, observation); err == nil {
		t.Fatal("replacement parent was accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "victim")); err != nil {
		t.Fatalf("outside victim was removed: %v", err)
	}
}

func TestArchiveRejectsSpecialFileWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := WriteArchive(root, "fifo", io.Discard)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "special") {
			t.Fatalf("FIFO archive returned %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("FIFO archive blocked")
	}
}

func TestFailedArchiveCannotBeAcceptedAsCompletePrefix(t *testing.T) {
	source := t.TempDir()
	destination := t.TempDir()
	if err := os.Mkdir(filepath.Join(source, "tree"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "tree", "a-regular"), []byte("prefix"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(source, "tree", "z-fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	var partial bytes.Buffer
	if _, _, err := WriteArchive(source, "tree", &partial); err == nil {
		t.Fatal("special-file tree was archived")
	}
	if _, err := ExtractArchive(&partial, destination, "backup"); err == nil {
		t.Fatal("partial archive prefix was accepted as complete")
	}
	if _, err := os.Lstat(filepath.Join(destination, "backup")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial archive left a destination: %v", err)
	}
}

func TestExtractArchiveRejectsHostileHeadersAndCleansPartialOutput(t *testing.T) {
	cases := []struct {
		name    string
		headers []*tar.Header
		bodies  [][]byte
	}{
		{name: "no-root", headers: []*tar.Header{archiveHeader("file", 0o600, tar.TypeReg, 0, "")}},
		{name: "traversal", headers: []*tar.Header{archiveHeader(".", 0o700, tar.TypeDir, 0, ""), archiveHeader("../escape", 0o600, tar.TypeReg, 0, "")}},
		{name: "duplicate", headers: []*tar.Header{archiveHeader(".", 0o700, tar.TypeDir, 0, ""), archiveHeader("file", 0o600, tar.TypeReg, 0, ""), archiveHeader("file", 0o600, tar.TypeReg, 0, "")}},
		{name: "symlink-parent", headers: []*tar.Header{archiveHeader(".", 0o700, tar.TypeDir, 0, ""), archiveHeader("link", 0o777, tar.TypeSymlink, 0, "target"), archiveHeader("link/child", 0o600, tar.TypeReg, 0, "")}},
		{name: "hardlink", headers: []*tar.Header{archiveHeader(".", 0o700, tar.TypeDir, 0, ""), archiveHeader("hard", 0o600, tar.TypeLink, 0, "target")}},
		{name: "ownership", headers: []*tar.Header{archiveHeader(".", 0o700, tar.TypeDir, 0, ""), func() *tar.Header { h := archiveHeader("file", 0o600, tar.TypeReg, 0, ""); h.Uid = 1; return h }()}},
		{name: "access-time", headers: []*tar.Header{func() *tar.Header {
			h := archiveHeader(".", 0o700, tar.TypeDir, 0, "")
			h.AccessTime = time.Unix(1, 0)
			return h
		}()}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			archive := makeArchive(t, test.headers, test.bodies)
			destination := t.TempDir()
			if _, err := ExtractArchive(bytes.NewReader(archive), destination, "output"); err == nil {
				t.Fatal("hostile archive was accepted")
			}
			if _, err := os.Lstat(filepath.Join(destination, "output")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("partial output remains: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(destination, "escape")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("archive escaped destination: %v", err)
			}
		})
	}
}

func TestExtractArchiveCleansTruncatedRegularFile(t *testing.T) {
	header := archiveHeader(".", 0o600, tar.TypeReg, 1024, "")
	archive := makeArchive(t, []*tar.Header{header}, [][]byte{bytes.Repeat([]byte("x"), 1024)})
	archive = archive[:700]
	destination := t.TempDir()
	if _, err := ExtractArchive(bytes.NewReader(archive), destination, "partial"); err == nil {
		t.Fatal("truncated archive was accepted")
	}
	if _, err := os.Lstat(filepath.Join(destination, "partial")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("truncated archive left output: %v", err)
	}
}

func makeArchive(t *testing.T, headers []*tar.Header, bodies [][]byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for index, header := range headers {
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if index < len(bodies) && len(bodies[index]) != 0 {
			if _, err := writer.Write(bodies[index]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func FuzzExtractArchive(f *testing.F) {
	seedRoot := f.TempDir()
	if err := os.WriteFile(filepath.Join(seedRoot, "seed"), []byte("recovery seed"), 0o640); err != nil {
		f.Fatal(err)
	}
	var valid bytes.Buffer
	if _, _, err := WriteArchive(seedRoot, "seed", &valid); err != nil {
		f.Fatal(err)
	}
	f.Add(valid.Bytes())
	f.Add([]byte("not an archive"))
	f.Fuzz(func(t *testing.T, data []byte) {
		destination := t.TempDir()
		_, _ = ExtractArchive(bytes.NewReader(data), destination, "output")
	})
}

func BenchmarkArchive1MiB(b *testing.B) {
	source := b.TempDir()
	destination := b.TempDir()
	if err := os.WriteFile(filepath.Join(source, "payload"), bytes.Repeat([]byte("x"), 1<<20), 0o600); err != nil {
		b.Fatal(err)
	}
	b.Run("write", func(b *testing.B) {
		for b.Loop() {
			if _, _, err := WriteArchive(source, "payload", io.Discard); err != nil {
				b.Fatal(err)
			}
		}
	})
	summary, err := Digest(source, "payload")
	if err != nil {
		b.Fatal(err)
	}
	entry := Entry{ID: "payload", Kind: summary.Kind, Size: summary.Size, Items: summary.Items, Mode: summary.Mode, SHA256: summary.SHA256}
	b.Run("verify", func(b *testing.B) {
		for b.Loop() {
			if err := Verify(context.Background(), source, entry); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("verify-progress", func(b *testing.B) {
		var last ArchiveProgress
		for b.Loop() {
			if err := VerifyProgress(context.Background(), source, entry, func(update ArchiveProgress) { last = update }); err != nil {
				b.Fatal(err)
			}
		}
		if last.Bytes != entry.Size || last.Items != entry.Items {
			b.Fatalf("final progress = %#v", last)
		}
	})
	var stream bytes.Buffer
	if _, _, err := WriteArchive(source, "payload", &stream); err != nil {
		b.Fatal(err)
	}
	archive := append([]byte(nil), stream.Bytes()...)
	b.Run("extract", func(b *testing.B) {
		for index := 0; b.Loop(); index++ {
			name := fmt.Sprintf("backup-%d", index)
			if _, err := ExtractArchive(bytes.NewReader(archive), destination, name); err != nil {
				b.Fatal(err)
			}
			if err := RemoveAll(destination, name); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkVerifyTree(b *testing.B) {
	root := b.TempDir()
	if err := os.Mkdir(filepath.Join(root, "tree"), 0o700); err != nil {
		b.Fatal(err)
	}
	for index := range 100 {
		name := filepath.Join(root, "tree", fmt.Sprintf("artifact-%03d", index))
		if err := os.WriteFile(name, bytes.Repeat([]byte{byte(index)}, 1024), 0o600); err != nil {
			b.Fatal(err)
		}
	}
	summary, err := Digest(root, "tree")
	if err != nil {
		b.Fatal(err)
	}
	entry := Entry{ID: "tree", Kind: summary.Kind, Size: summary.Size, Items: summary.Items, Mode: summary.Mode, SHA256: summary.SHA256}
	b.ResetTimer()
	for b.Loop() {
		if err := Verify(context.Background(), root, entry); err != nil {
			b.Fatal(err)
		}
	}
}
