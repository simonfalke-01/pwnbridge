package recovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/fsutil"
)

func TestCopyPreservesSupportedTypesAndRejectsOverwrite(t *testing.T) {
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
	if err := Copy(source, "tree", destination, "restored/tree"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(destination, "restored", "tree", "payload"))
	if err != nil || string(data) != "artifact" {
		t.Fatalf("payload = %q, %v", data, err)
	}
	info, err := os.Stat(filepath.Join(destination, "restored", "tree", "payload"))
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("payload mode = %#o, %v", info.Mode().Perm(), err)
	}
	if target, err := os.Readlink(filepath.Join(destination, "restored", "tree", "link")); err != nil || target != "payload" {
		t.Fatalf("link = %q, %v", target, err)
	}
	if err := Copy(source, "tree", destination, "restored/tree"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("overwrite returned %v", err)
	}
}

func TestCopyRejectsSpecialFilesWithoutBlockingAndCleansPartialTree(t *testing.T) {
	source := t.TempDir()
	destination := t.TempDir()
	if err := os.Mkdir(filepath.Join(source, "tree"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "tree", "a-regular"), []byte("copied first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(source, "tree", "z-fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Copy(source, "tree", destination, "restored") }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "special file") {
			t.Fatalf("special tree returned %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("copying a FIFO blocked")
	}
	if _, err := os.Lstat(filepath.Join(destination, "restored")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial destination remains: %v", err)
	}
}

func TestCopyRejectsSourceReplacementAndCleansSyncFailure(t *testing.T) {
	source := t.TempDir()
	destination := t.TempDir()
	sourcePath := filepath.Join(source, "source")
	if err := os.WriteFile(sourcePath, []byte("original"), 0o640); err != nil {
		t.Fatal(err)
	}
	err := copyWithHooks(source, "source", destination, "backup", copyHooks{
		syncFile: fsutil.SyncFile,
		afterInspect: func(string) {
			if err := os.Remove(sourcePath); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(sourcePath, []byte("attacker"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	})
	if err == nil || !strings.Contains(err.Error(), "changed while it was opened") {
		t.Fatalf("source replacement returned %v", err)
	}
	if _, err := os.Lstat(filepath.Join(destination, "backup")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement left destination: %v", err)
	}
	if err := os.WriteFile(sourcePath, []byte("stable"), 0o640); err != nil {
		t.Fatal(err)
	}
	err = copyWithHooks(source, "source", destination, "backup", copyHooks{
		syncFile: func(*os.File) error { return errors.New("injected sync failure") },
	})
	if err == nil || !strings.Contains(err.Error(), "injected sync failure") {
		t.Fatalf("sync failure returned %v", err)
	}
	if _, err := os.Lstat(filepath.Join(destination, "backup")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sync failure left destination: %v", err)
	}
}

func TestCopyKeepsOpenedDirectoryAcrossNamespaceReplacement(t *testing.T) {
	source := t.TempDir()
	destination := t.TempDir()
	if err := os.Mkdir(filepath.Join(source, "tree"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "tree", "payload"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := copyWithHooks(source, "tree", destination, "backup", copyHooks{
		syncFile: fsutil.SyncFile,
		afterDirectoryOpen: func(name string) {
			if name != "tree" {
				return
			}
			if err := os.Rename(filepath.Join(source, "tree"), filepath.Join(source, "moved")); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(source, "tree"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(source, "tree", "payload"), []byte("attacker"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(destination, "backup", "payload"))
	if err != nil || string(data) != "original" {
		t.Fatalf("copied replacement data = %q, %v", data, err)
	}
}

func TestRootedRemoveCannotEscapeAfterParentReplacement(t *testing.T) {
	fixture := t.TempDir()
	root := filepath.Join(fixture, "root")
	outside := filepath.Join(fixture, "outside")
	if err := os.MkdirAll(filepath.Join(root, "safe", "victim"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(outside, "victim"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := removeAll(root, filepath.Join("safe", "victim"), func() {
		if err := os.RemoveAll(filepath.Join(root, "safe")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(root, "safe")); err != nil {
			t.Fatal(err)
		}
	})
	if err == nil {
		t.Fatal("rooted removal unexpectedly followed the replacement")
	}
	if _, err := os.Stat(filepath.Join(outside, "victim")); err != nil {
		t.Fatalf("outside victim was removed: %v", err)
	}
}

func TestRecordListAndRestoreManifestEntries(t *testing.T) {
	recoveryRoot := t.TempDir()
	project := t.TempDir()
	archive := ArchiveName(time.Date(2026, 7, 14, 12, 34, 56, 123, time.UTC))
	id, err := BackupID(archive, "local", filepath.Join("dir", "payload"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Join(recoveryRoot, id)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(recoveryRoot, id), []byte("losing data"), 0o640); err != nil {
		t.Fatal(err)
	}
	recorded, err := Record(recoveryRoot, archive, "local", filepath.Join("dir", "payload"))
	if err != nil {
		t.Fatal(err)
	}
	if recorded.ID != id || recorded.Loser != "remote" || recorded.Kind != "regular" || recorded.Size != 11 || recorded.Items != 1 {
		t.Fatalf("recorded = %#v", recorded)
	}
	entries, err := List(recoveryRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0] != recorded {
		t.Fatalf("entries = %#v", entries)
	}
	restored, err := Restore(recoveryRoot, id, project, filepath.Join("recovered", "payload"))
	if err != nil || restored.ID != id {
		t.Fatalf("restore = %#v, %v", restored, err)
	}
	data, err := os.ReadFile(filepath.Join(project, "recovered", "payload"))
	if err != nil || string(data) != "losing data" {
		t.Fatalf("restored data = %q, %v", data, err)
	}
	if _, err := Restore(recoveryRoot, id, project, filepath.Join("recovered", "payload")); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("restore overwrite returned %v", err)
	}
}

func TestRecordAppendsMultipleManifestEntries(t *testing.T) {
	root := t.TempDir()
	archive := ArchiveName(time.Now())
	for _, name := range []string{"one", "two"} {
		id, err := BackupID(archive, "local", name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, id)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, id), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Record(root, archive, "local", name); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := List(root)
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries = %#v, %v", entries, err)
	}
	if _, err := Record(root, archive, "local", "one"); err == nil || !strings.Contains(err.Error(), "already recorded") {
		t.Fatalf("duplicate manifest entry returned %v", err)
	}
}

func TestRestoreRejectsSameSizeContentTampering(t *testing.T) {
	root := t.TempDir()
	destination := t.TempDir()
	archive := ArchiveName(time.Now())
	id, err := BackupID(archive, "local", "artifact")
	if err != nil {
		t.Fatal(err)
	}
	fullPath := filepath.Join(root, id)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte("valuable"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Record(root, archive, "local", "artifact"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(root, id, destination, "restored"); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("tampered restore returned %v", err)
	}
	if _, err := os.Lstat(filepath.Join(destination, "restored")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tampered restore created a destination: %v", err)
	}
}

func TestVerificationInventoryDefersCurrentMetadataMismatch(t *testing.T) {
	root := t.TempDir()
	archive := ArchiveName(time.Now())
	id, err := BackupID(archive, "local", "artifact")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Join(root, id)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, id), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Record(root, archive, "local", "artifact"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, id), []byte("different-length"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := List(root); err == nil {
		t.Fatal("ordinary inventory accepted changed structural metadata")
	}
	entries, err := ListForVerification(root)
	if err != nil || len(entries) != 1 || entries[0].ID != id || entries[0].Size != int64(len("original")) || entries[0].Mode != 0o600 {
		t.Fatalf("verification inventory = %#v, %v", entries, err)
	}
	if err := Verify(context.Background(), root, entries[0]); !errors.Is(err, ErrIntegrityMismatch) {
		t.Fatalf("changed entry verification returned %v", err)
	}
}

func TestRestoreAcceptsSchemaOneManifestWithoutDigest(t *testing.T) {
	root := t.TempDir()
	destination := t.TempDir()
	createdAt := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	archive := ArchiveName(createdAt)
	id, err := BackupID(archive, "remote", "legacy-manifest")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Join(root, id)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, id), []byte("compatible"), 0o640); err != nil {
		t.Fatal(err)
	}
	stored := manifest{
		Schema: manifestSchema, CreatedAt: createdAt, Winner: "remote",
		Entries: []manifestEntry{{Path: "legacy-manifest", Kind: "regular", Size: 10, Items: 1, Mode: 0o640}},
	}
	manifestData, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, archive, manifestName), manifestData, 0o600); err != nil {
		t.Fatal(err)
	}
	entry, err := Restore(root, id, destination, "restored")
	if err != nil {
		t.Fatal(err)
	}
	if entry.SHA256 != "" {
		t.Fatalf("legacy manifest unexpectedly gained digest %q", entry.SHA256)
	}
}

func TestDirectoryManifestRetainsOriginalBoundary(t *testing.T) {
	root := t.TempDir()
	project := t.TempDir()
	archive := ArchiveName(time.Now())
	id, err := BackupID(archive, "remote", "challenge")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, id, "nested", "empty"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, id, "nested", "solve.py"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Record(root, archive, "remote", "challenge"); err != nil {
		t.Fatal(err)
	}
	entries, err := List(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != id || entries[0].Kind != "directory" || entries[0].Items != 4 {
		t.Fatalf("directory entry = %#v", entries)
	}
	if _, err := Restore(root, id, project, "restored"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(project, "restored", "nested", "solve.py"))
	if err != nil || string(data) != "x" {
		t.Fatalf("restored directory data = %q, %v", data, err)
	}
	if info, err := os.Stat(filepath.Join(project, "restored", "nested", "empty")); err != nil || !info.IsDir() {
		t.Fatalf("restored empty directory = %#v, %v", info, err)
	}
}

func TestSymlinkManifestRestoresLinkWithoutFollowingIt(t *testing.T) {
	root := t.TempDir()
	project := t.TempDir()
	archive := ArchiveName(time.Now())
	id, err := BackupID(archive, "remote", "link")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Join(root, id)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../outside", filepath.Join(root, id)); err != nil {
		t.Fatal(err)
	}
	if _, err := Record(root, archive, "remote", "link"); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(root, id, project, "restored-link"); err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(filepath.Join(project, "restored-link")); err != nil || target != "../../outside" {
		t.Fatalf("restored link = %q, %v", target, err)
	}
}

func TestLegacyInventoryIsConservativeAndNewestFirst(t *testing.T) {
	root := t.TempDir()
	older := "20260714T123456Z"
	newer := "20260714T123457Z"
	for _, name := range []string{
		filepath.Join(root, older, "local-winner", "dir", "one"),
		filepath.Join(root, newer, "remote-winner", "two"),
	} {
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(filepath.Base(name)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, older, "local-winner", "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := List(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || entries[0].OriginalPath != "two" || !entries[0].Legacy {
		t.Fatalf("legacy entries = %#v", entries)
	}
	for _, entry := range entries {
		if entry.OriginalPath == "dir" {
			t.Fatal("legacy parent directory was presented as an independent recovery boundary")
		}
	}
}

func TestListRejectsMalformedOrChangedManifest(t *testing.T) {
	root := t.TempDir()
	archive := ArchiveName(time.Now())
	archivePath := filepath.Join(root, archive)
	if err := os.MkdirAll(archivePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archivePath, manifestName), []byte(`{"schema":1,"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := List(root); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("malformed manifest returned %v", err)
	}
}

func TestValidateRelativeAndIDs(t *testing.T) {
	for _, value := range []string{"", ".", "../escape", "a/../b", "/absolute", "nul\x00byte"} {
		if err := ValidateRelative(value); err == nil {
			t.Fatalf("unsafe path %q was accepted", value)
		}
	}
	if err := ValidateRelative(filepath.Join("safe", "name")); err != nil {
		t.Fatal(err)
	}
	if _, err := BackupID("not-a-time", "local", "safe"); err == nil {
		t.Fatal("invalid archive was accepted")
	}
	if _, err := BackupID(ArchiveName(time.Now()), "invalid", "safe"); err == nil {
		t.Fatal("invalid winner was accepted")
	}
}

func TestListArchivesAggregatesWholeResolutionUnitsNewestFirst(t *testing.T) {
	root := t.TempDir()
	newest := time.Date(2026, 7, 14, 12, 0, 3, 0, time.UTC)
	grouped := time.Date(2026, 7, 14, 12, 0, 2, 0, time.UTC)
	legacy := time.Date(2026, 7, 14, 12, 0, 1, 0, time.UTC)
	recordPruneTestFile(t, root, newest, "newest", "new")
	recordPruneTestFile(t, root, grouped, "one", "1234")
	recordPruneTestFile(t, root, grouped, filepath.Join("nested", "two"), "123456")
	legacyArchive := legacy.Format("20060102T150405Z")
	legacyID := filepath.Join(legacyArchive, "remote-winner", "legacy")
	if err := os.MkdirAll(filepath.Dir(filepath.Join(root, legacyID)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, legacyID), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	archives, err := ListArchives(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(archives) != 3 || archives[0].ID != ArchiveName(newest) || archives[1].ID != ArchiveName(grouped) || archives[2].ID != legacyArchive {
		t.Fatalf("archive order = %#v", archives)
	}
	if archives[1].Entries != 2 || archives[1].Size != 10 || archives[1].Items != 2 || archives[1].Legacy {
		t.Fatalf("grouped archive = %#v", archives[1])
	}
	if !archives[2].Legacy || archives[2].Entries != 1 || archives[2].Size != 3 {
		t.Fatalf("legacy archive = %#v", archives[2])
	}
}

func TestListArchivesRejectsAggregateOverflow(t *testing.T) {
	rootPath := t.TempDir()
	createdAt := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	archive := ArchiveName(createdAt)
	stored := manifest{
		Schema: manifestSchema, CreatedAt: createdAt, Winner: "local",
		Entries: []manifestEntry{
			{Path: "one", Kind: "regular", Size: int64(^uint64(0) >> 1), Items: 1, Mode: 0o600},
			{Path: "two", Kind: "regular", Size: 1, Items: 1, Mode: 0o600},
		},
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeManifest(root, filepath.Join(archive, manifestName), stored); err != nil {
		root.Close()
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ListArchives(rootPath); err == nil || !strings.Contains(err.Error(), "overflow") {
		t.Fatalf("overflowing archive inventory returned %v", err)
	}
}

func TestPruneArchivesRemovesWholeGroupsAndDoesNotFollowLinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "valuable"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	newest := time.Date(2026, 7, 14, 12, 0, 2, 0, time.UTC)
	old := time.Date(2026, 7, 14, 12, 0, 1, 0, time.UTC)
	recordPruneTestFile(t, root, newest, "newest", "new")
	recordPruneTestFile(t, root, old, "one", "old-one")
	oldArchive := ArchiveName(old)
	linkID, err := BackupID(oldArchive, "local", "link")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "valuable"), filepath.Join(root, linkID)); err != nil {
		t.Fatal(err)
	}
	if _, err := Record(root, oldArchive, "local", "link"); err != nil {
		t.Fatal(err)
	}
	archives, err := ListArchives(root)
	if err != nil || len(archives) != 2 || archives[1].Entries != 2 {
		t.Fatalf("archives = %#v, %v", archives, err)
	}
	results, err := PruneArchives(context.Background(), root, archives[1:])
	if err != nil || len(results) != 1 || results[0].CleanupPending || results[0].Archive.ID != oldArchive {
		t.Fatalf("prune results = %#v, %v", results, err)
	}
	remaining, err := ListArchives(root)
	if err != nil || len(remaining) != 1 || remaining[0].ID != ArchiveName(newest) {
		t.Fatalf("remaining archives = %#v, %v", remaining, err)
	}
	if data, err := os.ReadFile(filepath.Join(outside, "valuable")); err != nil || string(data) != "keep" {
		t.Fatalf("outside link target = %q, %v", data, err)
	}
}

func TestPruneCancellationLeavesRetryableHiddenTombstone(t *testing.T) {
	root := t.TempDir()
	newest := time.Date(2026, 7, 14, 12, 0, 2, 0, time.UTC)
	old := time.Date(2026, 7, 14, 12, 0, 1, 0, time.UTC)
	recordPruneTestFile(t, root, newest, "newest", "new")
	recordPruneTestFile(t, root, old, filepath.Join("tree", "old"), "old")
	archives, err := ListArchives(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	results, err := pruneArchives(ctx, root, archives[1:], pruneHooks{
		syncDirectory: syncRootDirectory,
		afterRename: func(_, _ string) {
			cancel()
		},
	})
	if !errors.Is(err, context.Canceled) || len(results) != 1 || !results[0].CleanupPending {
		t.Fatalf("cancelled prune = %#v, %v", results, err)
	}
	remaining, err := ListArchives(root)
	if err != nil || len(remaining) != 1 || remaining[0].ID != ArchiveName(newest) {
		t.Fatalf("visible archives after cancellation = %#v, %v", remaining, err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	foundTombstone := false
	for _, entry := range entries {
		foundTombstone = foundTombstone || validPruneTombstone(entry.Name())
	}
	if !foundTombstone {
		t.Fatal("cancelled prune did not retain a valid hidden tombstone")
	}
	unrelated := prunePrefix + ArchiveName(old) + "-0123456789abcdef0123456g"
	if err := os.Mkdir(filepath.Join(root, unrelated), 0o700); err != nil {
		t.Fatal(err)
	}
	if results, err := PruneArchives(context.Background(), root, nil); err != nil || len(results) != 0 {
		t.Fatalf("stale cleanup = %#v, %v", results, err)
	}
	entries, err = os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if validPruneTombstone(entry.Name()) {
			t.Fatalf("retry retained tombstone %q", entry.Name())
		}
	}
	if _, err := os.Stat(filepath.Join(root, unrelated)); err != nil {
		t.Fatalf("stale cleanup removed unrelated hidden directory: %v", err)
	}
}

func TestPruneRemovalRejectsFilesystemBoundaryIdentity(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.Mkdir(filepath.Join(rootPath, "tree"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "tree", "valuable"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	info, err := root.Lstat("tree")
	if err != nil {
		t.Fatal(err)
	}
	device, ok := fileDevice(info)
	if !ok {
		t.Fatal("test filesystem has no device identity")
	}
	if err := removeTreeContext(context.Background(), root, "tree", device+1); err == nil || !strings.Contains(err.Error(), "filesystem boundary") {
		t.Fatalf("cross-device removal returned %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(rootPath, "tree", "valuable")); err != nil || string(data) != "keep" {
		t.Fatalf("rejected tree content = %q, %v", data, err)
	}
}

func TestPruneAfterRenameReplacementCannotEscapeRecoveryRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "valuable"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	archive := ArchiveName(createdAt)
	id, err := BackupID(archive, "local", "tree")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, id), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, id, "inside"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Record(root, archive, "local", "tree"); err != nil {
		t.Fatal(err)
	}
	archives, err := ListArchives(root)
	if err != nil {
		t.Fatal(err)
	}
	results, err := pruneArchives(context.Background(), root, archives, pruneHooks{
		syncDirectory: syncRootDirectory,
		afterRename: func(_, tombstone string) {
			path := filepath.Join(root, tombstone, "local-winner", "tree")
			if removeErr := os.RemoveAll(path); removeErr != nil {
				t.Fatal(removeErr)
			}
			if linkErr := os.Symlink(outside, path); linkErr != nil {
				t.Fatal(linkErr)
			}
		},
	})
	if err != nil || len(results) != 1 || results[0].CleanupPending {
		t.Fatalf("replacement prune = %#v, %v", results, err)
	}
	if data, err := os.ReadFile(filepath.Join(outside, "valuable")); err != nil || string(data) != "keep" {
		t.Fatalf("outside replacement target = %q, %v", data, err)
	}
}

func TestPruneValidatesSelectionAndMissingRoot(t *testing.T) {
	if results, err := PruneArchives(context.Background(), filepath.Join(t.TempDir(), "missing"), nil); err != nil || len(results) != 0 {
		t.Fatalf("missing-root prune = %#v, %v", results, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := PruneArchives(ctx, t.TempDir(), nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled prune returned %v", err)
	}
	root := t.TempDir()
	createdAt := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	recordPruneTestFile(t, root, createdAt, "valuable", "keep")
	archives, err := ListArchives(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PruneArchives(context.Background(), root, []Archive{archives[0], archives[0]}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate prune selection returned %v", err)
	}
	changed := archives[0]
	changed.Size++
	if _, err := PruneArchives(context.Background(), root, []Archive{changed}); err == nil || !strings.Contains(err.Error(), "changed after selection") {
		t.Fatalf("changed prune selection returned %v", err)
	}
	remaining, err := ListArchives(root)
	if err != nil || len(remaining) != 1 {
		t.Fatalf("validation changed archives = %#v, %v", remaining, err)
	}
}

func TestPruneSyncFailureRestoresVisibleArchive(t *testing.T) {
	root := t.TempDir()
	createdAt := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	recordPruneTestFile(t, root, createdAt, "valuable", "keep")
	archives, err := ListArchives(root)
	if err != nil {
		t.Fatal(err)
	}
	syncCalls := 0
	results, err := pruneArchives(context.Background(), root, archives, pruneHooks{syncDirectory: func(root *os.Root, name string) error {
		syncCalls++
		if syncCalls == 1 {
			return errors.New("injected sync failure")
		}
		return syncRootDirectory(root, name)
	}})
	if err == nil || len(results) != 0 || syncCalls != 2 {
		t.Fatalf("sync-failed prune = %#v, calls=%d, %v", results, syncCalls, err)
	}
	remaining, listErr := ListArchives(root)
	if listErr != nil || len(remaining) != 1 || remaining[0].ID != ArchiveName(createdAt) {
		t.Fatalf("rolled-back archives = %#v, %v", remaining, listErr)
	}
}

func TestPruneTombstoneGrammarIsExact(t *testing.T) {
	archive := ArchiveName(time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC))
	for value, want := range map[string]bool{
		prunePrefix + archive + "-0123456789abcdef01234567":                 true,
		prunePrefix + "20269999T999999.000000000Z-0123456789abcdef01234567": false,
		prunePrefix + archive + "-0123456789abcdef0123456g":                 false,
		"unrelated-" + archive + "-0123456789abcdef01234567":                false,
	} {
		if got := validPruneTombstone(value); got != want {
			t.Errorf("validPruneTombstone(%q) = %t, want %t", value, got, want)
		}
	}
}

func recordPruneTestFile(t testing.TB, root string, createdAt time.Time, original, content string) string {
	t.Helper()
	archive := ArchiveName(createdAt)
	id, err := BackupID(archive, "local", original)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Join(root, id)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, id), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Record(root, archive, "local", original); err != nil {
		t.Fatal(err)
	}
	return id
}

func BenchmarkCopy1MiB(b *testing.B) {
	source := b.TempDir()
	destination := b.TempDir()
	if err := os.WriteFile(filepath.Join(source, "source"), bytes.Repeat([]byte("x"), 1<<20), 0o600); err != nil {
		b.Fatal(err)
	}
	b.Run("plain", func(b *testing.B) {
		for i := 0; b.Loop(); i++ {
			name := filepath.Join(destination, fmt.Sprintf("plain-%d", i))
			data, err := os.ReadFile(filepath.Join(source, "source"))
			if err != nil {
				b.Fatal(err)
			}
			if err := os.WriteFile(name, data, 0o600); err != nil {
				b.Fatal(err)
			}
			if err := os.Remove(name); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("rooted-durable", func(b *testing.B) {
		for i := 0; b.Loop(); i++ {
			name := fmt.Sprintf("durable-%d", i)
			if err := Copy(source, "source", destination, name); err != nil {
				b.Fatal(err)
			}
			if err := os.Remove(filepath.Join(destination, name)); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkList100(b *testing.B) {
	rootPath := b.TempDir()
	createdAt := time.Date(2026, 7, 14, 12, 34, 56, 789, time.UTC)
	archive := ArchiveName(createdAt)
	stored := manifest{Schema: manifestSchema, CreatedAt: createdAt, Winner: "local"}
	for index := range 100 {
		name := fmt.Sprintf("artifacts/item-%03d", index)
		id, err := BackupID(archive, "local", name)
		if err != nil {
			b.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(rootPath, id)), 0o700); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(rootPath, id), []byte("artifact"), 0o600); err != nil {
			b.Fatal(err)
		}
		stored.Entries = append(stored.Entries, manifestEntry{Path: name, Kind: "regular", Size: 8, Items: 1, Mode: 0o600})
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		b.Fatal(err)
	}
	if err := writeManifest(root, filepath.Join(archive, manifestName), stored); err != nil {
		root.Close()
		b.Fatal(err)
	}
	if err := root.Close(); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		entries, err := List(rootPath)
		if err != nil || len(entries) != 100 {
			b.Fatalf("entries = %d, %v", len(entries), err)
		}
	}
}

func BenchmarkPruneArchive100(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	base := b.TempDir()
	createdAt := time.Date(2026, 7, 14, 12, 34, 56, 789, time.UTC)
	archive := ArchiveName(createdAt)
	for iteration := 0; iteration < b.N; iteration++ {
		rootPath := filepath.Join(base, fmt.Sprintf("prune-%d", iteration))
		stored := manifest{Schema: manifestSchema, CreatedAt: createdAt, Winner: "local"}
		for index := range 100 {
			name := fmt.Sprintf("artifacts/item-%03d", index)
			id, err := BackupID(archive, "local", name)
			if err != nil {
				b.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(filepath.Join(rootPath, id)), 0o700); err != nil {
				b.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(rootPath, id), []byte("artifact"), 0o600); err != nil {
				b.Fatal(err)
			}
			stored.Entries = append(stored.Entries, manifestEntry{Path: name, Kind: "regular", Size: 8, Items: 1, Mode: 0o600})
		}
		root, err := os.OpenRoot(rootPath)
		if err != nil {
			b.Fatal(err)
		}
		if err := writeManifest(root, filepath.Join(archive, manifestName), stored); err != nil {
			root.Close()
			b.Fatal(err)
		}
		if err := root.Close(); err != nil {
			b.Fatal(err)
		}
		archives, err := ListArchives(rootPath)
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		results, err := PruneArchives(context.Background(), rootPath, archives)
		b.StopTimer()
		if err != nil || len(results) != 1 || results[0].CleanupPending {
			b.Fatalf("prune results = %#v, %v", results, err)
		}
		if err := os.RemoveAll(rootPath); err != nil {
			b.Fatal(err)
		}
	}
}
