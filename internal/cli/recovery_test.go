package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/config"
	"github.com/simonfalke-01/pwnbridge/internal/recovery"
)

func TestRecoveryVerifyAllContinuesAndUsesNoNetwork(t *testing.T) {
	app, output, project := setupRecoveryVerifyCLI(t)
	validID := recordRecoveryFile(t, project.WS.RecoveryPath, time.Date(2026, 7, 14, 12, 0, 2, 0, time.UTC), "valid\nname", "valuable")
	tamperedID := recordRecoveryFile(t, project.WS.RecoveryPath, time.Date(2026, 7, 14, 12, 0, 3, 0, time.UTC), "tampered", "original")
	if err := os.WriteFile(filepath.Join(project.WS.RecoveryPath, tamperedID), []byte("modified-and-longer"), 0o640); err != nil {
		t.Fatal(err)
	}
	legacyArchive := recovery.ArchiveName(time.Date(2026, 7, 14, 12, 0, 1, 0, time.UTC))
	legacyID, err := recovery.BackupID(legacyArchive, "local", "legacy")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Join(project.WS.RecoveryPath, legacyID)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project.WS.RecoveryPath, legacyID), []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}

	bin := t.TempDir()
	marker := filepath.Join(bin, "external-command-ran")
	for _, name := range []string{"ssh", "mutagen"} {
		script := "#!/bin/sh\ntouch \"" + marker + "\"\nexit 99\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)

	err = execute(t, app, "sync", "recovery", "verify")
	if err == nil || !strings.Contains(err.Error(), "1 failed, 1 without recorded digests") {
		t.Fatalf("incomplete verification returned %v", err)
	}
	for _, wanted := range []string{
		"failed id=" + strconvQuote(tamperedID) + " sha256=", "reason=integrity-mismatch",
		"verified id=" + strconvQuote(validID) + " sha256=", "unverified id=" + strconvQuote(legacyID),
		"summary verified=1 failed=1 unverified=1 complete=false",
	} {
		if !strings.Contains(output.String(), wanted) {
			t.Fatalf("verification output missing %q:\n%s", wanted, output.String())
		}
	}
	if strings.Contains(output.String(), validID) {
		t.Fatalf("verification output did not quote a control-bearing ID: %q", output.String())
	}
	if strings.Index(output.String(), strconvQuote(tamperedID)) > strings.Index(output.String(), strconvQuote(validID)) {
		t.Fatalf("verification did not retain newest-first inventory order:\n%s", output.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("offline verification invoked SSH or Mutagen: %v", err)
	}

	output.Reset()
	err = execute(t, app, "sync", "recovery", "verify", "--json")
	if err == nil {
		t.Fatal("incomplete JSON verification returned success")
	}
	var envelope struct {
		Schema int                        `json:"schema"`
		Data   recoveryVerificationReport `json:"data"`
	}
	if err := json.Unmarshal(output.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Schema != 1 || envelope.Data.Verified != 1 || envelope.Data.Failed != 1 || envelope.Data.Unverified != 1 || envelope.Data.Checked != 3 || envelope.Data.Total != 3 || envelope.Data.Complete {
		t.Fatalf("verification JSON = %#v", envelope)
	}
	if len(envelope.Data.Entries) != 3 || envelope.Data.Entries[0].ID != tamperedID || envelope.Data.Entries[1].ID != validID || envelope.Data.Entries[2].ID != legacyID {
		t.Fatalf("verification JSON order = %#v", envelope.Data.Entries)
	}

	output.Reset()
	if err := execute(t, app, "sync", "recovery", "verify", validID); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "summary verified=1 failed=0 unverified=0 complete=true") || strings.Contains(output.String(), tamperedID) {
		t.Fatalf("selected verification = %s", output.String())
	}
}

func TestRecoveryVerifySelectionDiscoveryEmptyAndOutputErrors(t *testing.T) {
	entries := []recovery.Entry{{ID: "one"}, {ID: "two"}}
	selected, err := selectRecoveryEntries(entries, []string{"two", "one"})
	if err != nil || len(selected) != 2 || selected[0].ID != "two" || selected[1].ID != "one" {
		t.Fatalf("selected entries = %#v, %v", selected, err)
	}
	for _, ids := range [][]string{{"one", "one"}, {"missing"}, {"../escape"}} {
		if _, err := selectRecoveryEntries(entries, ids); err == nil {
			t.Fatalf("unsafe selection %#v was accepted", ids)
		}
	}
	if err := renderRecoveryVerification(cliFailingWriter{}, recoveryVerificationReport{Complete: true}); err == nil {
		t.Fatal("verification output failure was ignored")
	}

	app, output, _ := setupRecoveryVerifyCLI(t)
	command, _, err := app.Root().Find([]string{"sync", "recovery", "verify"})
	if err != nil || command.Name() != "verify" {
		t.Fatalf("recovery verify command = %v, %v", command, err)
	}
	if err := execute(t, app, "sync", "recovery", "verify"); err != nil {
		t.Fatal(err)
	}
	if output.String() != "no recovery copies\nsummary verified=0 failed=0 unverified=0 complete=true checked=0 total=0\n" {
		t.Fatalf("empty verification output = %q", output.String())
	}
}

func TestRecoveryPrunePreviewsAndRemovesWholeArchivesOffline(t *testing.T) {
	app, output, project := setupRecoveryVerifyCLI(t)
	newest := time.Date(2026, 7, 14, 12, 0, 3, 0, time.UTC)
	old := time.Date(2026, 7, 14, 12, 0, 2, 0, time.UTC)
	newestID := recordRecoveryFile(t, project.WS.RecoveryPath, newest, "newest", "new")
	oldOne := recordRecoveryFile(t, project.WS.RecoveryPath, old, "old-one", "1234")
	oldTwo := recordRecoveryFile(t, project.WS.RecoveryPath, old, filepath.Join("nested", "old-two"), "123456")

	bin := t.TempDir()
	marker := filepath.Join(bin, "external-command-ran")
	for _, name := range []string{"ssh", "mutagen"} {
		script := "#!/bin/sh\ntouch \"" + marker + "\"\nexit 99\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)

	if err := execute(t, app, "sync", "recovery", "prune", "--keep-last", "1", "--dry-run"); err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{
		"would-prune archive=" + strconvQuote(recovery.ArchiveName(old)),
		"entries=2 logical_bytes=10 items=2",
		"summary kept=1 selected=1 pruned=0 pending_cleanup=0 not_run=0 logical_bytes=10 dry_run=true complete=true",
	} {
		if !strings.Contains(output.String(), wanted) {
			t.Fatalf("prune preview missing %q:\n%s", wanted, output)
		}
	}
	for _, id := range []string{newestID, oldOne, oldTwo} {
		if _, err := os.Lstat(filepath.Join(project.WS.RecoveryPath, id)); err != nil {
			t.Fatalf("dry-run removed %q: %v", id, err)
		}
	}

	output.Reset()
	if err := execute(t, app, "sync", "recovery", "prune", "--keep-last", "1", "--yes"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "pruned archive="+strconvQuote(recovery.ArchiveName(old))) ||
		!strings.Contains(output.String(), "summary kept=1 selected=1 pruned=1 pending_cleanup=0 not_run=0 logical_bytes=10 dry_run=false complete=true") {
		t.Fatalf("confirmed prune output = %s", output)
	}
	archives, err := recovery.ListArchives(project.WS.RecoveryPath)
	if err != nil || len(archives) != 1 || archives[0].ID != recovery.ArchiveName(newest) {
		t.Fatalf("remaining archives = %#v, %v", archives, err)
	}
	recordRecoveryFile(t, project.WS.RecoveryPath, time.Date(2026, 7, 14, 12, 0, 1, 0, time.UTC), "json-old", "old")
	output.Reset()
	if err := execute(t, app, "sync", "recovery", "prune", "--keep-last", "1", "--yes", "--json"); err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Schema int                 `json:"schema"`
		Data   recoveryPruneReport `json:"data"`
	}
	if err := json.Unmarshal(output.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Schema != 1 || !envelope.Data.Complete || envelope.Data.Pruned != 1 || envelope.Data.PendingCleanup != 0 || envelope.Data.NotRun != 0 || len(envelope.Data.Archives) != 1 || envelope.Data.Archives[0].Status != "pruned" {
		t.Fatalf("confirmed prune JSON = %#v", envelope)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("offline prune invoked SSH or Mutagen: %v", err)
	}
}

func TestRecoveryPruneJSONNoOpAndValidation(t *testing.T) {
	app, output, project := setupRecoveryVerifyCLI(t)
	createdAt := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	recordRecoveryFile(t, project.WS.RecoveryPath, createdAt, "only", "valuable")
	if err := execute(t, app, "sync", "recovery", "prune", "--keep-last", "1", "--dry-run", "--json"); err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Schema int                 `json:"schema"`
		Data   recoveryPruneReport `json:"data"`
	}
	if err := json.Unmarshal(output.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Schema != 1 || envelope.Data.Kept != 1 || envelope.Data.Selected != 0 || !envelope.Data.DryRun || !envelope.Data.Complete || len(envelope.Data.Archives) != 0 {
		t.Fatalf("no-op prune JSON = %#v", envelope)
	}

	for _, args := range [][]string{
		{"sync", "recovery", "prune", "--keep-last", "0", "--dry-run"},
		{"sync", "recovery", "prune", "--keep-last", "1"},
		{"sync", "recovery", "prune", "--keep-last", "1", "--dry-run", "--yes"},
	} {
		if err := execute(t, app, args...); err == nil {
			t.Fatalf("invalid prune arguments %#v were accepted", args)
		}
	}
	if selected := selectRecoveryArchivesForPrune([]recovery.Archive{{ID: "new"}, {ID: "old"}}, 1); len(selected) != 1 || selected[0].ID != "old" {
		t.Fatalf("prune selection = %#v", selected)
	}
	if selected := selectRecoveryArchivesForPrune([]recovery.Archive{{ID: "only"}}, 2); len(selected) != 0 {
		t.Fatalf("over-retained prune selection = %#v", selected)
	}
}

func TestRecoveryPruneFailsClosedOnCorruptCatalog(t *testing.T) {
	app, _, project := setupRecoveryVerifyCLI(t)
	newest := time.Date(2026, 7, 14, 12, 0, 2, 0, time.UTC)
	old := time.Date(2026, 7, 14, 12, 0, 1, 0, time.UTC)
	newestID := recordRecoveryFile(t, project.WS.RecoveryPath, newest, "newest", "new")
	oldID := recordRecoveryFile(t, project.WS.RecoveryPath, old, "old", "old")
	manifest := filepath.Join(project.WS.RecoveryPath, recovery.ArchiveName(old), "manifest.json")
	if err := os.WriteFile(manifest, []byte(`{"schema":1,"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := execute(t, app, "sync", "recovery", "prune", "--keep-last", "1", "--yes"); err == nil {
		t.Fatal("prune accepted a corrupt catalog")
	}
	for _, id := range []string{newestID, oldID} {
		if _, err := os.Lstat(filepath.Join(project.WS.RecoveryPath, id)); err != nil {
			t.Fatalf("failed-closed prune removed %q: %v", id, err)
		}
	}
}

func TestRecoveryPrunePartialReportAndOutputFailure(t *testing.T) {
	all := []recovery.Archive{
		{ID: "new", CreatedAt: time.Unix(3, 0), Entries: 1, Size: 1, Items: 1},
		{ID: "old", CreatedAt: time.Unix(2, 0), Entries: 2, Size: 10, Items: 2},
		{ID: "older", CreatedAt: time.Unix(1, 0), Entries: 1, Size: 5, Items: 1},
	}
	report, err := newRecoveryPruneReport(all, all[1:], 1, false)
	if err != nil {
		t.Fatal(err)
	}
	report.apply([]recovery.PruneResult{{Archive: all[1], CleanupPending: true}})
	if report.PendingCleanup != 1 || report.Pruned != 0 || report.NotRun != 1 || report.Archives[0].Status != "pending-cleanup" || report.Archives[1].Status != "not-run" {
		t.Fatalf("partial prune report = %#v", report)
	}
	if err := renderRecoveryPrune(cliFailingWriter{}, report); err == nil {
		t.Fatal("prune output failure was ignored")
	}
}

func TestVerifyRecoveryEntriesPreservesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := verifyRecoveryEntries(ctx, t.TempDir(), []recovery.Entry{{ID: "entry", SHA256: strings.Repeat("a", 64)}})
	if err != context.Canceled {
		t.Fatalf("canceled entry verification returned %v", err)
	}
}

func TestRecoveryVerificationProgressAndCancelledPartialOutput(t *testing.T) {
	for _, test := range []struct {
		progress recoveryVerificationProgress
		want     string
	}{
		{recoveryVerificationProgress{Index: 1, Total: 2, Bytes: 25, TotalBytes: 100}, "Verifying recovery 1/2 (25%)"},
		{recoveryVerificationProgress{Index: 2, Total: 2, Items: 3, TotalItems: 4}, "Verifying recovery 2/2 (75%)"},
		{recoveryVerificationProgress{Index: 1, Total: 1, Bytes: 200, TotalBytes: 100}, "Verifying recovery 1/1 (99%)"},
		{recoveryVerificationProgress{Index: 1, Total: 1, Bytes: 100, TotalBytes: 100, Done: true}, "Verifying recovery 1/1 (100%)"},
	} {
		if got := formatRecoveryProgress(test.progress); got != test.want {
			t.Errorf("formatRecoveryProgress(%#v) = %q, want %q", test.progress, got, test.want)
		}
	}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "large"), bytes.Repeat([]byte("x"), 2<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	summary, err := recovery.Digest(root, "large")
	if err != nil {
		t.Fatal(err)
	}
	entry := recovery.Entry{ID: "large", Kind: summary.Kind, Size: summary.Size, Items: summary.Items, Mode: summary.Mode, SHA256: summary.SHA256}
	if err := os.WriteFile(filepath.Join(root, "small"), []byte("verified first"), 0o600); err != nil {
		t.Fatal(err)
	}
	smallSummary, err := recovery.Digest(root, "small")
	if err != nil {
		t.Fatal(err)
	}
	small := recovery.Entry{ID: "small", Kind: smallSummary.Kind, Size: smallSummary.Size, Items: smallSummary.Items, Mode: smallSummary.Mode, SHA256: smallSummary.SHA256}
	ctx, cancel := context.WithCancel(context.Background())
	report, err := verifyRecoveryEntriesProgress(ctx, root, []recovery.Entry{small, entry}, func(update recoveryVerificationProgress) {
		if update.Index == 2 && update.Bytes > 0 {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) || report.Complete || report.Checked != 1 || report.Total != 2 || len(report.Entries) != 1 || report.Entries[0].ID != "small" || report.Entries[0].Status != "verified" {
		t.Fatalf("cancelled progress report = %#v, error %v", report, err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	report, err = verifyRecoveryEntriesProgress(ctx, root, []recovery.Entry{small}, func(update recoveryVerificationProgress) {
		if update.Done {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) || report.Complete || report.Checked != 1 || report.Total != 1 || len(report.Entries) != 1 || report.Entries[0].Status != "verified" {
		t.Fatalf("final-boundary cancellation report = %#v, error %v", report, err)
	}

	app, output, project := setupRecoveryVerifyCLI(t)
	recordRecoveryFile(t, project.WS.RecoveryPath, time.Date(2026, 7, 14, 12, 0, 4, 0, time.UTC), "cancelled", "content")
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	command := app.Root()
	command.SetOut(app.Out)
	command.SetErr(app.Err)
	command.SetArgs([]string{"sync", "recovery", "verify", "--json"})
	err = command.ExecuteContext(ctx)
	if !errors.Is(err, context.Canceled) || ExitCode(err) != 130 {
		t.Fatalf("cancelled command returned %v (exit %d)", err, ExitCode(err))
	}
	var envelope struct {
		Schema int                        `json:"schema"`
		Data   recoveryVerificationReport `json:"data"`
	}
	if decodeErr := json.Unmarshal(output.Bytes(), &envelope); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if envelope.Schema != 1 || envelope.Data.Complete || envelope.Data.Checked != 0 || envelope.Data.Total != 1 || len(envelope.Data.Entries) != 0 {
		t.Fatalf("cancelled JSON report = %#v", envelope)
	}
}

func TestVerifyRecoveryEntriesContinuesAfterReadError(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "valid"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	summary, err := recovery.Digest(root, "valid")
	if err != nil {
		t.Fatal(err)
	}
	valid := recovery.Entry{ID: "valid", Kind: summary.Kind, Size: summary.Size, Items: summary.Items, Mode: summary.Mode, SHA256: summary.SHA256}
	missing := valid
	missing.ID = "missing"
	report, err := verifyRecoveryEntries(context.Background(), root, []recovery.Entry{missing, valid})
	if err != nil {
		t.Fatal(err)
	}
	if report.Failed != 1 || report.Verified != 1 || report.Complete || report.Entries[0].Reason != "read-error" || report.Entries[1].Status != "verified" {
		t.Fatalf("continued verification = %#v", report)
	}
}

func setupRecoveryVerifyCLI(t *testing.T) (*App, *bytes.Buffer, *projectContext) {
	t.Helper()
	app, output := testApp(t)
	if err := app.Paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	projectRoot := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(projectRoot); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	effective := config.Defaults()
	effective.Global.DefaultHost = "test"
	effective.Global.Hosts["test"] = config.Host{
		Destination: "must-not-connect", Platform: "linux/amd64",
		WorkspaceRoot: "~/.local/share/pwnbridge/workspaces", BootstrapProfile: "pwn",
	}
	if err := config.SaveGlobal(filepath.Join(app.Paths.Config, "config.toml"), effective.Global); err != nil {
		t.Fatal(err)
	}
	project, err := app.loadProject(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	return app, output, project
}

func recordRecoveryFile(t *testing.T, root string, created time.Time, original, content string) string {
	t.Helper()
	archive := recovery.ArchiveName(created)
	id, err := recovery.BackupID(archive, "local", original)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Join(root, id)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, id), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Record(root, archive, "local", original); err != nil {
		t.Fatal(err)
	}
	return id
}

func strconvQuote(value string) string {
	return strconv.QuoteToASCII(value)
}

type cliFailingWriter struct{}

func (cliFailingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
