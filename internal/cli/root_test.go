package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/broker"
	"github.com/simonfalke-01/pwnbridge/internal/config"
	"github.com/simonfalke-01/pwnbridge/internal/paths"
	"github.com/simonfalke-01/pwnbridge/internal/protocol"
	"github.com/simonfalke-01/pwnbridge/internal/shell"
	"github.com/simonfalke-01/pwnbridge/internal/syncer"
	"github.com/simonfalke-01/pwnbridge/internal/workspace"
)

func testApp(t *testing.T) (*App, *bytes.Buffer) {
	t.Helper()
	root := t.TempDir()
	p := paths.Paths{Config: filepath.Join(root, "config"), State: filepath.Join(root, "state"), Data: filepath.Join(root, "data"), Cache: filepath.Join(root, "cache")}
	output := &bytes.Buffer{}
	return &App{Paths: p, In: os.Stdin, Out: output, Err: output}, output
}

func execute(t *testing.T, app *App, args ...string) error {
	t.Helper()
	cmd := app.Root()
	cmd.SetOut(app.Out)
	cmd.SetErr(app.Err)
	cmd.SetArgs(args)
	return cmd.Execute()
}

func TestRootRejectsRemovedCommandShorthand(t *testing.T) {
	app, _ := testApp(t)
	err := execute(t, app, "--", "pwninit")
	if err == nil || !strings.Contains(err.Error(), "pwnbridge run") || !strings.Contains(err.Error(), "pb COMMAND") {
		t.Fatalf("removed shorthand was not rejected clearly: %v", err)
	}
}

func TestPBIsAFlagTransparentRunAlias(t *testing.T) {
	app, output := testApp(t)
	app.ProgramName = "pb"
	if err := execute(t, app, "--help"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "pb COMMAND [ARG...]") {
		t.Fatalf("pb help is missing its invocation: %s", output)
	}
	output.Reset()
	if err := execute(t, app, "--", "pwninit"); err == nil || !strings.Contains(err.Error(), "does not need `--`") {
		t.Fatalf("pb accepted a redundant delimiter: %v", err)
	}
	if err := execute(t, app, "pwninit", "--no-template"); err == nil || !strings.Contains(err.Error(), "no host selected") {
		t.Fatalf("pb did not pass command flags through to the run path: %v", err)
	}
}

func TestImplicitWorkspaceGuardBlocksAccidentalLargeDirectory(t *testing.T) {
	root := t.TempDir()
	large := filepath.Join(root, "movie.mkv")
	file, err := os.Create(large)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(implicitWorkspaceMaxBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := guardImplicitWorkspace(root, ""); err == nil || !strings.Contains(err.Error(), "pwnbridge init") {
		t.Fatalf("large implicit workspace was not blocked with remediation: %v", err)
	}
	if err := guardImplicitWorkspace(root, filepath.Join(root, ".pwnbridge.toml")); err != nil {
		t.Fatalf("explicit project was blocked: %v", err)
	}
}

func TestImplicitWorkspaceGuardSkipsBuiltInIgnores(t *testing.T) {
	root := t.TempDir()
	gitDir := filepath.Join(root, ".git", "objects")
	if err := os.MkdirAll(gitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	large := filepath.Join(gitDir, "pack")
	file, err := os.Create(large)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(implicitWorkspaceMaxBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := guardImplicitWorkspace(root, ""); err != nil {
		t.Fatalf("built-in ignored content triggered guard: %v", err)
	}
}

func TestHostLifecycle(t *testing.T) {
	app, output := testApp(t)
	cwd := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	if err := execute(t, app, "host", "add", "x86", "user@example"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "added host x86") {
		t.Fatalf("output: %s", output)
	}
	effective, err := config.Load(cwd, app.Paths)
	if err != nil {
		t.Fatal(err)
	}
	if effective.Global.Hosts["x86"].Destination != "user@example" {
		t.Fatalf("config: %#v", effective.Global)
	}
	output.Reset()
	if err := execute(t, app, "host", "list"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "user@example") {
		t.Fatalf("output: %s", output)
	}
	output.Reset()
	if err := execute(t, app, "host", "add", "remote", "user@remote"); err != nil {
		t.Fatal(err)
	}
	if err := execute(t, app, "host", "default", "remote"); err != nil {
		t.Fatal(err)
	}
	effective, err = config.Load(cwd, app.Paths)
	if err != nil {
		t.Fatal(err)
	}
	if effective.Global.DefaultHost != "remote" {
		t.Fatalf("host default did not update the default: %q", effective.Global.DefaultHost)
	}
	manager := workspace.Manager{Paths: app.Paths}
	if binding, bindErr := manager.Binding(cwd); bindErr != nil || binding != "" {
		t.Fatalf("host default unexpectedly changed the project binding: binding=%q err=%v", binding, bindErr)
	}
	if !strings.Contains(output.String(), "default host is now remote") {
		t.Fatalf("host default output did not describe its effect: %s", output)
	}
	if err := execute(t, app, "host", "use", "x86"); err != nil {
		t.Fatal(err)
	}
	if binding, bindErr := manager.Binding(cwd); bindErr != nil || binding != "x86" {
		t.Fatalf("host use did not bind the current project: binding=%q err=%v", binding, bindErr)
	}
	effective, err = config.Load(cwd, app.Paths)
	if err != nil {
		t.Fatal(err)
	}
	if effective.Global.DefaultHost != "remote" {
		t.Fatalf("host use changed the machine default: %q", effective.Global.DefaultHost)
	}
	if err := execute(t, app, "host", "use", "--default"); err != nil {
		t.Fatal(err)
	}
	if binding, bindErr := manager.Binding(cwd); bindErr != nil || binding != "" {
		t.Fatalf("host use --default did not clear the project binding: binding=%q err=%v", binding, bindErr)
	}
}

func TestHostListHelpExplainsScopeMarkers(t *testing.T) {
	app, output := testApp(t)
	if err := execute(t, app, "host", "list", "--help"); err != nil {
		t.Fatal(err)
	}
	help := output.String()
	if !strings.Contains(help, "(*)") || !strings.Contains(help, "(>)") || !strings.Contains(help, "machine-wide default") || !strings.Contains(help, "current project's effective host") {
		t.Fatalf("host list help does not explain its markers: %s", help)
	}
	output.Reset()
	if err := execute(t, app, "host", "--help"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "* machine default, > current project") {
		t.Fatalf("host command summary does not explain list markers: %s", output)
	}
}

func TestEffectiveConfigReportsProjectBinding(t *testing.T) {
	app, output := testApp(t)
	cwd := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	if err := execute(t, app, "host", "add", "default", "user@default"); err != nil {
		t.Fatal(err)
	}
	if err := execute(t, app, "host", "add", "bound", "user@bound"); err != nil {
		t.Fatal(err)
	}
	manager := workspace.Manager{Paths: app.Paths}
	if err := manager.SetBinding(cwd, "bound"); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := execute(t, app, "config", "show", "--effective", "--json"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"selected_host": "bound"`) {
		t.Fatalf("effective config ignored project binding: %s", output)
	}
}

func TestHostAddRejectsInvalidInputWithoutWriting(t *testing.T) {
	app, _ := testApp(t)
	cwd := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)

	for _, args := range [][]string{
		{"host", "add", "../escape", "user@example"},
		{"host", "add", "x86", "-oProxyCommand=bad"},
	} {
		if err := execute(t, app, args...); err == nil {
			t.Fatalf("expected %q to be rejected", args)
		}
	}
	if _, err := os.Stat(filepath.Join(app.Paths.Config, "config.toml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid host add wrote configuration: %v", err)
	}
}

func TestInitIsNonDestructive(t *testing.T) {
	app, _ := testApp(t)
	cwd := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	if err := execute(t, app, "init"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cwd, ".pwnbridge.toml")
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	if err := execute(t, app, "init"); err == nil {
		t.Fatal("second init should refuse overwrite")
	}
}

func TestVersionJSON(t *testing.T) {
	app, output := testApp(t)
	if err := execute(t, app, "version", "--json"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"protocol": 1`) {
		t.Fatalf("output: %s", output)
	}
}

func TestDoctorWithoutHostDoesNotPanic(t *testing.T) {
	app, _ := testApp(t)
	cwd := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	_ = execute(t, app, "doctor", "--json")
}

func TestJSONEnvelopeAndExitCodes(t *testing.T) {
	app, output := testApp(t)
	if err := execute(t, app, "version", "--json"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"schema": 1`) || !strings.Contains(output.String(), `"data"`) {
		t.Fatalf("missing stable JSON envelope: %s", output)
	}
	if got := ExitCode(&shell.ExitError{Code: 42}); got != 42 {
		t.Fatalf("remote exit status lost: %d", got)
	}
	if got := ExitCode(errors.Join(&shell.ExitError{Code: 42}, context.Canceled)); got != 130 {
		t.Fatalf("local cancellation lost to teardown status: %d", got)
	}
	if got := ExitCode(&syncer.UnhealthyError{}); got != 4 {
		t.Fatalf("sync exit status = %d", got)
	}
	if got := ExitCode(errors.New("generic")); got != 1 {
		t.Fatalf("generic exit status = %d", got)
	}
}

func TestRecoveryCopyDoesNotFollowSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "outside-secret")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "workspace-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(dir, "recovery", "link")
	if err := copyPath(link, backup); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(backup)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("recovery copy followed a workspace symlink")
	}
	if got, _ := os.Readlink(backup); got != target {
		t.Fatalf("symlink target changed: %q", got)
	}
}

func TestConflictPathRejectsSymlinkParents(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "safe"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := rejectSymlinkParents(root, filepath.Join("safe", "file")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := rejectSymlinkParents(root, filepath.Join("link", "file")); err == nil {
		t.Fatal("conflict path traversed a symbolic-link parent")
	}
	check := remoteSymlinkParentCheck("~/.local/share/pwnbridge/workspaces/id/root", "dir/a b/file")
	for _, wanted := range []string{`"$HOME"/'.local/share/pwnbridge/workspaces/id/root'`, `root/dir/a b'`} {
		if !strings.Contains(check, wanted) {
			t.Fatalf("remote parent check is missing %q: %s", wanted, check)
		}
	}
}

func TestBrokerlessSessionUsesOwnerLeaseAndOmitsCredentials(t *testing.T) {
	app, _ := testApp(t)
	localWorkspace := t.TempDir()
	recordPath := filepath.Join(app.Paths.State, "sessions", "0123456789abcdef.json")
	record := broker.SessionRecord{
		OwnerPID: os.Getpid(), ID: "0123456789abcdef",
		Token:          "0123456789abcdef0123456789abcdef",
		LocalWorkspace: localWorkspace, RecordPath: recordPath, LeasePath: recordPath + ".lease",
		RemoteSessionDir: "/remote/session",
		Runtime:          protocol.RuntimeSpec{Kind: "host", Workspace: "/remote/work", SessionDir: "/remote/session"},
	}
	lease, err := workspace.AcquireLock(record.LeasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.SaveSession(recordPath, record); err != nil {
		t.Fatal(err)
	}
	sessions, err := app.liveSessions(localWorkspace)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].ID != record.ID {
		t.Fatalf("brokerless session was not retained: %#v", sessions)
	}

	effective := config.Defaults()
	effective.Global.Terminal.Scope = "remote"
	session := activeSession{Token: record.Token, Record: record, project: &projectContext{Config: effective}}
	environment := session.environment()
	for key := range environment {
		if strings.HasPrefix(key, "PWNBRIDGE_") {
			t.Fatalf("internal terminal state leaked into command environment: %s", key)
		}
	}
	terminal := session.terminalSpec()
	if terminal.Broker != "" || terminal.Token != "" || terminal.Scope != "remote" {
		t.Fatalf("brokerless terminal state is invalid: %#v", terminal)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	sessions, err = app.liveSessions(localWorkspace)
	if err != nil || len(sessions) != 0 {
		t.Fatalf("unlocked stale session survived PID reuse guard: sessions=%#v err=%v", sessions, err)
	}
}

func TestInvalidOldSessionRecordCannotHideLiveKernelLease(t *testing.T) {
	app, _ := testApp(t)
	recordPath := filepath.Join(app.Paths.State, "sessions", "0123456789abcdef.json")
	leasePath := recordPath + ".lease"
	lease, err := workspace.AcquireLock(leasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recordPath, []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(recordPath, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := app.liveSessions(t.TempDir()); err == nil {
		t.Fatal("invalid record with a live kernel lease was silently removed")
	}
	if _, err := os.Stat(recordPath); err != nil {
		t.Fatalf("live invalid record was removed: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if sessions, err := app.liveSessions(t.TempDir()); err != nil || len(sessions) != 0 {
		t.Fatalf("inactive invalid record was not cleaned: sessions=%#v err=%v", sessions, err)
	}
	for _, path := range []string{recordPath, leasePath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale path %s survived cleanup: %v", path, err)
		}
	}

	orphanPath := filepath.Join(app.Paths.State, "sessions", "fedcba9876543210.json")
	if err := os.WriteFile(orphanPath, []byte("also-not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(orphanPath, old, old); err != nil {
		t.Fatal(err)
	}
	if sessions, err := app.liveSessions(t.TempDir()); err != nil || len(sessions) != 0 {
		t.Fatalf("old invalid record without a lease was not cleaned: sessions=%#v err=%v", sessions, err)
	}
	if _, err := os.Stat(orphanPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan invalid record survived cleanup: %v", err)
	}
}

func TestHostUseRecoversFromStaleProjectBinding(t *testing.T) {
	app, _ := testApp(t)
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	effective := config.Defaults()
	effective.Global.DefaultHost = "good"
	effective.Global.Hosts["good"] = config.Host{
		Destination: "pwnbox", Platform: "linux/amd64",
		WorkspaceRoot: "~/.local/share/pwnbridge/workspaces", BootstrapProfile: "pwn",
	}
	if err := config.SaveGlobal(filepath.Join(app.Paths.Config, "config.toml"), effective.Global); err != nil {
		t.Fatal(err)
	}
	manager := workspace.Manager{Paths: app.Paths}
	if err := manager.SetBinding(root, "removed-host"); err != nil {
		t.Fatal(err)
	}
	if err := execute(t, app, "host", "use", "good"); err != nil {
		t.Fatalf("host use could not recover stale binding: %v", err)
	}
	if bound, err := manager.Binding(root); err != nil || bound != "good" {
		t.Fatalf("binding = %q, err=%v", bound, err)
	}
}

func TestIgnoreParsingIsBoundedAndDoesNotImportGitignore(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("never-import-this\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".pwnbridgeignore"), []byte("# comment\n recordings/ \n*.bak\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	patterns, err := projectIgnores(root, []string{"configured/"})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(patterns, "|")
	if got != "configured/|recordings/|*.bak" || strings.Contains(got, "never-import") {
		t.Fatalf("patterns = %q", got)
	}
	if _, err := parseIgnores([]byte{'a', 0, 'b'}, nil); err == nil {
		t.Fatal("NUL ignore pattern was accepted")
	}
	if _, err := parseIgnores([]byte(strings.Repeat("a", 4097)), nil); err == nil {
		t.Fatal("oversized ignore pattern was accepted")
	}
}

func FuzzIgnoreParser(f *testing.F) {
	f.Add([]byte("# comment\ncore*\nrecordings/\n"))
	f.Add([]byte{'a', 0, 'b'})
	f.Fuzz(func(t *testing.T, data []byte) {
		patterns, err := parseIgnores(data, []string{"configured/"})
		if err != nil {
			return
		}
		if len(patterns) > 4096 {
			t.Fatalf("unbounded result: %d", len(patterns))
		}
		for _, pattern := range patterns {
			if pattern == "" || len(pattern) > 4096 || strings.IndexByte(pattern, 0) >= 0 {
				t.Fatalf("invalid accepted pattern %q", pattern)
			}
		}
	})
}
