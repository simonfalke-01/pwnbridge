package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/broker"
	"github.com/simonfalke-01/pwnbridge/internal/config"
	"github.com/simonfalke-01/pwnbridge/internal/paths"
	"github.com/simonfalke-01/pwnbridge/internal/protocol"
	"github.com/simonfalke-01/pwnbridge/internal/recovery"
	"github.com/simonfalke-01/pwnbridge/internal/shell"
	"github.com/simonfalke-01/pwnbridge/internal/subprocess"
	"github.com/simonfalke-01/pwnbridge/internal/syncer"
	"github.com/simonfalke-01/pwnbridge/internal/transport"
	"github.com/simonfalke-01/pwnbridge/internal/workspace"
	"github.com/spf13/cobra"
)

func testApp(t *testing.T) (*App, *bytes.Buffer) {
	t.Helper()
	root := t.TempDir()
	p := paths.Paths{Config: filepath.Join(root, "config"), State: filepath.Join(root, "state"), Data: filepath.Join(root, "data"), Cache: filepath.Join(root, "cache")}
	output := &bytes.Buffer{}
	return &App{Paths: p, In: os.Stdin, Out: output, Err: output}, output
}

func TestShellTransportAutoUsesInlinePredictionAndForcedMoshFailsClosed(t *testing.T) {
	mosh := filepath.Join(t.TempDir(), "mosh")
	if err := os.WriteFile(mosh, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	session := &activeSession{
		Broker: &broker.Broker{},
		Record: broker.SessionRecord{RemoteSocket: "unix:/remote/broker.sock"},
		Master: &transport.Master{Client: transport.Client{Mosh: mosh}},
		Probe:  transport.HostProbe{Tools: map[string]bool{"mosh-server": true}},
	}
	if got, err := shellTransport(config.Host{ShellTransport: "auto"}, "host", session); err != nil || got != "inline" {
		t.Fatalf("auto transport = %q, %v", got, err)
	}
	session.Probe.Tools["mosh-server"] = false
	if got, err := shellTransport(config.Host{ShellTransport: "auto"}, "host", session); err != nil || got != "inline" {
		t.Fatalf("auto transport without Mosh = %q, %v", got, err)
	}
	if _, err := shellTransport(config.Host{ShellTransport: "mosh"}, "host", session); err == nil || !strings.Contains(err.Error(), "mosh-server") {
		t.Fatalf("forced Mosh did not fail closed: %v", err)
	}
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

func TestPaneExecutableResolvesPBToPwnbridge(t *testing.T) {
	dir := t.TempDir()
	pwnbridge := filepath.Join(dir, "pwnbridge")
	if err := os.WriteFile(pwnbridge, []byte("client"), 0o700); err != nil {
		t.Fatal(err)
	}
	pb := filepath.Join(dir, "pb")
	if err := os.Symlink("pwnbridge", pb); err != nil {
		t.Fatal(err)
	}
	got, err := resolvePaneExecutable(pb)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(pwnbridge)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("pane executable = %q, want %q", got, want)
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
	if effective.Global.Hosts["x86"].ShellTransport != "auto" || effective.Global.Hosts["x86"].MoshPort != "60000:61000" {
		t.Fatalf("host add did not install Mosh defaults: %#v", effective.Global.Hosts["x86"])
	}
	if err := execute(t, app, "host", "transport", "x86", "mosh", "--mosh-port", "61000:61010"); err != nil {
		t.Fatal(err)
	}
	effective, err = config.Load(cwd, app.Paths)
	if err != nil {
		t.Fatal(err)
	}
	if effective.Global.Hosts["x86"].ShellTransport != "mosh" || effective.Global.Hosts["x86"].MoshPort != "61000:61010" {
		t.Fatalf("host transport did not persist: %#v", effective.Global.Hosts["x86"])
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
	if !strings.Contains(output.String(), `"protocol": 4`) || !strings.Contains(output.String(), `"config_schema": 2`) {
		t.Fatalf("output: %s", output)
	}
}

func TestBootstrapRecipeCRUD(t *testing.T) {
	app, output := testApp(t)
	file := filepath.Join(t.TempDir(), "recipe.toml")
	data := "schema = 1\nname = 'lab'\ncomponents = ['core', 'gdb', 'python', 'pwntools', 'tracing']\nsystem_packages = ['ripgrep']\npip_packages = ['ropper==1.13.10']\n"
	if err := os.WriteFile(file, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := execute(t, app, "config", "bootstrap", "import", file); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := execute(t, app, "config", "bootstrap", "show", "lab", "--json"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"name": "lab"`) || !strings.Contains(output.String(), "ropper==1.13.10") {
		t.Fatalf("show output: %s", output)
	}
	exported := filepath.Join(t.TempDir(), "export.toml")
	if err := execute(t, app, "config", "bootstrap", "export", "lab", "--output", exported); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(exported); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("export mode: %v %v", info, err)
	}
	if err := execute(t, app, "config", "bootstrap", "remove", "lab"); err != nil {
		t.Fatal(err)
	}
	if err := execute(t, app, "config", "bootstrap", "show", "lab"); err == nil {
		t.Fatal("removed recipe was still available")
	}
}

func TestRootVersionFlag(t *testing.T) {
	app, output := testApp(t)
	if err := execute(t, app, "--version"); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "pwnbridge dev (unknown, unknown)\n" {
		t.Fatalf("--version output = %q", got)
	}
	output.Reset()
	if err := execute(t, app, "-v"); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "pwnbridge dev (unknown, unknown)\n" {
		t.Fatalf("-v output = %q", got)
	}
}

func TestVisibleCommandsHaveDescriptions(t *testing.T) {
	app, _ := testApp(t)
	var visit func(*cobra.Command)
	visit = func(parent *cobra.Command) {
		for _, cmd := range parent.Commands() {
			if cmd.Hidden {
				continue
			}
			if strings.TrimSpace(cmd.Short) == "" {
				t.Errorf("visible command %q has no help description", cmd.CommandPath())
			}
			visit(cmd)
		}
	}
	visit(app.Root())
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

func TestValidateConflictArgumentsRequiresExactSafeUniquePaths(t *testing.T) {
	raw := map[string]any{"conflicts": []any{
		map[string]any{"path": "solve.py"},
		map[string]any{"path": "directory/space name.txt"},
	}}
	paths, err := validateConflictArguments(raw, []string{"solve.py", "directory/space name.txt"})
	if err != nil || strings.Join(paths, "|") != "solve.py|directory/space name.txt" {
		t.Fatalf("validated paths = %v, %v", paths, err)
	}
	for name, arguments := range map[string][]string{
		"escape":       {"../solve.py"},
		"absolute":     {filepath.Join(string(filepath.Separator), "solve.py")},
		"not-conflict": {"other.py"},
		"duplicate":    {"solve.py", "./solve.py"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateConflictArguments(raw, arguments); err == nil {
				t.Fatalf("arguments %v were accepted", arguments)
			}
		})
	}
	if _, err := validateConflictArguments(map[string]any{"status": "broken"}, []string{"solve.py"}); err == nil || !strings.Contains(err.Error(), "no resolvable") {
		t.Fatalf("missing conflicts returned %v", err)
	}
}

func TestWriteConflictDiffShowsSafeUnifiedLocalToRemotePreview(t *testing.T) {
	local := protocol.FileSnapshot{Kind: "regular", Size: 10, Mode: 0o640, Content: []byte("same\nlocal\n"), SHA256: strings.Repeat("a", 64)}
	remote := protocol.FileSnapshot{Kind: "regular", Size: 11, Mode: 0o600, Content: []byte("same\nremote\n"), SHA256: strings.Repeat("b", 64)}
	var output bytes.Buffer
	if err := writeConflictDiff(context.Background(), &output, "space name.txt", local, remote); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, wanted := range []string{`conflict "space name.txt" (local -> remote)`, `--- local/"space name.txt"`, `+++ remote/"space name.txt"`, "-local", "+remote", "metadata: local=regular"} {
		if !strings.Contains(got, wanted) {
			t.Fatalf("preview is missing %q:\n%s", wanted, got)
		}
	}

	output.Reset()
	remote.Content = append([]byte(nil), local.Content...)
	remote.Size = local.Size
	if err := writeConflictDiff(context.Background(), &output, "solve.py", local, remote); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "copies have identical content") || !strings.Contains(output.String(), "metadata:") {
		t.Fatalf("identical content summary = %s", output.String())
	}
}

func TestWriteConflictDiffNeverRendersControlOrUnboundedContent(t *testing.T) {
	unsafeContent := []byte("safe\n\x1b]52;c;dGVzdA==\a")
	local := protocol.FileSnapshot{Kind: "regular", Size: int64(len(unsafeContent)), Mode: 0o600, Content: unsafeContent, SHA256: strings.Repeat("a", 64)}
	remote := protocol.FileSnapshot{Kind: "regular", Size: 4, Mode: 0o600, Content: []byte("safe"), SHA256: strings.Repeat("b", 64)}
	var output bytes.Buffer
	if err := writeConflictDiff(context.Background(), &output, "control.txt", local, remote); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output.Bytes(), []byte{0x1b}) || !strings.Contains(output.String(), "terminal control characters") || !strings.Contains(output.String(), "sha256=") {
		t.Fatalf("unsafe preview = %q", output.Bytes())
	}

	output.Reset()
	local = protocol.FileSnapshot{Kind: "regular", Size: protocol.MaxConflictPreviewBytes + 1, Mode: 0o600, Omitted: true}
	if err := writeConflictDiff(context.Background(), &output, "large.bin", local, remote); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "exceeds 1048576-byte limit") {
		t.Fatalf("large preview = %s", output.String())
	}
}

func TestWriteConflictDiffBoundsFinalToolDiagnostic(t *testing.T) {
	dir := t.TempDir()
	diff := filepath.Join(dir, "diff")
	script := "#!/bin/sh\ndd if=/dev/zero bs=1048576 count=1 >&2 2>/dev/null\nprintf 'final-diff-error\\n' >&2\nexit 2\n"
	if err := os.WriteFile(diff, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	local := protocol.FileSnapshot{Kind: "regular", Size: 2, Mode: 0o600, Content: []byte("a\n")}
	remote := protocol.FileSnapshot{Kind: "regular", Size: 2, Mode: 0o600, Content: []byte("b\n")}
	var output bytes.Buffer
	err := writeConflictDiff(context.Background(), &output, "solve.py", local, remote)
	if err == nil || !strings.Contains(err.Error(), "[output truncated]") || !strings.HasSuffix(err.Error(), "final-diff-error") {
		t.Fatalf("diff diagnostic = %q", err)
	}
	if len(err.Error()) > subprocess.DiagnosticLimit+1024 {
		t.Fatalf("diff diagnostic length = %d", len(err.Error()))
	}
}

func TestWriteConflictDiffSummarizesNonRegularTypes(t *testing.T) {
	cases := []struct {
		name   string
		local  protocol.FileSnapshot
		remote protocol.FileSnapshot
		want   string
	}{
		{name: "links", local: protocol.FileSnapshot{Kind: "symlink", LinkTarget: "local\nlink"}, remote: protocol.FileSnapshot{Kind: "symlink", LinkTarget: "remote"}, want: `symlink -> "local\nlink"`},
		{name: "different", local: protocol.FileSnapshot{Kind: "directory", Mode: 0o700}, remote: protocol.FileSnapshot{Kind: "missing"}, want: "endpoint types differ"},
		{name: "special", local: protocol.FileSnapshot{Kind: "special", Mode: 0o600}, remote: protocol.FileSnapshot{Kind: "special", Mode: 0o600}, want: "unavailable for special"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := writeConflictDiff(context.Background(), &output, test.name, test.local, test.remote); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), test.want) {
				t.Fatalf("summary = %s", output.String())
			}
		})
	}
}

func TestDecodeSnapshotIsStrictAndDiffCommandIsDiscoverable(t *testing.T) {
	var snapshot protocol.FileSnapshot
	if err := decodeSnapshot([]byte("{\"kind\":\"regular\",\"size\":1,\"sha256\":\"2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881\",\"content\":\"eA==\"}\n"), &snapshot); err != nil || string(snapshot.Content) != "x" {
		t.Fatalf("snapshot = %#v, %v", snapshot, err)
	}
	for _, input := range []string{
		`{"kind":"unknown"}`,
		`{"kind":"regular","extra":true}`,
		`{"kind":"missing"} {"kind":"missing"}`,
		`{"kind":"regular","size":1048577,"omitted":false}`,
		`{"kind":"regular","size":1,"sha256":"wrong","content":"eA=="}`,
	} {
		if err := decodeSnapshot([]byte(input), &snapshot); err == nil {
			t.Fatalf("unsafe snapshot %q was accepted", input)
		}
	}
	app, _ := testApp(t)
	command, _, err := app.Root().Find([]string{"sync", "diff"})
	if err != nil || command.Name() != "diff" {
		t.Fatalf("sync diff command = %v, %v", command, err)
	}
}

func TestRecoveryCommandsListJSONAndRestoreWithoutOverwrite(t *testing.T) {
	app, output := testApp(t)
	projectRoot := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(projectRoot); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	effective := config.Defaults()
	effective.Global.DefaultHost = "test"
	effective.Global.Hosts["test"] = config.Host{
		Destination: "pwnbox", Platform: "linux/amd64",
		WorkspaceRoot: "~/.local/share/pwnbridge/workspaces", BootstrapProfile: "pwn",
	}
	if err := config.SaveGlobal(filepath.Join(app.Paths.Config, "config.toml"), effective.Global); err != nil {
		t.Fatal(err)
	}
	project, err := app.loadProject(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	archive := recovery.ArchiveName(time.Date(2026, 7, 14, 12, 34, 56, 7, time.UTC))
	original := "control\nname"
	id, err := recovery.BackupID(archive, "local", original)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Join(project.WS.RecoveryPath, id)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project.WS.RecoveryPath, id), []byte("recover me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Record(project.WS.RecoveryPath, archive, "local", original); err != nil {
		t.Fatal(err)
	}
	if err := execute(t, app, "sync", "recovery", "list"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "control\nname") || !strings.Contains(output.String(), `control\nname`) {
		t.Fatalf("human recovery output was not escaped: %q", output.String())
	}
	output.Reset()
	if err := execute(t, app, "sync", "recovery", "list", "--json"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"entries"`) || !strings.Contains(output.String(), `"original_path": "control\nname"`) {
		t.Fatalf("recovery JSON = %s", output)
	}
	output.Reset()
	if err := execute(t, app, "sync", "recovery", "restore", id, "--to", "recovered"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(projectRoot, "recovered"))
	if err != nil || string(data) != "recover me" {
		t.Fatalf("restored data = %q, %v", data, err)
	}
	if err := execute(t, app, "sync", "recovery", "restore", id, "--to", "recovered"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("restore overwrite returned %v", err)
	}
}

func TestRecoveryCommandIsDiscoverableAndRequiresExplicitDestination(t *testing.T) {
	app, _ := testApp(t)
	command, _, err := app.Root().Find([]string{"sync", "recovery", "restore"})
	if err != nil || command.Name() != "restore" {
		t.Fatalf("sync recovery restore command = %v, %v", command, err)
	}
	if err := execute(t, app, "sync", "recovery", "restore", "id"); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("missing restore destination returned %v", err)
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
	ignorePath := filepath.Join(root, ".pwnbridgeignore")
	if err := os.Remove(ignorePath); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(ignorePath, 0o600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := projectIgnores(root, nil); err == nil {
		t.Fatal("FIFO ignore file was accepted")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("FIFO ignore rejection took %v", elapsed)
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
