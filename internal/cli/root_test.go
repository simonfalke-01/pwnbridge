package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pwnbridge/pwnbridge/internal/config"
	"github.com/pwnbridge/pwnbridge/internal/paths"
	"github.com/pwnbridge/pwnbridge/internal/shell"
	"github.com/pwnbridge/pwnbridge/internal/syncer"
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

func TestProviderSpecificTerminalLayout(t *testing.T) {
	terminal := config.Defaults().Global.Terminal
	terminal.Provider = "zellij"
	terminal.Zellij.Floating = true
	if placement, _ := terminalLayout(terminal); placement != "floating" {
		t.Fatalf("Zellij layout = %q", placement)
	}
	terminal = config.Defaults().Global.Terminal
	terminal.Provider = "tmux"
	terminal.Tmux.Direction = "vertical"
	terminal.Tmux.Size = "35%"
	if placement, size := terminalLayout(terminal); placement != "down" || size != "35%" {
		t.Fatalf("tmux layout = %q %q", placement, size)
	}
}
