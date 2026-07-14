package provider

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/subprocess"
)

func TestTitleSanitization(t *testing.T) {
	if got := cleanTitle("a\n\x1bb"); got != "ab" {
		t.Fatalf("got %q", got)
	}
}

func TestAutoSelectTerminalFallback(t *testing.T) {
	t.Setenv("ZELLIJ", "")
	t.Setenv("TMUX", "")
	t.Setenv("TMUX_PANE", "")
	t.Setenv("TERM_PROGRAM", "")
	t.Setenv("KITTY_WINDOW_ID", "")
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	p, caps, err := NewRegistry(t.TempDir()).Select(t.Context(), "auto")
	if err != nil {
		t.Fatal(err)
	}
	if p == nil || caps.Name != "terminal-app" {
		t.Fatalf("got %#v", caps)
	}
}

func TestPercent(t *testing.T) {
	if percentValue("50%") != "50" || percentValue("200%") != "" {
		t.Fatal("percent validation failed")
	}
}

func installFakeProviderTool(t *testing.T, name, script string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

func TestZellijProviderLayoutsAndLifecycle(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "zellij.log")
	script := `#!/bin/sh
for arg in "$@"; do printf '<%s>' "$arg" >> "$PWNBRIDGE_PROVIDER_TEST_LOG"; done
printf '\n' >> "$PWNBRIDGE_PROVIDER_TEST_LOG"
case "$*" in
  *"current-tab-info --json"*) printf '{"tab_id":9}' ;;
  *"list-tabs --json"*) printf '[{"position":1,"tab_id":9}]' ;;
  *"list-panes --json"*) printf '[{"id":7,"is_plugin":false,"exited":false,"tab_id":9,"tab_position":1}]' ;;
  *"new-tab"*) printf '9\n' ;;
  *"new-pane"*) printf 'terminal_7\n' ;;
esac
`
	installFakeProviderTool(t, "zellij", script)
	t.Setenv("PWNBRIDGE_PROVIDER_TEST_LOG", logPath)
	t.Setenv("ZELLIJ", "0")
	t.Setenv("ZELLIJ_SESSION_NAME", "")
	p := Zellij{}
	base := Spec{Cwd: "/tmp/work space", Title: "debug", Size: "50%", Focus: true, CloseOnSuccess: true, NearCurrentPane: true, RequireVisible: true, Command: []string{"printf", "a b"}}
	for _, placement := range []string{"right", "down", "floating"} {
		spec := base
		spec.Placement = placement
		handle, err := p.Open(context.Background(), spec)
		if err != nil || handle.ID != "terminal_7" {
			t.Fatalf("%s open: handle=%#v err=%v", placement, handle, err)
		}
	}
	tabSpec := base
	tabSpec.Placement = "tab"
	tab, err := p.Open(context.Background(), tabSpec)
	if err != nil || tab.ID != "9" || tab.Aux != "tab" {
		t.Fatalf("tab open: handle=%#v err=%v", tab, err)
	}
	if state, err := p.Inspect(context.Background(), Handle{ID: "terminal_7"}); err != nil || !state.Exists || !state.Running {
		t.Fatalf("pane inspect: state=%#v err=%v", state, err)
	}
	if state, err := p.Inspect(context.Background(), tab); err != nil || !state.Exists {
		t.Fatalf("tab inspect: state=%#v err=%v", state, err)
	}
	if err := p.Focus(context.Background(), tab); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(context.Background(), tab); err != nil {
		t.Fatal(err)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(logData)
	for _, wanted := range []string{"<current-tab-info><--json>", "<--tab-id><9><--direction><right>", "<--direction><down>", "<--floating>", "<focus-pane-id><terminal_7>", "<new-tab>", "<go-to-tab><2>", "<close-tab><--tab-id><9>", "<printf><a b>"} {
		if !strings.Contains(log, wanted) {
			t.Fatalf("missing %q in Zellij calls:\n%s", wanted, log)
		}
	}
	if strings.Contains(log, "<--near-current-pane>") {
		t.Fatalf("Zellij near-current-pane regression returned: %s", log)
	}
}

func TestZellijLiveNearCurrentPane(t *testing.T) {
	session := os.Getenv("PWNBRIDGE_TEST_ZELLIJ_SESSION")
	if session == "" {
		t.Skip("set PWNBRIDGE_TEST_ZELLIJ_SESSION for live Zellij integration")
	}
	t.Setenv("ZELLIJ", "0")
	t.Setenv("ZELLIJ_SESSION_NAME", session)
	if os.Getenv("ZELLIJ_PANE_ID") == "" {
		t.Setenv("ZELLIJ_PANE_ID", "0")
	}
	p := Zellij{}
	handle, err := p.Open(context.Background(), Spec{
		Cwd: t.TempDir(), Title: "pwnbridge live test", Placement: "right",
		Focus: false, CloseOnSuccess: true, NearCurrentPane: true, RequireVisible: true,
		Command: []string{"/bin/sh", "-c", "sleep 10"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close(context.Background(), handle)
	state, err := p.Inspect(context.Background(), handle)
	if err != nil || !state.Exists || !state.Running {
		t.Fatalf("live pane state=%#v err=%v", state, err)
	}
}

func TestTmuxProviderLayoutsAndArgv(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "tmux.log")
	script := `#!/bin/sh
for arg in "$@"; do printf '<%s>' "$arg" >> "$PWNBRIDGE_PROVIDER_TEST_LOG"; done
printf '\n' >> "$PWNBRIDGE_PROVIDER_TEST_LOG"
case "$1" in split-window|new-window) printf '%%9\n' ;; esac
`
	installFakeProviderTool(t, "tmux", script)
	t.Setenv("PWNBRIDGE_PROVIDER_TEST_LOG", logPath)
	t.Setenv("TMUX", "/tmp/tmux")
	t.Setenv("TMUX_PANE", "%1")
	p := Tmux{}
	for _, placement := range []string{"right", "down", "tab"} {
		handle, err := p.Open(context.Background(), Spec{Cwd: "/tmp/work space", Title: "debug", Placement: placement, Size: "50%", Focus: false, Command: []string{"printf", "a b"}})
		if err != nil || handle.ID != "%9" {
			t.Fatalf("%s open: handle=%#v err=%v", placement, handle, err)
		}
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(data)
	for _, wanted := range []string{"<split-window><-t><%1>", "<-h>", "<new-window>", "<printf><a b>"} {
		if !strings.Contains(log, wanted) {
			t.Fatalf("missing %q in tmux calls:\n%s", wanted, log)
		}
	}
}

func TestWezTermProviderLifecycle(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "wezterm.log")
	script := `#!/bin/sh
for arg in "$@"; do printf '<%s>' "$arg" >> "$PWNBRIDGE_PROVIDER_TEST_LOG"; done
printf '\n' >> "$PWNBRIDGE_PROVIDER_TEST_LOG"
case "$*" in
  *"cli list --format json"*) printf '[{"pane_id":42}]' ;;
  *"cli split-pane"*|*"cli spawn"*) printf '42\n' ;;
esac
`
	installFakeProviderTool(t, "wezterm", script)
	t.Setenv("PWNBRIDGE_PROVIDER_TEST_LOG", logPath)
	p := WezTerm{}
	for _, placement := range []string{"right", "down", "tab"} {
		handle, err := p.Open(context.Background(), Spec{Cwd: "/tmp/work", Placement: placement, Size: "40%", Command: []string{"printf", "a b"}})
		if err != nil || handle.ID != "42" {
			t.Fatalf("%s open: handle=%#v err=%v", placement, handle, err)
		}
	}
	if state, err := p.Inspect(context.Background(), Handle{ID: "42"}); err != nil || !state.Exists {
		t.Fatalf("inspect: state=%#v err=%v", state, err)
	}
	if err := p.Focus(context.Background(), Handle{ID: "42"}); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(context.Background(), Handle{ID: "42"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(logPath)
	log := string(data)
	for _, wanted := range []string{"<split-pane>", "<--right>", "<--bottom>", "<spawn>", "<activate-pane><--pane-id><42>", "<kill-pane><--pane-id><42>", "<printf><a b>"} {
		if !strings.Contains(log, wanted) {
			t.Fatalf("missing %q in WezTerm calls:\n%s", wanted, log)
		}
	}
}

func TestKittyProviderLifecycle(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "kitty.log")
	script := `#!/bin/sh
for arg in "$@"; do printf '<%s>' "$arg" >> "$PWNBRIDGE_PROVIDER_TEST_LOG"; done
printf '\n' >> "$PWNBRIDGE_PROVIDER_TEST_LOG"
case "$*" in
  *"@ ls"*) printf '[{"tabs":[{"windows":[{"id":77}]}]}]' ;;
  *"@ launch"*) printf '77\n' ;;
esac
`
	installFakeProviderTool(t, "kitty", script)
	t.Setenv("PWNBRIDGE_PROVIDER_TEST_LOG", logPath)
	p := Kitty{}
	for _, placement := range []string{"right", "down", "tab"} {
		handle, err := p.Open(context.Background(), Spec{Cwd: "/tmp/work", Title: "debug", Placement: placement, Size: "40%", Focus: false, Command: []string{"printf", "a b"}})
		if err != nil || handle.ID != "77" {
			t.Fatalf("%s open: handle=%#v err=%v", placement, handle, err)
		}
	}
	if state, err := p.Inspect(context.Background(), Handle{ID: "77"}); err != nil || !state.Exists {
		t.Fatalf("inspect: state=%#v err=%v", state, err)
	}
	if err := p.Focus(context.Background(), Handle{ID: "77"}); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(context.Background(), Handle{ID: "77"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(logPath)
	log := string(data)
	for _, wanted := range []string{"<--location><vsplit>", "<--location><hsplit>", "<--type=tab>", "<--keep-focus>", "<focus-window><--match><id:77>", "<close-window><--match><id:77>"} {
		if !strings.Contains(log, wanted) {
			t.Fatalf("missing %q in kitty calls:\n%s", wanted, log)
		}
	}
}

func TestApplicationLauncherContainsOnlyQuotedTrustedArgv(t *testing.T) {
	installFakeProviderTool(t, "open", "#!/bin/sh\nexit 0\n")
	runtimeDir := t.TempDir()
	p := AppWindow{Name: "terminal-app", Application: "Terminal", RuntimeDir: runtimeDir}
	handle, err := p.Open(context.Background(), Spec{Command: []string{"/tmp/trusted helper", "a'b", "$(touch /tmp/nope)"}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(handle.Aux)
	if err != nil {
		t.Fatal(err)
	}
	launcher := string(data)
	for _, quoted := range []string{shellQuote("/tmp/trusted helper"), shellQuote("a'b"), shellQuote("$(touch /tmp/nope)")} {
		if !strings.Contains(launcher, quoted) {
			t.Fatalf("launcher lost quoted argv %q: %s", quoted, launcher)
		}
	}
	if err := p.Close(context.Background(), handle); err != nil {
		t.Fatal(err)
	}
}

func TestCustomProviderRequestIsVersionedAndStructured(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "custom.json")
	script := `#!/bin/sh
payload=$(cat)
printf '%s' "$payload" > "$PWNBRIDGE_PROVIDER_TEST_LOG"
printf '{"provider":"custom:test","id":"handle-1"}\n'
`
	installFakeProviderTool(t, "pwnbridge-terminal-test", script)
	t.Setenv("PWNBRIDGE_PROVIDER_TEST_LOG", logPath)
	handle, err := (Custom{Name: "test"}).Open(context.Background(), Spec{SessionID: "session", RequestID: "request", Command: []string{"/trusted/helper", "a b"}})
	if err != nil || handle.ID != "handle-1" {
		t.Fatalf("handle=%#v err=%v", handle, err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	var request struct {
		Version   int    `json:"version"`
		Operation string `json:"operation"`
		Value     Spec   `json:"value"`
	}
	if err := json.Unmarshal(data, &request); err != nil {
		t.Fatal(err)
	}
	if request.Version != 1 || request.Operation != "open" || len(request.Value.Command) != 2 || request.Value.Command[1] != "a b" {
		t.Fatalf("bad custom provider request: %#v", request)
	}
}

func TestCustomProviderBoundsInheritedOutputPipes(t *testing.T) {
	script := `#!/bin/sh
sleep 4 &
printf '{"provider":"custom:test","id":"handle-1"}\n'
`
	installFakeProviderTool(t, "pwnbridge-terminal-test", script)
	started := time.Now()
	_, err := (Custom{Name: "test"}).Open(context.Background(), Spec{})
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("custom provider with inherited output pipe returned %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("inherited provider output pipe remained open for %v", elapsed)
	}
}

func TestProviderResponseLimits(t *testing.T) {
	t.Run("small open acknowledgement", func(t *testing.T) {
		script := "#!/bin/sh\ndd if=/dev/zero bs=65537 count=1 2>/dev/null\n"
		installFakeProviderTool(t, "tmux", script)
		t.Setenv("TMUX", "/tmp/tmux")
		t.Setenv("TMUX_PANE", "%1")
		_, err := (Tmux{}).Open(context.Background(), Spec{Cwd: "/tmp", Command: []string{"true"}})
		if err == nil || !strings.Contains(err.Error(), "65536-byte limit") {
			t.Fatalf("oversized open response = %v", err)
		}
	})

	t.Run("tmux inspection overflow is not a closed pane", func(t *testing.T) {
		script := "#!/bin/sh\ndd if=/dev/zero bs=65537 count=1 2>/dev/null\n"
		installFakeProviderTool(t, "tmux", script)
		state, err := (Tmux{}).Inspect(context.Background(), Handle{ID: "%1"})
		if state.Exists || err == nil || !strings.Contains(err.Error(), "65536-byte limit") {
			t.Fatalf("oversized tmux inspection state=%#v error=%v", state, err)
		}
	})

	t.Run("Zellij visibility inventory overflow", func(t *testing.T) {
		script := `#!/bin/sh
case "$*" in
  *"new-pane"*) printf 'terminal_7\n' ;;
  *"list-panes --json"*) dd if=/dev/zero bs=1048576 count=5 2>/dev/null ;;
esac
`
		installFakeProviderTool(t, "zellij", script)
		t.Setenv("ZELLIJ", "0")
		_, err := (Zellij{}).Open(context.Background(), Spec{Cwd: "/tmp", RequireVisible: true, Command: []string{"true"}})
		if err == nil || !strings.Contains(err.Error(), "4194304-byte limit") {
			t.Fatalf("oversized Zellij visibility error = %v", err)
		}
	})

	t.Run("terminal inventory maximum and overflow", func(t *testing.T) {
		dir := t.TempDir()
		responsePath := filepath.Join(dir, "response")
		prefix := `[{"pane_id":42,"padding":"`
		suffix := `"}]`
		response := prefix + strings.Repeat("x", maxProviderInventory-len(prefix)-len(suffix)) + suffix
		if err := os.WriteFile(responsePath, []byte(response), 0o600); err != nil {
			t.Fatal(err)
		}
		script := "#!/bin/sh\ncat \"$PWNBRIDGE_PROVIDER_RESPONSE\"\n"
		installFakeProviderTool(t, "wezterm", script)
		t.Setenv("PWNBRIDGE_PROVIDER_RESPONSE", responsePath)
		state, err := (WezTerm{}).Inspect(context.Background(), Handle{ID: "42"})
		if err != nil || !state.Exists {
			t.Fatalf("maximum inventory state=%#v error=%v", state, err)
		}
		if err := os.WriteFile(responsePath, append([]byte(response), 'x'), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := (WezTerm{}).Inspect(context.Background(), Handle{ID: "42"}); err == nil || !strings.Contains(err.Error(), "4194304-byte limit") {
			t.Fatalf("oversized inventory error = %v", err)
		}
	})

	t.Run("custom response maximum and overflow", func(t *testing.T) {
		dir := t.TempDir()
		responsePath := filepath.Join(dir, "response")
		prefix := `{"provider":"custom:test","id":"handle","aux":"`
		suffix := `"}`
		response := prefix + strings.Repeat("x", maxCustomProviderOutput-len(prefix)-len(suffix)) + suffix
		if err := os.WriteFile(responsePath, []byte(response), 0o600); err != nil {
			t.Fatal(err)
		}
		script := "#!/bin/sh\ncat >/dev/null\ncat \"$PWNBRIDGE_PROVIDER_RESPONSE\"\n"
		installFakeProviderTool(t, "pwnbridge-terminal-limit", script)
		t.Setenv("PWNBRIDGE_PROVIDER_RESPONSE", responsePath)
		handle, err := (Custom{Name: "limit"}).Open(context.Background(), Spec{})
		if err != nil || handle.ID != "handle" || len(handle.Aux) == 0 {
			t.Fatalf("maximum custom handle=%#v error=%v", handle, err)
		}
		if err := os.WriteFile(responsePath, append([]byte(response), 'x'), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := (Custom{Name: "limit"}).Open(context.Background(), Spec{}); err == nil || !strings.Contains(err.Error(), "1048576-byte limit") {
			t.Fatalf("oversized custom error = %v", err)
		}
	})

	t.Run("final diagnostic", func(t *testing.T) {
		script := "#!/bin/sh\ndd if=/dev/zero bs=1048576 count=1 >&2 2>/dev/null\nprintf 'final-provider-error\\n' >&2\nexit 9\n"
		installFakeProviderTool(t, "tmux", script)
		t.Setenv("TMUX", "/tmp/tmux")
		t.Setenv("TMUX_PANE", "%1")
		_, err := (Tmux{}).Open(context.Background(), Spec{Cwd: "/tmp", Command: []string{"true"}})
		if err == nil || !strings.Contains(err.Error(), "[output truncated]") || !strings.HasSuffix(err.Error(), "final-provider-error") {
			t.Fatalf("provider diagnostic = %q", err)
		}
		if len(err.Error()) > subprocess.DiagnosticLimit+1024 {
			t.Fatalf("provider diagnostic length = %d", len(err.Error()))
		}
	})
}
