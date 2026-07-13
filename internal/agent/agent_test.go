package agent

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simonfalke-01/pwnbridge/internal/fsutil"
	"github.com/simonfalke-01/pwnbridge/internal/protocol"
)

func TestRequestRoundTrip(t *testing.T) {
	want := protocol.ExecRequest{Args: []string{"printf", "a b"}, Cwd: "/tmp"}
	encoded, err := EncodeRequest(want)
	if err != nil {
		t.Fatal(err)
	}
	var got protocol.ExecRequest
	if err := decodeRequest([]string{encoded}, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Args) != 2 || got.Args[1] != "a b" {
		t.Fatalf("got %#v", got)
	}
}

func TestRequestRejectsTrailingJSON(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(`{"args":["true"],"cwd":"/tmp","runtime":{},"terminal":{}} {}`))
	var request protocol.ExecRequest
	if err := decodeRequest([]string{encoded}, &request); err == nil {
		t.Fatal("request with a trailing JSON value was accepted")
	}
}

func TestBootstrapStepValidation(t *testing.T) {
	good := protocol.BootstrapStep{ID: "packages-install", Args: []string{"apt-get", "install", "-y", "gdb"}, Environment: map[string]string{"DEBIAN_FRONTEND": "noninteractive"}}
	if !validBootstrapStep(good) {
		t.Fatal("valid structured bootstrap step was rejected")
	}
	bad := good
	bad.Environment = map[string]string{"BAD-NAME": "value"}
	if validBootstrapStep(bad) {
		t.Fatal("invalid environment name was accepted")
	}
	bad = good
	bad.Args = []string{"apt-get", "bad\x00arg"}
	if validBootstrapStep(bad) {
		t.Fatal("NUL argument was accepted")
	}
}

func TestManagedBashRCHasConciseSafePrompt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bashrc")
	if err := writeBashRC(path, "0123456789abcdef", "lima-x86", "ret2win", true, false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, wanted := range []string{`[pwnbridge:lima-x86]`, `ret2win`, `PROMPT_COMMAND`, `$HOME/.bashrc`} {
		if !strings.Contains(content, wanted) {
			t.Fatalf("generated bashrc is missing %q:\n%s", wanted, content)
		}
	}
	if err := writeBashRC(path, "0123456789abcdef", "bad;host", "ret2win", false, false); err == nil {
		t.Fatal("unsafe prompt component was accepted")
	}
}

func TestMoshBashRCUsesRemoteSynchronizationBarrier(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bashrc")
	if err := writeBashRC(path, "0123456789abcdef", "remote-x86", "ret2win", false, true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, wanted := range []string{"shopt -s extdebug", "pwnbridge-shell-barrier", "trap '__pwnbridge_before_command' DEBUG", "post-command sync blocked"} {
		if !strings.Contains(content, wanted) {
			t.Fatalf("generated Mosh bashrc is missing %q:\n%s", wanted, content)
		}
	}
	if strings.Contains(content, "777;pwnbridge") {
		t.Fatal("Mosh bashrc retained the SSH-only OSC marker")
	}
}

func TestEnvironmentFilter(t *testing.T) {
	got := filteredEnvironment([]string{"PATH=/x", "LD_PRELOAD=a", "SSH_TTY=/dev/x", "ZELLIJ=1", "TERM=xterm", "A=b"})
	if got["PATH"] != "/x" || got["LD_PRELOAD"] != "a" || got["A"] != "b" {
		t.Fatalf("missing preserved values: %#v", got)
	}
	for _, key := range []string{"SSH_TTY", "ZELLIJ", "TERM"} {
		if _, ok := got[key]; ok {
			t.Fatalf("leaked %s", key)
		}
	}
}

func TestStringEncodingPreservesBytes(t *testing.T) {
	input := []string{"a b", string([]byte{0xff, 0xfe})}
	encoded := encodeStrings(input)
	if _, err := base64.StdEncoding.DecodeString(encoded[1]); err != nil {
		t.Fatal(err)
	}
	got, err := decodeStrings(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, "|") != strings.Join(input, "|") {
		t.Fatalf("got %#v", got)
	}
}

func TestValidID(t *testing.T) {
	if !validID("0123456789abcdef") || validID("../../escape") {
		t.Fatal("ID validation failed")
	}
}

func TestContainerEnvironmentTranslatesPrivatePaths(t *testing.T) {
	session := filepath.Join("", "home", "user", ".cache", "pwnbridge", "sessions", "abc")
	environment := map[string]string{
		"PWNBRIDGE_SESSION_DIR": session,
		"PWNBRIDGE_BROKER":      "unix:" + filepath.Join(session, "broker.sock"),
	}
	prepareRuntimeEnvironment(protocol.RuntimeSpec{Kind: "container", SessionDir: session}, environment)
	if environment["PWNBRIDGE_SESSION_DIR"] != "/run/pwnbridge" || environment["PWNBRIDGE_BROKER"] != "unix:/run/pwnbridge/broker.sock" {
		t.Fatalf("container paths not translated: %#v", environment)
	}
}

func TestBrokerAddressValidation(t *testing.T) {
	valid := []string{
		"unix:/home/user/.cache/pwnbridge/sessions/abc/broker.sock",
		"unix:/run/pwnbridge/broker.sock",
		"tcp:127.0.0.1:31337",
		"tcp:[::1]:31337",
	}
	for _, address := range valid {
		if _, _, err := validateBrokerAddress(address); err != nil {
			t.Errorf("expected %q to be valid: %v", address, err)
		}
	}
	invalid := []string{
		"unix:/tmp/attacker.sock",
		"unix:relative/broker.sock",
		"tcp:localhost:31337",
		"tcp:192.0.2.1:31337",
		"tcp:127.0.0.1:0",
		"udp:127.0.0.1:31337",
	}
	for _, address := range invalid {
		if _, _, err := validateBrokerAddress(address); err == nil {
			t.Errorf("expected %q to be rejected", address)
		}
	}
}

func TestRemoteZellijTerminalWrapper(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "zellij.log")
	script := `#!/bin/sh
for arg in "$@"; do printf '<%s>' "$arg" >> "$PWNBRIDGE_AGENT_TEST_LOG"; done
printf '\n' >> "$PWNBRIDGE_AGENT_TEST_LOG"
case "$*" in
  *"action new-pane"*) printf 'terminal_9\n' ;;
  *"action list-panes --json"*) printf '[]' ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "zellij"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PWNBRIDGE_AGENT_TEST_LOG", logPath)
	t.Setenv("ZELLIJ", "0")
	terminal := protocol.TerminalSpec{Provider: "remote-zellij", Placement: "down"}
	if err := remoteTerminalWrapper([]string{"gdb", "a b"}, terminal); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(logPath)
	got := string(data)
	for _, wanted := range []string{"<new-pane>", "<--direction><down>", "<gdb><a b>", "<list-panes><--json>"} {
		if !strings.Contains(got, wanted) {
			t.Fatalf("missing %q in calls:\n%s", wanted, got)
		}
	}
}

func TestRemoteTmuxTerminalWrapper(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "tmux.log")
	script := `#!/bin/sh
for arg in "$@"; do printf '<%s>' "$arg" >> "$PWNBRIDGE_AGENT_TEST_LOG"; done
printf '\n' >> "$PWNBRIDGE_AGENT_TEST_LOG"
case "$1" in
  split-window) printf '%%9\n'; exit 0 ;;
  display-message) exit 1 ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "tmux"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PWNBRIDGE_AGENT_TEST_LOG", logPath)
	t.Setenv("TMUX", "/tmp/tmux")
	terminal := protocol.TerminalSpec{Provider: "remote-tmux", Placement: "right"}
	if err := remoteTerminalWrapper([]string{"gdb", "a b"}, terminal); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(logPath)
	got := string(data)
	for _, wanted := range []string{"<split-window>", "<-h>", "<gdb><a b>", "<display-message>"} {
		if !strings.Contains(got, wanted) {
			t.Fatalf("missing %q in calls:\n%s", wanted, got)
		}
	}
}

func TestRemoteMuxUsesIsolatedTmuxServer(t *testing.T) {
	name := "pwnbridge-0123456789abcdef"
	got := remoteMuxArgs("remote-tmux", name, "/private/managed-shell")
	want := []string{"tmux", "-L", name, "new-session", "-s", name, "-n", "shell", "/private/managed-shell"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("tmux argv = %#v, want %#v", got, want)
	}
	got = remoteMuxArgs("remote-zellij", name, "/private/managed-shell")
	if len(got) == 0 || got[0] != "zellij" {
		t.Fatalf("zellij argv = %#v", got)
	}
}

func TestTerminalConfigIsPrivateAndTranslatesContainerPaths(t *testing.T) {
	session := filepath.Join(t.TempDir(), ".cache", "pwnbridge", "sessions", "0123456789abcdef")
	if err := os.MkdirAll(session, 0o700); err != nil {
		t.Fatal(err)
	}
	runtimeSpec := protocol.RuntimeSpec{Kind: "container", ID: "pwnbridge-0123456789abcdef", SessionDir: session}
	terminal := protocol.TerminalSpec{
		SessionID: "0123456789abcdef", Scope: "host", Provider: "custom:test", Placement: "right",
		Broker: "unix:" + filepath.Join(session, "broker.sock"), Token: strings.Repeat("a", 64),
	}
	if err := writeTerminalConfig(session, terminal, runtimeSpec); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(session, "terminal.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("terminal state mode = %o", info.Mode().Perm())
	}
	var got terminalConfig
	if err := fsutil.ReadJSONLimit(path, protocol.MaxFrame, &got); err != nil {
		t.Fatal(err)
	}
	if got.Terminal.SessionDir != "/run/pwnbridge" || got.Terminal.Broker != "unix:/run/pwnbridge/broker.sock" {
		t.Fatalf("container terminal paths not translated: %#v", got.Terminal)
	}
	if got.Runtime.SessionDir != session {
		t.Fatalf("host runtime path was lost: %#v", got.Runtime)
	}
}
