package agent

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pwnbridge/pwnbridge/internal/protocol"
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
	t.Setenv("PWNBRIDGE_TERMINAL_PROVIDER", "remote-zellij")
	t.Setenv("PWNBRIDGE_TERMINAL_PLACEMENT", "down")
	t.Setenv("ZELLIJ", "0")
	if err := remoteTerminalWrapper([]string{"gdb", "a b"}); err != nil {
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
	t.Setenv("PWNBRIDGE_TERMINAL_PROVIDER", "remote-tmux")
	t.Setenv("PWNBRIDGE_TERMINAL_PLACEMENT", "right")
	t.Setenv("TMUX", "/tmp/tmux")
	if err := remoteTerminalWrapper([]string{"gdb", "a b"}); err != nil {
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
