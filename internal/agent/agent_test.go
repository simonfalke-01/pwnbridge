package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/simonfalke-01/pwnbridge/internal/fsutil"
	"github.com/simonfalke-01/pwnbridge/internal/protocol"
	"github.com/simonfalke-01/pwnbridge/internal/recovery"
	"github.com/simonfalke-01/pwnbridge/internal/version"
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

func TestSnapshotCommandReturnsBoundedRootedFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "solve.py"), []byte("print('local')\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeRequest(protocol.SnapshotRequest{Root: root, Path: "solve.py"})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := snapshotCommand([]string{encoded}, &output); err != nil {
		t.Fatal(err)
	}
	var snapshot protocol.FileSnapshot
	if err := json.Unmarshal(output.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Kind != "regular" || string(snapshot.Content) != "print('local')\n" || snapshot.Mode != 0o640 {
		t.Fatalf("snapshot = %#v", snapshot)
	}

	escape, err := EncodeRequest(protocol.SnapshotRequest{Root: root, Path: "../secret"})
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshotCommand([]string{escape}, &output); err == nil {
		t.Fatal("snapshot command accepted an escaping path")
	}
}

func TestRecoveryStreamWaitsForDurableAckThenRemoves(t *testing.T) {
	source := t.TempDir()
	destination := t.TempDir()
	if err := os.Mkdir(filepath.Join(source, "tree"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "tree", "payload"), []byte("remote loser"), 0o640); err != nil {
		t.Fatal(err)
	}
	request, err := EncodeRequest(protocol.RecoveryRequest{Root: source, Path: "tree"})
	if err != nil {
		t.Fatal(err)
	}
	agentInput, clientInput := io.Pipe()
	clientOutput, agentOutput := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- recoveryStreamCommand([]string{request}, agentInput, agentOutput)
		_ = agentOutput.Close()
	}()
	summary, err := recovery.ExtractArchive(clientOutput, destination, "backup")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(source, "tree", "payload")); err != nil {
		t.Fatalf("source disappeared before ACK: %v", err)
	}
	if err := json.NewEncoder(clientInput).Encode(protocol.RecoveryAck{Commit: true, SHA256: summary.SHA256}); err != nil {
		t.Fatal(err)
	}
	if err := clientInput.Close(); err != nil {
		t.Fatal(err)
	}
	var result protocol.RecoveryResult
	if err := json.NewDecoder(clientOutput).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !result.Removed || result.SHA256 != summary.SHA256 || result.Items != 2 {
		t.Fatalf("result = %#v", result)
	}
	if _, err := os.Lstat(filepath.Join(source, "tree")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("acknowledged source remains: %v", err)
	}
}

func TestRecoveryStreamPreservesSourceWithoutMatchingAck(t *testing.T) {
	for _, test := range []struct {
		name  string
		input []byte
	}{
		{name: "no-ack"},
		{name: "mismatch", input: []byte(`{"commit":true,"sha256":"wrong"}`)},
		{name: "trailing", input: []byte(`{"commit":true,"sha256":"wrong"} {}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "loser"), []byte("valuable"), 0o600); err != nil {
				t.Fatal(err)
			}
			request, err := EncodeRequest(protocol.RecoveryRequest{Root: root, Path: "loser"})
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			if err := recoveryStreamCommand([]string{request}, bytes.NewReader(test.input), &output); err == nil {
				t.Fatal("invalid acknowledgement was accepted")
			}
			if data, err := os.ReadFile(filepath.Join(root, "loser")); err != nil || string(data) != "valuable" {
				t.Fatalf("unacknowledged source changed: %q, %v", data, err)
			}
		})
	}
}

func TestRecoveryStreamPreservesSourceChangedBeforeAck(t *testing.T) {
	source := t.TempDir()
	destination := t.TempDir()
	path := filepath.Join(source, "loser")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	request, err := EncodeRequest(protocol.RecoveryRequest{Root: source, Path: "loser"})
	if err != nil {
		t.Fatal(err)
	}
	agentInput, clientInput := io.Pipe()
	clientOutput, agentOutput := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- recoveryStreamCommand([]string{request}, agentInput, agentOutput)
		_ = agentOutput.Close()
	}()
	summary, err := recovery.ExtractArchive(clientOutput, destination, "backup")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(clientInput).Encode(protocol.RecoveryAck{Commit: true, SHA256: summary.SHA256}); err != nil {
		t.Fatal(err)
	}
	_ = clientInput.Close()
	if err := <-done; err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("changed source returned %v", err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "changed!" {
		t.Fatalf("changed source was removed: %q, %v", data, err)
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

func TestRemotePaneExistsBoundsHungMultiplexer(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\nexec sleep 4\n"
	if err := os.WriteFile(filepath.Join(dir, "tmux"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	started := time.Now()
	if exists, err := remotePaneExists(context.Background(), "remote-tmux", "%9"); exists || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hung multiplexer query returned exists=%t error=%v", exists, err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("hung multiplexer query blocked for %v", elapsed)
	}
}

func TestRemotePaneExistsRejectsOversizedZellijInventory(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\ndd if=/dev/zero bs=1048576 count=5 2>/dev/null\n"
	if err := os.WriteFile(filepath.Join(dir, "zellij"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	exists, err := remotePaneExists(context.Background(), "remote-zellij", "terminal_9")
	if exists || err == nil || !strings.Contains(err.Error(), "4194304-byte limit") {
		t.Fatalf("oversized Zellij inventory returned exists=%t error=%v", exists, err)
	}
}

func TestEnsureRuntimeSignalHelper(t *testing.T) {
	if os.Getenv("PWNBRIDGE_AGENT_ENSURE_HELPER") != "1" {
		return
	}
	spec := protocol.RuntimeSpec{
		Kind: "container", Engine: os.Getenv("PWNBRIDGE_AGENT_ENGINE"), Image: "image:tag",
		Workspace: t.TempDir(), WorkspaceID: "workspace", SessionDir: t.TempDir(),
	}
	if err := ensureRuntime(&spec, "session"); !errors.Is(err, context.Canceled) {
		t.Fatalf("signal-aware runtime setup returned %v", err)
	}
}

func TestEnsureRuntimeCancelsEngineClientOnSignal(t *testing.T) {
	dir := t.TempDir()
	engine := filepath.Join(dir, "docker")
	marker := filepath.Join(dir, "pull-started")
	script := `#!/bin/sh
case "$1 $2" in
  "inspect -f") exit 1 ;;
  "image inspect") exit 1 ;;
  "pull --quiet")
    printf '%s' "$$" > "$PWNBRIDGE_AGENT_PULL_MARKER"
    while :; do :; done ;;
  rm*) exit 0 ;;
esac
exit 1
`
	if err := os.WriteFile(engine, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestEnsureRuntimeSignalHelper$")
	command.Env = append(os.Environ(),
		"PWNBRIDGE_AGENT_ENSURE_HELPER=1",
		"PWNBRIDGE_AGENT_ENGINE="+engine,
		"PWNBRIDGE_AGENT_PULL_MARKER="+marker,
	)
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatalf("engine pull did not start: %s", output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	started := time.Now()
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("signal helper failed: %v: %s", err, output.String())
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("signal-aware runtime cancellation took %v", elapsed)
	}
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("engine client %d survived cancellation: %v", pid, err)
	}
}

func TestRuntimeProgressWriterRequiresCharacterTerminal(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	if progress := terminalProgressWriter(slave); progress != slave {
		t.Fatalf("PTY progress writer = %#v", progress)
	}

	regular, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	if progress := terminalProgressWriter(regular); progress != nil {
		t.Fatalf("regular-file progress writer = %#v", progress)
	}

	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	if progress := terminalProgressWriter(null); progress != nil {
		t.Fatalf("null-device progress writer = %#v", progress)
	}
}

func TestAgentRuntimeHelpersRestoreAfterHostSetup(t *testing.T) {
	spec := protocol.RuntimeSpec{Kind: "host"}
	if err := ensureRuntime(&spec, "session"); err != nil || spec.Kind != "host" {
		t.Fatalf("host ensure spec=%#v error=%v", spec, err)
	}
	if err := stopRuntime(spec); err != nil {
		t.Fatalf("host stop = %v", err)
	}
	_ = runtimeProgressWriter()
}

func TestDFAvailableHonorsContext(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "df"), []byte("#!/bin/sh\nexec sleep 4\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	if available := dfAvailable(ctx, "-Pk", "/"); available != 0 {
		t.Fatalf("cancelled df reported %d available", available)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("cancelled df blocked for %v", elapsed)
	}
}

func BenchmarkRemotePaneQuery(b *testing.B) {
	dir := b.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tmux"), []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		b.Fatal(err)
	}
	b.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	b.Run("plain", func(b *testing.B) {
		for b.Loop() {
			_ = exec.Command("tmux", "display-message", "-p", "-t", "%9", "#{pane_id}").Run()
		}
	})
	b.Run("bounded", func(b *testing.B) {
		for b.Loop() {
			_, _ = remotePaneExists(context.Background(), "remote-tmux", "%9")
		}
	})
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
	originalArg0 := os.Args[0]
	os.Args[0] = filepath.Join(session, "bin", "pwntools-terminal")
	defer func() { os.Args[0] = originalArg0 }()
	if _, err := loadTerminalConfig(); err != nil {
		t.Fatalf("load private terminal state: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTerminalConfig(); err == nil {
		t.Fatal("group-readable terminal state was accepted")
	}
}

func TestTerminalWrapperRejectsMalformedBrokerExit(t *testing.T) {
	id := "0123456789abcdef"
	root, err := os.MkdirTemp("/tmp", "pb-agent-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	session := filepath.Join(root, ".cache", "pwnbridge", "sessions", id)
	if err := os.MkdirAll(filepath.Join(session, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(session, "requests"), 0o700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(session, "broker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	token := strings.Repeat("a", 64)
	runtimeSpec := protocol.RuntimeSpec{Kind: "host", ID: "pwnbridge-" + id, Workspace: "/work", SessionDir: session}
	terminal := protocol.TerminalSpec{SessionID: id, Scope: "host", Provider: "custom:test", Placement: "right", Broker: "unix:" + socket, Token: token}
	if err := writeTerminalConfig(session, terminal, runtimeSpec); err != nil {
		t.Fatal(err)
	}
	originalArg0 := os.Args[0]
	os.Args[0] = filepath.Join(session, "bin", "pwntools-terminal")
	defer func() { os.Args[0] = originalArg0 }()

	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer conn.Close()
		var open protocol.Message
		if decodeErr := protocol.Decode(conn, &open); decodeErr != nil {
			serverDone <- decodeErr
			return
		}
		serverDone <- protocol.Encode(conn, protocol.Message{
			Protocol: version.ProtocolVersion, Type: "exited", SessionID: id, RequestID: open.RequestID, Token: token,
			Payload: []byte(`{"code":"success"}`),
		})
	}()
	if err := terminalWrapper([]string{"gdb"}); err == nil || !strings.Contains(err.Error(), "decode broker exit response") {
		t.Fatalf("malformed broker exit was not rejected: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}
