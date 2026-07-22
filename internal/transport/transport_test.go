package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/protocol"
)

func TestCanceledCommandsPreserveContextError(t *testing.T) {
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh")
	if err := os.WriteFile(ssh, []byte("#!/bin/sh\nexec sleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	client := Client{SSH: ssh, Destination: "fake", AgentPath: "/agent"}
	for name, run := range map[string]func(context.Context) error{
		"client": func(ctx context.Context) error {
			_, err := client.run(ctx, "ignored")
			return err
		},
		"master": func(ctx context.Context) error {
			_, err := (&Master{Client: client}).Run(ctx, "broker-ping", map[string]string{"value": "test"})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(20*time.Millisecond, cancel)
			if err := run(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation was obscured by process error: %v", err)
			}
		})
	}
}

func TestRawBoundedCapsAndDrainsCombinedOutput(t *testing.T) {
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh")
	if err := os.WriteFile(ssh, []byte("#!/bin/sh\nprintf 'abcdefgh'\nprintf 'ijklmnop' >&2\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	client := Client{SSH: ssh, Destination: "fake"}
	output, err := client.RawBounded(context.Background(), "ignored", 10)
	if err == nil || !strings.Contains(err.Error(), "exceeded 10-byte limit") {
		t.Fatalf("bounded output error = %v", err)
	}
	if len(output) != 10 {
		t.Fatalf("bounded output length = %d, want 10", len(output))
	}
	if _, err := client.RawBounded(context.Background(), "ignored", 0); err == nil {
		t.Fatal("non-positive output limit was accepted")
	}
}

func TestSmallProtocolProbesBoundOutputAndInheritedDescriptors(t *testing.T) {
	t.Run("basic output", func(t *testing.T) {
		dir := t.TempDir()
		ssh := filepath.Join(dir, "ssh")
		if err := os.WriteFile(ssh, []byte("#!/bin/sh\nprintf '__PWNBRIDGE_HOME__/home/pwner\\n__PWNBRIDGE_OS__Linux\\n__PWNBRIDGE_ARCH__x86_64\\n'\ndd if=/dev/zero bs=70000 count=1 2>/dev/null\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := (Client{SSH: ssh, Destination: "fake"}).BasicProbe(context.Background()); err == nil || !strings.Contains(err.Error(), "65536-byte limit") {
			t.Fatalf("basic probe flood returned %v", err)
		}
	})

	t.Run("agent output", func(t *testing.T) {
		dir := t.TempDir()
		ssh := filepath.Join(dir, "ssh")
		if err := os.WriteFile(ssh, []byte("#!/bin/sh\nprintf '{\"protocol\":4,\"os\":\"linux\",\"architecture\":\"amd64\"}'\ndd if=/dev/zero bs=1048577 count=1 2>/dev/null\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := (Client{SSH: ssh, Destination: "fake", AgentPath: "/agent"}).ProbeAgent(context.Background()); err == nil || !strings.Contains(err.Error(), "1048576-byte limit") {
			t.Fatalf("agent probe flood returned %v", err)
		}
	})

	t.Run("inherited descriptor", func(t *testing.T) {
		dir := t.TempDir()
		ssh := filepath.Join(dir, "ssh")
		if err := os.WriteFile(ssh, []byte("#!/bin/sh\nsleep 4 &\nprintf '__PWNBRIDGE_HOME__/home/pwner\\n__PWNBRIDGE_OS__Linux\\n__PWNBRIDGE_ARCH__x86_64\\n'\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		_, err := (Client{SSH: ssh, Destination: "fake"}).BasicProbe(context.Background())
		if !errors.Is(err, exec.ErrWaitDelay) {
			t.Fatalf("inherited probe descriptor returned %v", err)
		}
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Fatalf("inherited probe descriptor remained open for %v", elapsed)
		}
	})
}

func TestPrepareAgentVerifiesAndProbesCachedAssetInOneChannel(t *testing.T) {
	dir := t.TempDir()
	asset := filepath.Join(dir, "agent")
	content := []byte("verified agent")
	if err := os.WriteFile(asset, content, 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "calls")
	ssh := filepath.Join(dir, "ssh")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$PWNBRIDGE_TRANSPORT_TEST_LOG"
printf '{"protocol":4,"os":"linux","architecture":"amd64","home":"/home/pwner"}'
`
	if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PWNBRIDGE_TRANSPORT_TEST_LOG", logPath)
	remote, probe, err := (Client{SSH: ssh, Destination: "fake"}).PrepareAgent(context.Background(), asset)
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(content))
	wantRemote := "~/.local/share/pwnbridge/agents/4/" + digest + "/pwnbridge-agent"
	if remote != wantRemote || probe.Protocol != 4 || probe.Architecture != "amd64" {
		t.Fatalf("prepared agent = %q, %#v", remote, probe)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(strings.TrimSpace(string(data)), "\n") + 1; lines != 1 {
		t.Fatalf("cached preparation used %d SSH channels: %s", lines, data)
	}
	if !strings.Contains(string(data), digest) || !strings.Contains(string(data), "sha256sum") {
		t.Fatalf("cached preparation omitted digest verification: %s", data)
	}
}

func TestManagementResponsesAreBoundedAndAcceptMaximumSnapshot(t *testing.T) {
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh")
	response := filepath.Join(dir, "response")
	script := `#!/bin/sh
case "$PWNBRIDGE_TRANSPORT_TEST_MODE" in
  response) cat "$PWNBRIDGE_TRANSPORT_TEST_RESPONSE" ;;
  inherited) sleep 4 & printf '{}' ;;
  *) dd if=/dev/zero bs=1048576 count=3 2>/dev/null ;;
esac
`
	if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PWNBRIDGE_TRANSPORT_TEST_RESPONSE", response)
	client := Client{SSH: ssh, Destination: "fake", AgentPath: "/agent"}

	if output, err := client.Raw(context.Background(), "ignored"); err == nil || !strings.Contains(err.Error(), "1048576-byte limit") || len(output) != maxSSHCommandOutputBytes {
		t.Fatalf("ordinary management flood = %d bytes, %v", len(output), err)
	}
	master := &Master{Client: client, ControlPath: "/control"}
	if output, err := master.Run(context.Background(), "snapshot", protocol.SnapshotRequest{Root: "/tmp", Path: "x"}); err == nil || !strings.Contains(err.Error(), "2097152-byte limit") || len(output) != maxAgentResponseBytes {
		t.Fatalf("agent management flood = %d bytes, %v", len(output), err)
	}
	if err := master.ConfigureBroker(context.Background(), "/local.sock", "/remote.sock", ""); err == nil || !strings.Contains(err.Error(), "65536-byte limit") {
		t.Fatalf("forwarding management flood returned %v", err)
	}

	snapshot := protocol.FileSnapshot{Kind: "regular", Size: protocol.MaxConflictPreviewBytes, Mode: 0o600, Content: bytes.Repeat([]byte("x"), protocol.MaxConflictPreviewBytes)}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) <= maxAgentProbeOutputBytes || len(data) >= maxAgentResponseBytes {
		t.Fatalf("maximum snapshot JSON size = %d", len(data))
	}
	if err := os.WriteFile(response, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PWNBRIDGE_TRANSPORT_TEST_MODE", "response")
	output, err := master.Run(context.Background(), "snapshot", protocol.SnapshotRequest{Root: "/tmp", Path: "x"})
	if err != nil || !bytes.Equal(output, data) {
		t.Fatalf("maximum snapshot response = %d bytes, %v", len(output), err)
	}

	t.Setenv("PWNBRIDGE_TRANSPORT_TEST_MODE", "inherited")
	started := time.Now()
	if _, err := master.Run(context.Background(), "broker-ping", protocol.BrokerPing{}); !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("inherited agent response descriptor returned %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("inherited agent response descriptor remained open for %v", elapsed)
	}
}

func TestAgentUploadBoundsSCPDiagnostics(t *testing.T) {
	dir := t.TempDir()
	asset := filepath.Join(dir, "agent")
	content := []byte("agent")
	if err := os.WriteFile(asset, content, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(content))
	temporary := "/home/pwner/.cache/pwnbridge/upload-" + digest + ".test"
	ssh := filepath.Join(dir, "ssh")
	script := `#!/bin/sh
case "$*" in
  *"__PWNBRIDGE_HOME__"*) printf '__PWNBRIDGE_HOME__/home/pwner\n__PWNBRIDGE_OS__Linux\n__PWNBRIDGE_ARCH__x86_64\n' ;;
  *"test -x"*) exit 1 ;;
  *"mktemp"*) printf '%s' "$PWNBRIDGE_TRANSPORT_TEST_TEMP" ;;
esac
`
	if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	scp := filepath.Join(dir, "scp")
	if err := os.WriteFile(scp, []byte("#!/bin/sh\ndd if=/dev/zero bs=70000 count=1 2>/dev/null\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PWNBRIDGE_TRANSPORT_TEST_TEMP", temporary)
	_, err := (Client{SSH: ssh, SCP: scp, Destination: "fake"}).DeployAgent(context.Background(), asset)
	if err == nil || !strings.Contains(err.Error(), "SCP output exceeded 65536-byte limit") {
		t.Fatalf("SCP diagnostic flood returned %v", err)
	}
}

func TestMasterCloseBoundsControlCommand(t *testing.T) {
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh")
	if err := os.WriteFile(ssh, []byte("#!/bin/sh\nexec sleep 4\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	master := &Master{Client: Client{SSH: ssh, Destination: "fake"}, ControlPath: "/control", closeTimeout: 100 * time.Millisecond}
	started := time.Now()
	if err := master.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("SSH control command blocked close for %v", elapsed)
	}
}

func TestMasterCloseIsConcurrentAndIdempotent(t *testing.T) {
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh")
	logPath := filepath.Join(dir, "close.log")
	if err := os.WriteFile(ssh, []byte("#!/bin/sh\nprintf x >> \"$PWNBRIDGE_TRANSPORT_TEST_LOG\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PWNBRIDGE_TRANSPORT_TEST_LOG", logPath)
	master := &Master{Client: Client{SSH: ssh, Destination: "fake"}, ControlPath: "/control"}
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_ = master.Close()
		}()
	}
	wait.Wait()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "x" {
		t.Fatalf("close command ran %d times", len(data))
	}
}

func TestControlMasterBoundsInheritedOutputPipes(t *testing.T) {
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh")
	pidPath := filepath.Join(dir, "child.pid")
	script := `#!/bin/sh
for arg in "$@"; do
  if test "$arg" = "-M"; then
    sleep 30 &
    printf '%s' "$!" > "$PWNBRIDGE_TRANSPORT_TEST_PID"
    exit 0
  fi
done
exit 1
`
	if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PWNBRIDGE_TRANSPORT_TEST_PID", pidPath)
	t.Cleanup(func() {
		data, err := os.ReadFile(pidPath)
		if err != nil {
			return
		}
		pid, err := strconv.Atoi(string(data))
		if err == nil {
			if process, findErr := os.FindProcess(pid); findErr == nil {
				_ = process.Kill()
			}
		}
	})
	started := time.Now()
	_, err := (Client{SSH: ssh, Destination: "fake"}).StartControlMaster(context.Background(), dir)
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("control master with inherited output pipe returned %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("control master output pipe remained open for %v", elapsed)
	}
}

func TestMasterCloseReapsProcessAfterForcedKill(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command("sh", "-c", `trap '' INT; : > "$PWNBRIDGE_TRANSPORT_TEST_READY"; exec sleep 30`)
	cmd.Env = append(os.Environ(), "PWNBRIDGE_TRANSPORT_TEST_READY="+ready)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatal("interrupt-ignoring master did not become ready")
		}
		time.Sleep(time.Millisecond)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	master := &Master{process: cmd, done: done}
	started := time.Now()
	if err := master.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("interrupt-ignoring master blocked close for %v", elapsed)
	}
	if cmd.ProcessState == nil {
		t.Fatalf("master process was not reaped: %#v", cmd.ProcessState)
	}
	status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("master process status = %#v, want SIGKILL", cmd.ProcessState)
	}
}

func TestFindAgentAssetResolvesHomebrewExecutableSymlink(t *testing.T) {
	root := t.TempDir()
	cellar := filepath.Join(root, "Cellar", "pwnbridge", "0.1.1")
	executable := filepath.Join(cellar, "bin", "pwnbridge")
	agent := filepath.Join(cellar, "libexec", "pwnbridge", "pwnbridge-agent-linux-amd64")
	if err := os.MkdirAll(filepath.Dir(executable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(agent), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("client"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(agent, []byte("agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	linkedExecutable := filepath.Join(root, "bin", "pwnbridge")
	if err := os.MkdirAll(filepath.Dir(linkedExecutable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(executable, linkedExecutable); err != nil {
		t.Fatal(err)
	}
	got, ok := findAgentAssetFromExecutable(linkedExecutable)
	want, err := filepath.EvalSymlinks(agent)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got != want {
		t.Fatalf("got asset %q, ok=%t; want %q", got, ok, want)
	}
}

func TestAgentAssetMustBeBoundedRegularFile(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "agent-fifo")
	if err := syscall.Mkfifo(fifo, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := FindAgentAsset(fifo); err == nil {
		t.Fatal("FIFO agent asset was accepted")
	}
	oversized := filepath.Join(dir, "agent-oversized")
	file, err := os.OpenFile(oversized, os.O_CREATE|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxAgentAssetBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := (Client{}).DeployAgent(context.Background(), oversized); err == nil {
		t.Fatal("oversized agent asset was accepted")
	}
}

func TestRemoteAgentCommandQuotesRequest(t *testing.T) {
	got := remoteAgentCommand("~/.local/share/pwnbridge/agent", "exec", "abc_DEF-123")
	want := `exec "$HOME"/'.local/share/pwnbridge/agent' 'exec' 'abc_DEF-123'`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestManagedCommandQuietsNormalSharedConnectionClose(t *testing.T) {
	master := &Master{
		Client:      Client{SSH: "ssh", Destination: "host", AgentPath: "/agent"},
		ControlPath: "/control",
	}
	command := master.Command(context.Background(), true, "exec", "request")
	if len(command.Args) < 2 || command.Args[1] != "-q" {
		t.Fatalf("managed SSH command is not quiet: %#v", command.Args)
	}
}

func TestMoshCommandUsesPredictionControlMasterAndPortRange(t *testing.T) {
	master := &Master{Client: Client{SSH: "ssh", Mosh: "mosh", Destination: "user@host", AgentPath: "/agent"}, ControlPath: "/private/control"}
	command := master.MoshCommand(context.Background(), "shell", "request", "61000:61010")
	want := []string{"mosh", "--predict=always", "--ssh='ssh' -S '/private/control'", "--port=61000:61010", "--", "user@host", "/agent", "shell", "request"}
	if strings.Join(command.Args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("Mosh argv = %#v, want %#v", command.Args, want)
	}
}

func TestSafeMoshEnvironmentKeepsOnlyUTF8Locale(t *testing.T) {
	t.Setenv("LANG", "en_SG.UTF-8")
	t.Setenv("LC_ALL", "C")
	t.Setenv("LC_CTYPE", "C")
	values := map[string]string{}
	for _, entry := range SafeMoshEnvironment() {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			values[key] = value
		}
	}
	if values["LANG"] != "en_SG.UTF-8" || values["LC_CTYPE"] != "en_SG.UTF-8" {
		t.Fatalf("Mosh locale = %#v", values)
	}
	if _, exists := values["LC_ALL"]; exists {
		t.Fatalf("non-UTF-8 LC_ALL leaked into Mosh environment: %#v", values)
	}
}

func TestShellQuote(t *testing.T) {
	if got := shellQuote("a'b"); got != `'a'\''b'` {
		t.Fatalf("got %q", got)
	}
}

func TestArchitecture(t *testing.T) {
	if normalizeArchitecture("x86_64\n") != "amd64" {
		t.Fatal("x86_64 normalization failed")
	}
}

func TestBasicProbeIgnoresLoginBanner(t *testing.T) {
	probe, err := parseBasicProbe([]byte("authorized use only\n__PWNBRIDGE_HOME__/home/pwner\n__PWNBRIDGE_OS__Linux\n__PWNBRIDGE_ARCH__x86_64\n"))
	if err != nil {
		t.Fatal(err)
	}
	if probe.Home != "/home/pwner" || probe.OS != "linux" || probe.Architecture != "amd64" {
		t.Fatalf("unexpected probe: %#v", probe)
	}
}

func TestSafeSSHEnvironmentRemovesLocalMuxAndBrokerState(t *testing.T) {
	t.Setenv("TERM", "dumb")
	t.Setenv("TMUX", "/tmp/tmux")
	t.Setenv("TMUX_PANE", "%1")
	t.Setenv("ZELLIJ", "0")
	t.Setenv("ZELLIJ_SESSION_NAME", "local")
	t.Setenv("PWNBRIDGE_BROKER_TOKEN", "secret")
	t.Setenv("PWNBRIDGE_E2E_SSH_CONFIG", "/tmp/test-config")
	t.Setenv("LANG", "en_SG.UTF-8")
	t.Setenv("LC_CTYPE", "en_SG.UTF-8")
	values := map[string]string{}
	for _, entry := range SafeSSHEnvironment() {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			values[key] = value
		}
	}
	for _, forbidden := range []string{"TMUX", "TMUX_PANE", "ZELLIJ", "ZELLIJ_SESSION_NAME", "PWNBRIDGE_BROKER_TOKEN", "LANG", "LC_CTYPE"} {
		if _, ok := values[forbidden]; ok {
			t.Fatalf("%s leaked into SSH environment", forbidden)
		}
	}
	if values["TERM"] != "xterm-256color" || values["PWNBRIDGE_E2E_SSH_CONFIG"] != "/tmp/test-config" {
		t.Fatalf("safe SSH environment lost required values: %#v", values)
	}
}

func TestRemoteForwardingProbeUsesLoopbackAndFailsClosed(t *testing.T) {
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh")
	logPath := filepath.Join(dir, "calls")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$PWNBRIDGE_TRANSPORT_TEST_LOG"
case " $* " in
  *" -O check "*) exit 0 ;;
  *" -O exit "*) exit 0 ;;
  *" -O forward -R 127.0.0.1:0:127.0.0.1:9 "*)
	 case "${PWNBRIDGE_TRANSPORT_TEST_STATUS:-0}" in
	   0) printf 43123; exit 0 ;;
	   2) dd if=/dev/zero bs=70000 count=1 2>/dev/null; exit 0 ;;
	   *) exit 1 ;;
	 esac ;;
  *" -M -N "*) trap 'exit 0' INT TERM; while :; do sleep 1; done ;;
esac
exit 42
`
	if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PWNBRIDGE_TRANSPORT_TEST_LOG", logPath)
	client := Client{SSH: ssh, Destination: "ssh-alias"}
	if err := client.CheckRemoteForwarding(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, required := range []string{"ClearAllForwardings=yes", "ExitOnForwardFailure=yes", "ForwardAgent=no", "ForwardX11=no", "-O forward -R 127.0.0.1:0:127.0.0.1:9 ssh-alias"} {
		if !strings.Contains(got, required) {
			t.Fatalf("forwarding probe is missing %q: %s", required, got)
		}
	}
	t.Setenv("PWNBRIDGE_TRANSPORT_TEST_STATUS", "1")
	if err := client.CheckRemoteForwarding(context.Background()); err == nil {
		t.Fatal("disabled reverse forwarding was accepted")
	}
	t.Setenv("PWNBRIDGE_TRANSPORT_TEST_STATUS", "2")
	if err := client.CheckRemoteForwarding(context.Background()); err == nil || !strings.Contains(err.Error(), "65536-byte limit") {
		t.Fatalf("forwarding output flood returned %v", err)
	}
}

func TestMasterFallsBackToLoopbackTCP(t *testing.T) {
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh")
	script := `#!/bin/sh
case " $* " in
  *" -O check "*) exit 0 ;;
  *" -O forward "*".sock:"*) exit 1 ;;
  *" -O forward "*) echo 45678; exit 0 ;;
  *" -O exit "*) exit 0 ;;
  *" -M -N "*) trap 'exit 0' INT TERM; while :; do sleep 1; done ;;
esac
exit 0
`
	if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	client := Client{SSH: ssh, Destination: "fake"}
	master, err := client.StartMaster(context.Background(), filepath.Join(dir, "runtime"), filepath.Join(dir, "broker.sock"), "/tmp/remote.sock", "127.0.0.1:12345")
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	if master.BrokerAddress != "tcp:127.0.0.1:45678" {
		t.Fatalf("got %q", master.BrokerAddress)
	}
}

func TestControlMasterWorksWithoutReverseForwarding(t *testing.T) {
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh")
	script := `#!/bin/sh
case " $* " in
  *" -O check "*) exit 0 ;;
  *" -O exit "*) exit 0 ;;
  *" -O forward "*) exit 1 ;;
  *" -M -N "*) trap 'exit 0' INT TERM; while :; do sleep 1; done ;;
esac
exit 0
`
	if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	client := Client{SSH: ssh, Destination: "fake"}
	master, err := client.StartControlMaster(context.Background(), filepath.Join(dir, "runtime"))
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	if master.BrokerAddress != "" || master.ControlPath == "" {
		t.Fatalf("unexpected control-only master: %#v", master)
	}
}

func TestControlMasterReportsSSHStartupFailure(t *testing.T) {
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh")
	script := `#!/bin/sh
case " $* " in
  *" -q "*) exit 255 ;;
esac
printf 'Permission denied (publickey).\n' >&2
exit 255
`
	if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := (Client{SSH: ssh, Destination: "fake"}).StartControlMaster(context.Background(), filepath.Join(dir, "runtime"))
	if err == nil || !strings.Contains(err.Error(), "Permission denied (publickey).") {
		t.Fatalf("startup error did not retain SSH diagnostic: %v", err)
	}
}

func TestSharedControlMasterReportsSSHStartupFailure(t *testing.T) {
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh")
	script := `#!/bin/sh
case " $* " in
  *" -O check "*) exit 1 ;;
  *" -q "*) exit 255 ;;
esac
printf 'Permission denied (publickey).\n' >&2
exit 255
`
	if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := (Client{SSH: ssh, Destination: "fake"}).StartSharedControlMaster(context.Background(), filepath.Join(dir, "control"))
	if err == nil || !strings.Contains(err.Error(), "Permission denied (publickey).") {
		t.Fatalf("startup error did not retain SSH diagnostic: %v", err)
	}
}

func TestSharedControlMasterStartsOnceAndStopsExplicitly(t *testing.T) {
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh")
	state := filepath.Join(dir, "running")
	control := filepath.Join(dir, "control", "c")
	logPath := filepath.Join(dir, "calls")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$PWNBRIDGE_TRANSPORT_TEST_LOG"
case " $* " in
  *" -O check "*) test -f "$PWNBRIDGE_TRANSPORT_TEST_STATE" ;;
  *" -O exit "*) rm -f "$PWNBRIDGE_TRANSPORT_TEST_STATE" "$PWNBRIDGE_TRANSPORT_TEST_CONTROL" ;;
  *" -M -N -f "*) : > "$PWNBRIDGE_TRANSPORT_TEST_STATE"; : > "$PWNBRIDGE_TRANSPORT_TEST_CONTROL" ;;
  *) exit 1 ;;
esac
`
	if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PWNBRIDGE_TRANSPORT_TEST_LOG", logPath)
	t.Setenv("PWNBRIDGE_TRANSPORT_TEST_STATE", state)
	t.Setenv("PWNBRIDGE_TRANSPORT_TEST_CONTROL", control)
	client := Client{SSH: ssh, Destination: "fake"}
	results := make(chan error, 8)
	for range 8 {
		go func() {
			master, err := client.StartSharedControlMaster(context.Background(), filepath.Dir(control))
			if err == nil && (!master.Shared || master.ControlPath != control) {
				err = fmt.Errorf("unexpected shared master: %#v", master)
			}
			if master != nil {
				_ = master.Close()
			}
			results <- err
		}()
	}
	for range 8 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if starts := strings.Count(string(data), "-M -N -f "); starts != 1 {
		t.Fatalf("shared master starts = %d: %s", starts, data)
	}
	if !strings.Contains(string(data), "ControlPersist=2m") || !strings.Contains(string(data), "ForwardAgent=no") {
		t.Fatalf("shared master safety options missing: %s", data)
	}
	if err := client.StopSharedControlMaster(context.Background(), filepath.Dir(control)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("shared master was not stopped: %v", err)
	}
}

func TestSharedMasterCloseCancelsOnlyItsForward(t *testing.T) {
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh")
	logPath := filepath.Join(dir, "calls")
	if err := os.WriteFile(ssh, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$PWNBRIDGE_TRANSPORT_TEST_LOG\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PWNBRIDGE_TRANSPORT_TEST_LOG", logPath)
	master := &Master{
		Client:      Client{SSH: ssh, Destination: "fake"},
		ControlPath: "/private/control", Shared: true,
		ForwardSpec: "/remote/broker.sock:/local/broker.sock",
	}
	if err := master.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !strings.Contains(got, "-O cancel -R /remote/broker.sock:/local/broker.sock fake") || strings.Contains(got, "-O exit") {
		t.Fatalf("shared close affected the wrong master state: %s", got)
	}
}

func TestMasterRelaysTCPFallbackToPrivateUnixSocket(t *testing.T) {
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh")
	script := `#!/bin/sh
case " $* " in
  *" -O check "*) exit 0 ;;
  *" -O forward "*".sock:"*) exit 1 ;;
  *" -O forward "*) echo 45678; exit 0 ;;
  *" socat UNIX-LISTEN:"*) printf relay; exit 0 ;;
  *" -O exit "*) exit 0 ;;
  *" -M -N "*) trap 'exit 0' INT TERM; while :; do sleep 1; done ;;
esac
exit 0
`
	if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	remoteSocket := "/tmp/private/session/broker.sock"
	client := Client{SSH: ssh, Destination: "fake"}
	master, err := client.StartMaster(context.Background(), filepath.Join(dir, "runtime"), filepath.Join(dir, "broker.sock"), remoteSocket, "127.0.0.1:12345")
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	if master.BrokerAddress != "unix:"+remoteSocket || master.RelayPIDFile == "" {
		t.Fatalf("fallback relay was not selected: %#v", master)
	}
}
