package transport

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestRemoteAgentCommandQuotesRequest(t *testing.T) {
	got := remoteAgentCommand("~/.local/share/pwnbridge/agent", "exec", "abc_DEF-123")
	want := `exec "$HOME"/'.local/share/pwnbridge/agent' 'exec' 'abc_DEF-123'`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
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
	values := map[string]string{}
	for _, entry := range SafeSSHEnvironment() {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			values[key] = value
		}
	}
	for _, forbidden := range []string{"TMUX", "TMUX_PANE", "ZELLIJ", "ZELLIJ_SESSION_NAME", "PWNBRIDGE_BROKER_TOKEN"} {
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
    test "${PWNBRIDGE_TRANSPORT_TEST_STATUS:-0}" = 0 || exit 1
    printf 43123
    exit 0 ;;
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
