package transport

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

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
