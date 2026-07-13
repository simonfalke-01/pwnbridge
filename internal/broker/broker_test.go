package broker

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/protocol"
	"github.com/simonfalke-01/pwnbridge/internal/terminal/provider"
	"github.com/simonfalke-01/pwnbridge/internal/version"
)

func TestBrokerAuthenticationAndPing(t *testing.T) {
	record := SessionRecord{Schema: 1, OwnerPID: os.Getpid(), ID: "0123456789abcdef", Token: "0123456789abcdef0123456789abcdef", LocalSocket: filepath.Join(t.TempDir(), "b.sock")}
	b := New(record, provider.NewRegistry(t.TempDir()))
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := Ping(record); err != nil {
		t.Fatal(err)
	}

	invalid := []protocol.Message{
		{Protocol: version.ProtocolVersion, Type: "ping", SessionID: record.ID, Token: "wrong"},
		{Protocol: version.ProtocolVersion + 1, Type: "ping", SessionID: record.ID, Token: record.Token},
		{Protocol: version.ProtocolVersion, Type: "ping", SessionID: "wrong-session", Token: record.Token},
	}
	for _, message := range invalid {
		conn, err := net.Dial("unix", record.LocalSocket)
		if err != nil {
			t.Fatal(err)
		}
		if err := protocol.Encode(conn, message); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		var response protocol.Message
		if err := protocol.Decode(conn, &response); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		conn.Close()
		if response.Type != "error" {
			t.Fatalf("invalid message %#v got %#v", message, response)
		}
		if response.Token != message.Token {
			t.Fatalf("error response did not echo supplied credential: %#v", response)
		}
	}
}

func TestBrokerRunsAuthenticatedShellBarrier(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "pb-barrier-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	record := SessionRecord{Schema: 1, OwnerPID: os.Getpid(), ID: "0123456789abcdef", Token: "0123456789abcdef0123456789abcdef", LocalSocket: filepath.Join(dir, "b.sock")}
	b := New(record, provider.NewRegistry(t.TempDir()))
	calls := 0
	b.BeforeOpen = func(context.Context) error { calls++; return nil }
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	conn, err := net.Dial("unix", record.LocalSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	request := protocol.Message{Protocol: version.ProtocolVersion, Type: "barrier", SessionID: record.ID, Token: record.Token}
	if err := protocol.Encode(conn, request); err != nil {
		t.Fatal(err)
	}
	var response protocol.Message
	if err := protocol.Decode(conn, &response); err != nil {
		t.Fatal(err)
	}
	if response.Type != "barrier-ok" || calls != 1 {
		t.Fatalf("barrier response=%#v calls=%d", response, calls)
	}
}

func TestPingRejectsSpoofedResponseIdentity(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "pb-broker-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "broker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	record := SessionRecord{ID: "0123456789abcdef", Token: "0123456789abcdef0123456789abcdef", LocalSocket: socket}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		var request protocol.Message
		if protocol.Decode(conn, &request) == nil {
			_ = protocol.Encode(conn, protocol.Message{Protocol: version.ProtocolVersion, Type: "pong", SessionID: record.ID, Token: "wrong"})
		}
	}()
	if err := Ping(record); err == nil {
		t.Fatal("ping accepted a response with the wrong token")
	}
	<-done
}

func TestSessionRecordRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	want := SessionRecord{OwnerPID: os.Getpid(), ID: "0123456789abcdef", Token: "0123456789abcdef0123456789abcdef", LocalSocket: "/tmp/a", RemoteSessionDir: "/remote/session", Runtime: protocol.RuntimeSpec{Kind: "host", Workspace: "/remote/work", SessionDir: "/remote/session"}}
	if err := SaveSession(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSession(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.Token != want.Token {
		t.Fatalf("got %#v", got)
	}
}

func TestBrokerOpenRateLimit(t *testing.T) {
	record := SessionRecord{OwnerPID: os.Getpid(), ID: "0123456789abcdef", Token: "0123456789abcdef0123456789abcdef"}
	b := New(record, provider.NewRegistry(t.TempDir()))
	for range maxOpenRequestsPerMinute {
		b.openTimes = append(b.openTimes, time.Now())
	}
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		b.handleWrapper(&peer{conn: server}, bufio.NewReader(server), protocol.Message{
			Protocol: version.ProtocolVersion, Type: "open", SessionID: record.ID,
			RequestID: "abcdef0123456789", Token: record.Token,
		})
		close(done)
	}()
	var response protocol.Message
	if err := protocol.Decode(client, &response); err != nil {
		t.Fatal(err)
	}
	if response.Type != "error" {
		t.Fatalf("expected rate-limit error, got %#v", response)
	}
	<-done
}

func TestBrokerPaneCapAndDuplicateRequest(t *testing.T) {
	record := SessionRecord{OwnerPID: os.Getpid(), ID: "0123456789abcdef", Token: "0123456789abcdef0123456789abcdef"}
	for _, test := range []struct {
		name  string
		setup func(*Broker)
	}{
		{"pane cap", func(b *Broker) {
			for i := range MaxPanes {
				b.requests[fmt.Sprintf("request%08d", i)] = &request{}
			}
		}},
		{"duplicate", func(b *Broker) { b.requests["abcdef0123456789"] = &request{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := New(record, provider.NewRegistry(t.TempDir()))
			test.setup(b)
			server, client := net.Pipe()
			defer client.Close()
			done := make(chan struct{})
			go func() {
				b.handleWrapper(&peer{conn: server}, bufio.NewReader(server), protocol.Message{
					Protocol: version.ProtocolVersion, Type: "open", SessionID: record.ID,
					RequestID: "abcdef0123456789", Token: record.Token,
				})
				close(done)
			}()
			var response protocol.Message
			if err := protocol.Decode(client, &response); err != nil {
				t.Fatal(err)
			}
			if response.Type != "error" {
				t.Fatalf("expected broker refusal, got %#v", response)
			}
			<-done
		})
	}
}

func TestPaneCancellationStopsSSH(t *testing.T) {
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh")
	script := "#!/bin/sh\ntrap 'exit 0' INT TERM\nwhile :; do sleep 1; done\n"
	if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	socket := filepath.Join(dir, "broker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	record := SessionRecord{
		OwnerPID: os.Getpid(), ID: "0123456789abcdef", Token: "0123456789abcdef0123456789abcdef",
		LocalSocket: socket, Destination: "host", AgentPath: "/agent", ControlPath: "/control",
	}
	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer conn.Close()
		var started protocol.Message
		if decodeErr := protocol.Decode(conn, &started); decodeErr != nil {
			serverDone <- decodeErr
			return
		}
		serverDone <- protocol.Encode(conn, protocol.Message{
			Protocol: version.ProtocolVersion, Type: "cancel", SessionID: record.ID,
			RequestID: started.RequestID, Token: record.Token,
		})
	}()
	started := time.Now()
	err = RunPane(t.Context(), record, "abcdef0123456789")
	if err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if time.Since(started) > 3*time.Second {
		t.Fatal("cancelled pane did not stop promptly")
	}
	if serverErr := <-serverDone; serverErr != nil && !errors.Is(serverErr, net.ErrClosed) {
		t.Fatal(serverErr)
	}
}

func TestSafeTitle(t *testing.T) {
	if got := safeTitle("a\n\x1bb"); got != "ab" {
		t.Fatalf("unsafe title survived: %q", got)
	}
	if len(safeTitle(strings.Repeat("x", 200))) != 80 {
		t.Fatal("title cap was not applied")
	}
}

func TestBrokerLayoutUsesSelectedAutoProvider(t *testing.T) {
	record := SessionRecord{
		Placement: "right", Size: "50%", ZellijDirection: "down", ZellijFloating: false,
		TmuxDirection: "vertical", TmuxSize: "35%",
	}
	if placement, size := brokerLayout(record, "zellij"); placement != "down" || size != "50%" {
		t.Fatalf("Zellij layout = %q %q", placement, size)
	}
	if placement, size := brokerLayout(record, "tmux"); placement != "down" || size != "35%" {
		t.Fatalf("tmux layout = %q %q", placement, size)
	}
	record.ZellijFloating = true
	if placement, _ := brokerLayout(record, "zellij"); placement != "floating" {
		t.Fatalf("floating Zellij layout = %q", placement)
	}
}

func TestRemoteAgentCommandDoesNotExposeShellExpansion(t *testing.T) {
	got := remoteAgentCommand("/tmp/a '$HOME'", "pane", "opaque")
	if !strings.Contains(got, `'/tmp/a '\''$HOME'\'''`) {
		t.Fatalf("agent path is not single-quoted safely: %s", got)
	}
}

func TestBrokerCloseDuringProviderOpenClosesLatePane(t *testing.T) {
	dir := t.TempDir()
	started := filepath.Join(dir, "started")
	release := filepath.Join(dir, "release")
	closed := filepath.Join(dir, "closed")
	script := `#!/bin/sh
request=$(cat)
case "$request" in
  *'"operation":"open"'*)
    : > "$PWNBRIDGE_BROKER_TEST_STARTED"
    while test ! -e "$PWNBRIDGE_BROKER_TEST_RELEASE"; do sleep 0.01; done
    printf '{"provider":"custom:test","id":"late-pane"}\n'
    ;;
  *'"operation":"close"'*)
    : > "$PWNBRIDGE_BROKER_TEST_CLOSED"
    printf '{}\n'
    ;;
  *) printf '{}\n' ;;
esac
`
	tool := filepath.Join(dir, "pwnbridge-terminal-test")
	if err := os.WriteFile(tool, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PWNBRIDGE_BROKER_TEST_STARTED", started)
	t.Setenv("PWNBRIDGE_BROKER_TEST_RELEASE", release)
	t.Setenv("PWNBRIDGE_BROKER_TEST_CLOSED", closed)
	record := SessionRecord{
		OwnerPID: os.Getpid(), ID: "0123456789abcdef", Token: "0123456789abcdef0123456789abcdef",
		Provider: "custom:test", Placement: "right", Size: "50%", LocalWorkspace: dir, Executable: "/trusted/pwnbridge",
	}
	b := New(record, provider.NewRegistry(dir))
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		b.handleWrapper(&peer{conn: server}, bufio.NewReader(server), protocol.Message{
			Protocol: version.ProtocolVersion, Type: "open", SessionID: record.ID,
			RequestID: "abcdef0123456789", Token: record.Token,
			Payload: protocol.Payload(protocol.OpenPayload{Title: "debug"}),
		})
		close(done)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("provider open did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("late provider open did not unwind")
	}
	if _, err := os.Stat(closed); err != nil {
		t.Fatalf("late-created pane was not closed: %v", err)
	}
}
