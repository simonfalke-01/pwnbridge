package broker

import (
	"bufio"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pwnbridge/pwnbridge/internal/protocol"
	"github.com/pwnbridge/pwnbridge/internal/terminal/provider"
	"github.com/pwnbridge/pwnbridge/internal/version"
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

	conn, err := net.Dial("unix", record.LocalSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := protocol.Encode(conn, protocol.Message{Protocol: version.ProtocolVersion, Type: "ping", SessionID: record.ID, Token: "wrong"}); err != nil {
		t.Fatal(err)
	}
	var response protocol.Message
	if err := protocol.Decode(conn, &response); err != nil {
		t.Fatal(err)
	}
	if response.Type != "error" {
		t.Fatalf("got %#v", response)
	}
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

func TestRemoteAgentCommandDoesNotExposeShellExpansion(t *testing.T) {
	got := remoteAgentCommand("/tmp/a '$HOME'", "pane", "opaque")
	if !strings.Contains(got, `'/tmp/a '\''$HOME'\'''`) {
		t.Fatalf("agent path is not single-quoted safely: %s", got)
	}
}
