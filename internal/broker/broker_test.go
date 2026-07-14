package broker

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
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

func TestBrokerCapsUnauthenticatedConnectionsAndReleasesSlots(t *testing.T) {
	record := SessionRecord{Schema: 1, OwnerPID: os.Getpid(), ID: "0123456789abcdef", Token: "0123456789abcdef0123456789abcdef", LocalSocket: filepath.Join(t.TempDir(), "b.sock")}
	b := New(record, provider.NewRegistry(t.TempDir()))
	b.handshakeTimeout = time.Second
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	connections := make([]net.Conn, 0, maxBrokerConnections)
	defer func() {
		for _, conn := range connections {
			_ = conn.Close()
		}
	}()
	for range maxBrokerConnections {
		conn, err := net.Dial("unix", record.LocalSocket)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
	}
	waitForConnectionCount(t, b, maxBrokerConnections)

	overflow, err := net.Dial("unix", record.LocalSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer overflow.Close()
	if err := overflow.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if _, err := overflow.Read(one[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("overflow connection was not rejected: %v", err)
	}

	if err := connections[0].Close(); err != nil {
		t.Fatal(err)
	}
	connections = connections[1:]
	waitForConnectionCount(t, b, maxBrokerConnections-1)
	if err := Ping(record); err != nil {
		t.Fatalf("released connection slot was not reusable: %v", err)
	}
}

func TestBrokerHandshakeTimeoutAndAuthenticatedLongevity(t *testing.T) {
	record := SessionRecord{Schema: 1, OwnerPID: os.Getpid(), ID: "0123456789abcdef", Token: "0123456789abcdef0123456789abcdef", LocalSocket: filepath.Join(t.TempDir(), "b.sock")}
	b := New(record, provider.NewRegistry(t.TempDir()))
	b.handshakeTimeout = 40 * time.Millisecond
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	idle, err := net.Dial("unix", record.LocalSocket)
	if err != nil {
		t.Fatal(err)
	}
	if err := idle.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if _, err := idle.Read(one[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("idle handshake was not closed after its deadline: %v", err)
	}
	_ = idle.Close()
	waitForConnectionCount(t, b, 0)

	requestID := "abcdef0123456789"
	b.mu.Lock()
	b.requests[requestID] = &request{id: requestID}
	b.mu.Unlock()
	pane, err := net.Dial("unix", record.LocalSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer pane.Close()
	started := protocol.Message{Protocol: version.ProtocolVersion, Type: "pane-started", SessionID: record.ID, RequestID: requestID, Token: record.Token}
	if err := protocol.Encode(pane, started); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * b.handshakeTimeout)
	b.mu.Lock()
	_, exists := b.requests[requestID]
	b.mu.Unlock()
	if !exists {
		t.Fatal("authenticated pane was closed by the handshake deadline")
	}
	exited := protocol.Message{Protocol: version.ProtocolVersion, Type: "exited", SessionID: record.ID, RequestID: requestID, Token: record.Token}
	if err := protocol.Encode(pane, exited); err != nil {
		t.Fatalf("authenticated pane inherited the handshake deadline: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		b.mu.Lock()
		_, exists := b.requests[requestID]
		b.mu.Unlock()
		if !exists {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("authenticated pane message was not processed after handshake timeout")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestBrokerCloseClosesAcceptedConnections(t *testing.T) {
	record := SessionRecord{Schema: 1, OwnerPID: os.Getpid(), ID: "0123456789abcdef", Token: "0123456789abcdef0123456789abcdef", LocalSocket: filepath.Join(t.TempDir(), "b.sock")}
	b := New(record, provider.NewRegistry(t.TempDir()))
	b.handshakeTimeout = time.Minute
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("unix", record.LocalSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitForConnectionCount(t, b, 1)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if got := len(b.connectionSlots); got != 0 {
		t.Fatalf("broker close left %d connection handler(s) running", got)
	}
	if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("accepted connection remained open after broker close: %v", err)
	}
}

func TestBrokerCloseRacesWithAccept(t *testing.T) {
	for iteration := range 25 {
		record := SessionRecord{Schema: 1, OwnerPID: os.Getpid(), ID: "0123456789abcdef", Token: "0123456789abcdef0123456789abcdef", LocalSocket: filepath.Join(t.TempDir(), "b.sock")}
		b := New(record, provider.NewRegistry(t.TempDir()))
		b.handshakeTimeout = time.Minute
		if err := b.Start(); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var callers sync.WaitGroup
		for range 8 {
			callers.Add(1)
			go func() {
				defer callers.Done()
				<-start
				conn, err := net.DialTimeout("unix", record.LocalSocket, 100*time.Millisecond)
				if err == nil {
					_ = conn.Close()
				}
			}()
		}
		close(start)
		if err := b.Close(); err != nil {
			t.Fatal(err)
		}
		callers.Wait()
		if got := len(b.connectionSlots); got != 0 {
			t.Fatalf("iteration %d retained %d connection slot(s)", iteration, got)
		}
		b.mu.Lock()
		active := len(b.connections)
		b.mu.Unlock()
		if active != 0 {
			t.Fatalf("iteration %d retained %d active connection(s)", iteration, active)
		}
	}
}

func waitForConnectionCount(t *testing.T, b *Broker, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for len(b.connectionSlots) != want {
		if time.Now().After(deadline) {
			t.Fatalf("active broker connections = %d, want %d", len(b.connectionSlots), want)
		}
		time.Sleep(time.Millisecond)
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
	path := filepath.Join(t.TempDir(), "0123456789abcdef.json")
	want := testSessionRecord(path)
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

func TestSessionRecordRejectsUntrustedFiles(t *testing.T) {
	t.Run("permissive mode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "0123456789abcdef.json")
		if err := SaveSession(path, testSessionRecord(path)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSession(path); err == nil {
			t.Fatal("group-readable session record was accepted")
		}
	})

	t.Run("symbolic link", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "0123456789abcdef.json")
		target := filepath.Join(dir, "target.json")
		if err := SaveSession(target, testSessionRecord(path)); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSession(path); err == nil {
			t.Fatal("symbolic-link session record was accepted")
		}
	})

	t.Run("named pipe", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "0123456789abcdef.json")
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		if _, err := LoadSession(path); err == nil {
			t.Fatal("named-pipe session record was accepted")
		}
		if time.Since(started) > time.Second {
			t.Fatal("named-pipe session record blocked during validation")
		}
	})

	t.Run("wrong filename", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "session.json")
		if err := SaveSession(path, testSessionRecord(path)); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSession(path); err == nil {
			t.Fatal("session record filename did not match its identity")
		}
	})

	t.Run("unknown field", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "0123456789abcdef.json")
		if err := SaveSession(path, testSessionRecord(path)); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data = []byte(strings.TrimSuffix(strings.TrimSpace(string(data)), "}") + ",\"future\":true}\n")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSession(path); err == nil {
			t.Fatal("unknown session record field was accepted")
		}
	})

	t.Run("oversized", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "0123456789abcdef.json")
		if err := SaveSession(path, testSessionRecord(path)); err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := file.WriteString(strings.Repeat(" ", protocol.MaxFrame))
		closeErr := file.Close()
		if writeErr != nil {
			t.Fatal(writeErr)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
		if _, err := LoadSession(path); err == nil {
			t.Fatal("oversized session record was accepted")
		}
	})
}

func testSessionRecord(path string) SessionRecord {
	return SessionRecord{
		OwnerPID: os.Getpid(), ID: "0123456789abcdef", Token: "0123456789abcdef0123456789abcdef",
		LocalSocket: "/tmp/a", RemoteSessionDir: "/remote/session", RecordPath: path, LeasePath: path + ".lease",
		Runtime: protocol.RuntimeSpec{Kind: "host", Workspace: "/remote/work", SessionDir: "/remote/session"},
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

func TestBrokerMalformedExitPayloadIsFailure(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload []byte
	}{
		{name: "missing"},
		{name: "wrong code type", payload: []byte(`{"code":"success"}`)},
		{name: "unknown field", payload: []byte(`{"code":0,"unknown":true}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := SessionRecord{ID: "0123456789abcdef", Token: "0123456789abcdef0123456789abcdef"}
			b := New(record, provider.NewRegistry(t.TempDir()))
			server, client := net.Pipe()
			defer client.Close()
			requestID := "abcdef0123456789"
			b.requests[requestID] = &request{id: requestID, wrapper: &peer{conn: server}}
			done := make(chan struct{})
			go func() {
				b.finish(requestID, protocol.Message{Payload: test.payload})
				close(done)
			}()
			var response protocol.Message
			if err := protocol.Decode(client, &response); err != nil {
				t.Fatal(err)
			}
			payload, err := protocol.ParsePayload[protocol.ExitPayload](response)
			if err != nil {
				t.Fatal(err)
			}
			if payload.Code == 0 || !strings.Contains(payload.Error, "invalid debugger exit payload") {
				t.Fatalf("malformed exit became success: %#v", payload)
			}
			_ = server.Close()
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

type blockingCloseProvider struct {
	started chan struct{}
	release chan struct{}
}

func (p *blockingCloseProvider) Detect(context.Context) (provider.Capabilities, int, error) {
	return provider.Capabilities{}, 0, nil
}
func (p *blockingCloseProvider) Open(context.Context, provider.Spec) (provider.Handle, error) {
	return provider.Handle{}, nil
}
func (p *blockingCloseProvider) Inspect(context.Context, provider.Handle) (provider.State, error) {
	return provider.State{}, nil
}
func (p *blockingCloseProvider) Focus(context.Context, provider.Handle) error { return nil }
func (p *blockingCloseProvider) Close(ctx context.Context, _ provider.Handle) error {
	close(p.started)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.release:
		return nil
	}
}

func TestBrokerCloseBoundsProviderCleanupWithoutHoldingMutex(t *testing.T) {
	record := SessionRecord{ID: "0123456789abcdef", Token: "0123456789abcdef0123456789abcdef"}
	b := New(record, provider.NewRegistry(t.TempDir()))
	b.providerCloseTTL = 250 * time.Millisecond
	blocker := &blockingCloseProvider{started: make(chan struct{}), release: make(chan struct{})}
	defer close(blocker.release)
	server, client := net.Pipe()
	defer client.Close()
	b.requests["abcdef0123456789"] = &request{
		id: "abcdef0123456789", wrapper: &peer{conn: server}, provider: blocker,
		handle: provider.Handle{ID: "pane"},
	}
	done := make(chan struct{})
	go func() {
		_ = b.Close()
		close(done)
	}()
	select {
	case <-blocker.started:
	case <-time.After(time.Second):
		t.Fatal("provider cleanup did not start")
	}
	locked := make(chan struct{}, 1)
	go func() {
		b.mu.Lock()
		locked <- struct{}{}
		b.mu.Unlock()
	}()
	select {
	case <-locked:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("broker held its request mutex during provider cleanup")
	}
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("wrapper connection remained open during provider cleanup: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("broker close exceeded the provider cleanup deadline")
	}
}

func TestBrokerCloseIsConcurrentSafe(t *testing.T) {
	b := New(SessionRecord{}, provider.NewRegistry(t.TempDir()))
	start := make(chan struct{})
	done := make(chan struct{})
	const callers = 32
	var wait sync.WaitGroup
	wait.Add(callers)
	for range callers {
		go func() {
			defer wait.Done()
			<-start
			if err := b.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}()
	}
	close(start)
	go func() {
		wait.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("concurrent broker close calls did not return")
	}
}

func TestBrokerCloseCancelsProviderOpen(t *testing.T) {
	dir := t.TempDir()
	started := filepath.Join(dir, "started")
	release := filepath.Join(dir, "release")
	defer os.WriteFile(release, nil, 0o600)
	script := `#!/bin/sh
request=$(cat)
case "$request" in
  *'"operation":"open"'*)
    : > "$PWNBRIDGE_BROKER_TEST_STARTED"
    while test ! -e "$PWNBRIDGE_BROKER_TEST_RELEASE"; do sleep 0.01; done
    printf '{"provider":"custom:test","id":"late-pane"}\n'
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
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("broker close did not cancel provider open")
	}
}

func TestBrokerProviderOpenDeadline(t *testing.T) {
	dir := t.TempDir()
	script := `#!/bin/sh
cat >/dev/null
exec sleep 30
`
	tool := filepath.Join(dir, "pwnbridge-terminal-test")
	if err := os.WriteFile(tool, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	record := SessionRecord{
		OwnerPID: os.Getpid(), ID: "0123456789abcdef", Token: "0123456789abcdef0123456789abcdef",
		Provider: "custom:test", Placement: "right", Size: "50%", LocalWorkspace: dir, Executable: "/trusted/pwnbridge",
	}
	b := New(record, provider.NewRegistry(dir))
	b.providerOpenTTL = 50 * time.Millisecond
	server, client := net.Pipe()
	defer server.Close()
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
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var response protocol.Message
	if err := protocol.Decode(client, &response); err != nil {
		t.Fatal(err)
	}
	if response.Type != "error" {
		t.Fatalf("provider timeout response = %#v", response)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed-out provider open did not unwind")
	}
}
