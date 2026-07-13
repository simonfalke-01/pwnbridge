package broker

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"

	"github.com/simonfalke-01/pwnbridge/internal/agent"
	"github.com/simonfalke-01/pwnbridge/internal/fsutil"
	"github.com/simonfalke-01/pwnbridge/internal/protocol"
	"github.com/simonfalke-01/pwnbridge/internal/terminal/provider"
	"github.com/simonfalke-01/pwnbridge/internal/transport"
	"github.com/simonfalke-01/pwnbridge/internal/version"
)

const MaxPanes = 8
const maxOpenRequestsPerMinute = 32

type SessionRecord struct {
	Schema                int                  `json:"schema"`
	OwnerPID              int                  `json:"owner_pid"`
	ID                    string               `json:"id"`
	Token                 string               `json:"token"`
	LocalSocket           string               `json:"local_socket"`
	LocalTCP              string               `json:"local_tcp,omitempty"`
	RemoteSocket          string               `json:"remote_socket"`
	ControlPath           string               `json:"control_path"`
	Destination           string               `json:"destination"`
	AgentPath             string               `json:"agent_path"`
	RemoteSessionDir      string               `json:"remote_session_dir"`
	LocalWorkspace        string               `json:"local_workspace"`
	Executable            string               `json:"executable"`
	RecordPath            string               `json:"record_path"`
	LeasePath             string               `json:"lease_path"`
	Provider              string               `json:"provider"`
	Placement             string               `json:"placement"`
	Size                  string               `json:"size"`
	Focus                 bool                 `json:"focus"`
	CloseOnSuccess        bool                 `json:"close_on_success"`
	HoldOnFailure         bool                 `json:"hold_on_failure"`
	ZellijNearCurrentPane bool                 `json:"zellij_near_current_pane"`
	ZellijDirection       string               `json:"zellij_direction"`
	ZellijFloating        bool                 `json:"zellij_floating"`
	TmuxDirection         string               `json:"tmux_direction"`
	TmuxSize              string               `json:"tmux_size"`
	Runtime               protocol.RuntimeSpec `json:"runtime"`
}

func SaveSession(path string, record SessionRecord) error {
	record.Schema = 1
	if record.RecordPath == "" {
		record.RecordPath = path
	}
	if record.LeasePath == "" {
		record.LeasePath = path + ".lease"
	}
	return fsutil.WriteJSON(path, record)
}

func LoadSession(path string) (SessionRecord, error) {
	var record SessionRecord
	if err := fsutil.ReadJSON(path, &record); err != nil {
		return record, err
	}
	if record.Schema != 1 || record.OwnerPID <= 0 || !validID(record.ID) || len(record.Token) < 32 ||
		record.RecordPath != path || record.LeasePath != path+".lease" || !validRuntime(record) {
		return record, errors.New("invalid broker session record")
	}
	return record, nil
}

func validRuntime(record SessionRecord) bool {
	runtime := record.Runtime
	if runtime.SessionDir != record.RemoteSessionDir || runtime.Workspace == "" {
		return false
	}
	if runtime.Kind == "host" {
		return true
	}
	if runtime.Kind != "container" || runtime.Image == "" || runtime.ID != "pwnbridge-"+record.ID {
		return false
	}
	return runtime.Engine == "" || runtime.Engine == "auto" || runtime.Engine == "docker" || runtime.Engine == "podman"
}

type peer struct {
	conn   net.Conn
	writer sync.Mutex
}

func (p *peer) send(message protocol.Message) error {
	p.writer.Lock()
	defer p.writer.Unlock()
	return protocol.Encode(p.conn, message)
}

type request struct {
	id       string
	wrapper  *peer
	pane     *peer
	provider provider.Provider
	handle   provider.Handle
}

type Broker struct {
	Record      SessionRecord
	Registry    *provider.Registry
	listener    net.Listener
	tcpListener net.Listener
	mu          sync.Mutex
	requests    map[string]*request
	openTimes   []time.Time
	done        chan struct{}
	BeforeOpen  func(context.Context) error
}

func New(record SessionRecord, registry *provider.Registry) *Broker {
	return &Broker{Record: record, Registry: registry, requests: map[string]*request{}, done: make(chan struct{})}
}

func (b *Broker) Start() error {
	if err := os.MkdirAll(filepath.Dir(b.Record.LocalSocket), 0o700); err != nil {
		return err
	}
	_ = os.Remove(b.Record.LocalSocket)
	listener, err := net.Listen("unix", b.Record.LocalSocket)
	if err != nil {
		return err
	}
	if err := os.Chmod(b.Record.LocalSocket, 0o600); err != nil {
		listener.Close()
		return err
	}
	b.listener = listener
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		listener.Close()
		return err
	}
	b.tcpListener = tcpListener
	b.Record.LocalTCP = tcpListener.Addr().String()
	go b.serve()
	go b.serveListener(tcpListener)
	return nil
}

func (b *Broker) Close() error {
	select {
	case <-b.done:
	default:
		close(b.done)
	}
	if b.listener != nil {
		_ = b.listener.Close()
	}
	if b.tcpListener != nil {
		_ = b.tcpListener.Close()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, request := range b.requests {
		if request.provider != nil && request.handle.ID != "" {
			_ = request.provider.Close(context.Background(), request.handle)
		}
		if request.wrapper != nil {
			_ = request.wrapper.conn.Close()
		}
		if request.pane != nil {
			_ = request.pane.conn.Close()
		}
	}
	b.requests = map[string]*request{}
	_ = os.Remove(b.Record.LocalSocket)
	return nil
}

func (b *Broker) serve() {
	b.serveListener(b.listener)
}

func (b *Broker) serveListener(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-b.done:
				return
			default:
				continue
			}
		}
		go b.handle(&peer{conn: conn})
	}
}

func (b *Broker) handle(p *peer) {
	defer p.conn.Close()
	reader := bufio.NewReader(p.conn)
	var first protocol.Message
	if err := protocol.Decode(reader, &first); err != nil {
		return
	}
	if err := b.validate(first); err != nil {
		_ = p.send(errorMessage(first, err))
		return
	}
	switch first.Type {
	case "ping":
		_ = p.send(protocol.Message{Protocol: version.ProtocolVersion, Type: "pong", SessionID: b.Record.ID, Token: b.Record.Token})
	case "open":
		b.handleWrapper(p, reader, first)
	case "pane-started":
		b.handlePane(p, reader, first)
	case "exited":
		b.finish(first.RequestID, first)
	default:
		_ = p.send(errorMessage(first, fmt.Errorf("unsupported broker message %q", first.Type)))
	}
}

func (b *Broker) handleWrapper(p *peer, reader *bufio.Reader, open protocol.Message) {
	b.mu.Lock()
	now := time.Now()
	cutoff := now.Add(-time.Minute)
	firstCurrent := 0
	for firstCurrent < len(b.openTimes) && b.openTimes[firstCurrent].Before(cutoff) {
		firstCurrent++
	}
	b.openTimes = append(b.openTimes[firstCurrent:], now)
	if len(b.openTimes) > maxOpenRequestsPerMinute {
		b.mu.Unlock()
		_ = p.send(errorMessage(open, errors.New("debugger request rate limit reached")))
		return
	}
	if len(b.requests) >= MaxPanes {
		b.mu.Unlock()
		_ = p.send(errorMessage(open, errors.New("debugger pane limit reached")))
		return
	}
	if _, exists := b.requests[open.RequestID]; exists {
		b.mu.Unlock()
		_ = p.send(errorMessage(open, errors.New("duplicate debugger request")))
		return
	}
	req := &request{id: open.RequestID, wrapper: p}
	b.requests[open.RequestID] = req
	b.mu.Unlock()
	if b.BeforeOpen != nil {
		if err := b.BeforeOpen(context.Background()); err != nil {
			b.fail(open.RequestID, fmt.Errorf("debugger sync barrier: %w", err))
			return
		}
	}

	terminalProvider, capabilities, err := b.Registry.Select(context.Background(), b.Record.Provider)
	if err != nil {
		b.fail(open.RequestID, err)
		return
	}
	payload, err := protocol.ParsePayload[protocol.OpenPayload](open)
	if err != nil {
		b.fail(open.RequestID, errors.New("invalid debugger metadata"))
		return
	}
	placement, size := brokerLayout(b.Record, capabilities.Name)
	if !contains(capabilities.Placements, placement) {
		if len(capabilities.Placements) == 1 && capabilities.Placements[0] == "window" {
			placement = "window"
		} else {
			b.fail(open.RequestID, fmt.Errorf("terminal provider %s does not support %s placement", capabilities.Name, placement))
			return
		}
	}
	spec := provider.Spec{
		SessionID: b.Record.ID, RequestID: open.RequestID, Cwd: b.Record.LocalWorkspace,
		Title: safeTitle(payload.Title), Placement: placement, Size: size, Focus: b.Record.Focus,
		CloseOnSuccess: b.Record.CloseOnSuccess, HoldOnFailure: b.Record.HoldOnFailure,
		NearCurrentPane: b.Record.ZellijNearCurrentPane, RequireVisible: true,
		Command: []string{b.Record.Executable, "__pane", "--record", b.Record.RecordPath, "--session", b.Record.ID, "--request", open.RequestID},
	}
	handle, err := terminalProvider.Open(context.Background(), spec)
	if err != nil {
		b.fail(open.RequestID, err)
		return
	}
	b.mu.Lock()
	if b.requests[open.RequestID] != req {
		b.mu.Unlock()
		_ = terminalProvider.Close(context.Background(), handle)
		return
	}
	req.provider, req.handle = terminalProvider, handle
	b.mu.Unlock()
	if err := p.send(protocol.Message{Protocol: version.ProtocolVersion, Type: "opened", SessionID: b.Record.ID, RequestID: open.RequestID, Token: b.Record.Token}); err != nil {
		b.cancel(open.RequestID, "pwntools parent disconnected while opening debugger")
		return
	}

	for {
		var message protocol.Message
		if err := protocol.Decode(reader, &message); err != nil {
			b.cancel(open.RequestID, "pwntools parent disconnected")
			return
		}
		if b.validate(message) != nil || message.RequestID != open.RequestID {
			continue
		}
		if message.Type == "cancel" {
			b.cancel(open.RequestID, "pwntools parent cancelled debugger")
			return
		}
	}
}

func (b *Broker) handlePane(p *peer, reader *bufio.Reader, started protocol.Message) {
	b.mu.Lock()
	req := b.requests[started.RequestID]
	if req == nil {
		b.mu.Unlock()
		_ = p.send(errorMessage(started, errors.New("unknown debugger request")))
		return
	}
	req.pane = p
	b.mu.Unlock()
	for {
		var message protocol.Message
		if err := protocol.Decode(reader, &message); err != nil {
			b.cancel(started.RequestID, "debugger pane disconnected")
			return
		}
		if b.validate(message) != nil || message.RequestID != started.RequestID {
			continue
		}
		if message.Type == "exited" {
			b.finish(started.RequestID, message)
			return
		}
	}
}

func (b *Broker) finish(id string, message protocol.Message) {
	b.mu.Lock()
	req := b.requests[id]
	if req != nil {
		delete(b.requests, id)
	}
	b.mu.Unlock()
	if req == nil {
		return
	}
	payload, _ := protocol.ParsePayload[protocol.ExitPayload](message)
	if req.wrapper != nil {
		_ = req.wrapper.send(protocol.Message{Protocol: version.ProtocolVersion, Type: "exited", SessionID: b.Record.ID, RequestID: id, Token: b.Record.Token, Payload: protocol.Payload(payload)})
	}
	if req.provider != nil && req.handle.ID != "" && (payload.Code == 0 && b.Record.CloseOnSuccess || payload.Code != 0 && !b.Record.HoldOnFailure) {
		_ = req.provider.Close(context.Background(), req.handle)
	}
}

func (b *Broker) cancel(id, reason string) {
	b.mu.Lock()
	req := b.requests[id]
	if req != nil {
		delete(b.requests, id)
	}
	b.mu.Unlock()
	if req == nil {
		return
	}
	message := protocol.Message{Protocol: version.ProtocolVersion, Type: "cancel", SessionID: b.Record.ID, RequestID: id, Token: b.Record.Token, Payload: protocol.Payload(protocol.ExitPayload{Error: reason})}
	if req.wrapper != nil {
		_ = req.wrapper.send(message)
	}
	if req.pane != nil {
		_ = req.pane.send(message)
	}
	if req.provider != nil && req.handle.ID != "" {
		_ = req.provider.Close(context.Background(), req.handle)
	}
}

func (b *Broker) fail(id string, err error) {
	b.mu.Lock()
	req := b.requests[id]
	if req != nil {
		delete(b.requests, id)
	}
	b.mu.Unlock()
	if req != nil && req.wrapper != nil {
		_ = req.wrapper.send(protocol.Message{Protocol: version.ProtocolVersion, Type: "error", SessionID: b.Record.ID, RequestID: id, Token: b.Record.Token, Payload: protocol.Payload(protocol.ExitPayload{Code: 1, Error: err.Error()})})
	}
}

func (b *Broker) validate(message protocol.Message) error {
	if message.Protocol != version.ProtocolVersion {
		return errors.New("broker protocol mismatch")
	}
	if message.Token != b.Record.Token {
		return errors.New("broker authentication failed")
	}
	if message.SessionID != b.Record.ID {
		return errors.New("broker session mismatch")
	}
	if message.RequestID != "" && !validID(message.RequestID) {
		return errors.New("invalid request id")
	}
	return nil
}

func errorMessage(request protocol.Message, err error) protocol.Message {
	// Echo only the credential supplied by the peer. A valid client can
	// authenticate an error response, while an invalid client learns nothing
	// it did not already send.
	return protocol.Message{Protocol: version.ProtocolVersion, Type: "error", SessionID: request.SessionID, RequestID: request.RequestID, Token: request.Token, Payload: protocol.Payload(protocol.ExitPayload{Code: 1, Error: err.Error()})}
}

func safeTitle(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, value)
	if len(value) > 80 {
		value = value[:80]
	}
	if value == "" {
		return "pwntools GDB"
	}
	return value
}

func brokerLayout(record SessionRecord, providerName string) (string, string) {
	placement, size := record.Placement, record.Size
	switch providerName {
	case "zellij":
		if record.ZellijFloating {
			placement = "floating"
		} else if placement == "right" || placement == "down" {
			placement = record.ZellijDirection
		}
	case "tmux":
		if placement == "right" || placement == "down" {
			if record.TmuxDirection == "vertical" || record.TmuxDirection == "down" {
				placement = "down"
			} else {
				placement = "right"
			}
		}
		if record.TmuxSize != "" {
			size = record.TmuxSize
		}
	}
	return placement, size
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func RunPane(ctx context.Context, record SessionRecord, requestID string) error {
	if !validID(requestID) {
		return errors.New("invalid pane request id")
	}
	conn, err := net.Dial("unix", record.LocalSocket)
	if err != nil {
		return fmt.Errorf("connect to broker: %w", err)
	}
	peer := &peer{conn: conn}
	started := protocol.Message{Protocol: version.ProtocolVersion, Type: "pane-started", SessionID: record.ID, RequestID: requestID, Token: record.Token}
	if err := peer.send(started); err != nil {
		conn.Close()
		return err
	}
	encoded, err := agent.EncodeRequest(protocol.PaneRequest{SessionID: record.ID, RequestID: requestID, SessionDir: record.RemoteSessionDir, Runtime: record.Runtime})
	if err != nil {
		conn.Close()
		return err
	}
	remote := remoteAgentCommand(record.AgentPath, "pane", encoded)
	cmd := exec.CommandContext(ctx, "ssh", "-S", record.ControlPath, "-tt", "-e", "none", record.Destination, remote)
	cmd.Env = transport.SafeSSHEnvironment()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	wasCancelled := false
	if err = cmd.Start(); err == nil {
		wait := make(chan error, 1)
		go func() { wait <- cmd.Wait() }()
		cancelMessage := make(chan error, 1)
		go func() {
			var message protocol.Message
			if decodeErr := protocol.Decode(conn, &message); decodeErr != nil {
				cancelMessage <- decodeErr
				return
			}
			if message.Protocol != version.ProtocolVersion || message.SessionID != record.ID || message.RequestID != requestID || message.Token != record.Token || message.Type != "cancel" {
				cancelMessage <- errors.New("invalid pane cancellation message")
				return
			}
			cancelMessage <- errors.New("debugger pane cancelled")
		}()
		select {
		case err = <-wait:
		case cancelErr := <-cancelMessage:
			wasCancelled = true
			err = cancelErr
			if cmd.Process != nil {
				_ = cmd.Process.Signal(os.Interrupt)
			}
			select {
			case <-wait:
			case <-time.After(500 * time.Millisecond):
				if cmd.Process != nil {
					_ = cmd.Process.Kill()
				}
				<-wait
			}
		case <-ctx.Done():
			wasCancelled = true
			err = ctx.Err()
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			<-wait
		}
	}
	code := 0
	if err != nil {
		code = 1
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		}
	}
	// A user-requested hold is useful for an actual debugger failure, but must
	// never turn session shutdown/SIGTERM into an immortal pane waiting on
	// stdin. main's signal context is authoritative for cancellation.
	if err != nil && !wasCancelled && record.HoldOnFailure && ctx.Err() == nil && term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintln(os.Stderr, "\npwnbridge: debugger failed; press Enter to close this pane")
		entered := make(chan struct{})
		go func() {
			_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
			close(entered)
		}()
		select {
		case <-entered:
		case <-ctx.Done():
		}
	}
	_ = peer.send(protocol.Message{Protocol: version.ProtocolVersion, Type: "exited", SessionID: record.ID, RequestID: requestID, Token: record.Token, Payload: protocol.Payload(protocol.ExitPayload{Code: code, Error: errorText(err)})})
	_ = conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
	_ = conn.Close()
	return err
}

func Ping(record SessionRecord) error {
	conn, err := net.DialTimeout("unix", record.LocalSocket, time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	request := protocol.Message{Protocol: version.ProtocolVersion, Type: "ping", SessionID: record.ID, Token: record.Token}
	if err := protocol.Encode(conn, request); err != nil {
		return err
	}
	var response protocol.Message
	if err := protocol.Decode(conn, &response); err != nil {
		return err
	}
	if response.Type != "pong" {
		return errors.New("unexpected broker ping response")
	}
	if response.Protocol != version.ProtocolVersion || response.SessionID != record.ID || response.Token != record.Token {
		return errors.New("broker ping response identity mismatch")
	}
	return nil
}

func remoteAgentCommand(path, operation, encoded string) string {
	resolved := shellQuote(path)
	if len(path) > 2 && path[:2] == "~/" {
		resolved = `"$HOME"/` + shellQuote(path[2:])
	}
	return "exec " + resolved + " " + shellQuote(operation) + " " + shellQuote(encoded)
}
func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
func validID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
