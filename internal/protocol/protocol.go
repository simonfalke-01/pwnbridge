package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const MaxFrame = 1 << 20

// MaxConflictPreviewBytes bounds each endpoint payload returned for a conflict
// preview. Remote responses use newline JSON rather than framed protocol data,
// but sharing this limit keeps both endpoint implementations identical.
const MaxConflictPreviewBytes = 1 << 20

type Message struct {
	Protocol  int             `json:"protocol"`
	Type      string          `json:"type"`
	SessionID string          `json:"session_id,omitempty"`
	RequestID string          `json:"request_id,omitempty"`
	Token     string          `json:"token,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

type Hello struct {
	Version      string   `json:"version"`
	OS           string   `json:"os"`
	Architecture string   `json:"architecture"`
	Capabilities []string `json:"capabilities,omitempty"`
}

type ExecRequest struct {
	Args        []string          `json:"args"`
	Cwd         string            `json:"cwd"`
	Environment map[string]string `json:"environment,omitempty"`
	Terminal    TerminalSpec      `json:"terminal"`
	Runtime     RuntimeSpec       `json:"runtime"`
}

type ShellRequest struct {
	Cwd           string            `json:"cwd"`
	Shell         string            `json:"shell"`
	SourceUserRC  bool              `json:"source_user_rc"`
	Nonce         string            `json:"nonce"`
	SessionID     string            `json:"session_id"`
	PromptHost    string            `json:"prompt_host,omitempty"`
	PromptPath    string            `json:"prompt_path,omitempty"`
	Environment   map[string]string `json:"environment,omitempty"`
	Terminal      TerminalSpec      `json:"terminal"`
	Runtime       RuntimeSpec       `json:"runtime"`
	RemoteBarrier bool              `json:"remote_barrier,omitempty"`
}

type TerminalSpec struct {
	SessionID  string `json:"session_id"`
	SessionDir string `json:"session_dir,omitempty"`
	Broker     string `json:"broker,omitempty"`
	Token      string `json:"token,omitempty"`
	Scope      string `json:"scope"`
	Provider   string `json:"provider"`
	Placement  string `json:"placement"`
}

type RuntimeSpec struct {
	Kind        string `json:"kind"`
	Engine      string `json:"engine,omitempty"`
	Image       string `json:"image,omitempty"`
	Workdir     string `json:"workdir,omitempty"`
	Network     string `json:"network,omitempty"`
	ID          string `json:"id,omitempty"`
	Workspace   string `json:"workspace,omitempty"`
	WorkspaceID string `json:"workspace_id,omitempty"`
	SessionDir  string `json:"session_dir,omitempty"`
}

type Manifest struct {
	Protocol   int         `json:"protocol"`
	SessionID  string      `json:"session_id"`
	RequestID  string      `json:"request_id"`
	ArgvBase64 []string    `json:"argv_base64"`
	EnvBase64  []string    `json:"env_base64"`
	CwdBase64  string      `json:"cwd_base64"`
	Runtime    RuntimeSpec `json:"runtime"`
}

type PaneRequest struct {
	SessionID  string      `json:"session_id"`
	RequestID  string      `json:"request_id"`
	SessionDir string      `json:"session_dir"`
	Runtime    RuntimeSpec `json:"runtime"`
}

type BrokerPing struct {
	SessionID string `json:"session_id"`
	Address   string `json:"address"`
	Token     string `json:"token"`
}

type CleanupRequest struct {
	SessionID  string      `json:"session_id"`
	SessionDir string      `json:"session_dir"`
	Runtime    RuntimeSpec `json:"runtime"`
}

type SnapshotRequest struct {
	Root string `json:"root"`
	Path string `json:"path"`
}

type FileSnapshot struct {
	Kind       string `json:"kind"`
	Size       int64  `json:"size,omitempty"`
	Mode       uint32 `json:"mode,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Content    []byte `json:"content,omitempty"`
	Omitted    bool   `json:"omitted,omitempty"`
	LinkTarget string `json:"link_target,omitempty"`
}

type RecoveryRequest struct {
	Root string `json:"root"`
	Path string `json:"path"`
}

type RecoveryAck struct {
	Commit bool   `json:"commit"`
	SHA256 string `json:"sha256"`
}

type RecoveryResult struct {
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Items   int64  `json:"items"`
	Removed bool   `json:"removed"`
}

// BootstrapRequest is the UI-independent execution contract. Arguments and
// environment values are discrete fields; agents never evaluate user-provided
// command templates.
type BootstrapRequest struct {
	Recipe           string          `json:"recipe"`
	AuthenticateSudo bool            `json:"authenticate_sudo"`
	Steps            []BootstrapStep `json:"steps"`
}

type BootstrapStep struct {
	ID          string            `json:"id"`
	Component   string            `json:"component"`
	Description string            `json:"description"`
	Args        []string          `json:"args"`
	Environment map[string]string `json:"environment,omitempty"`
	Sudo        bool              `json:"sudo"`
}

type BootstrapEvent struct {
	Type        string `json:"type"`
	StepID      string `json:"step_id,omitempty"`
	Component   string `json:"component,omitempty"`
	Description string `json:"description,omitempty"`
	Output      string `json:"output,omitempty"`
	ExitCode    int    `json:"exit_code,omitempty"`
	Error       string `json:"error,omitempty"`
}

type OpenPayload struct {
	Title string `json:"title,omitempty"`
}
type ExitPayload struct {
	Code  int    `json:"code"`
	Error string `json:"error,omitempty"`
}

func Encode(w io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > MaxFrame {
		return fmt.Errorf("frame size %d exceeds limit", len(data))
	}
	var size [4]byte
	// MaxFrame is 1 MiB, so the conversion is proven to fit in uint32.
	binary.BigEndian.PutUint32(size[:], uint32(len(data))) // #nosec G115
	if _, err := w.Write(size[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func Decode(r io.Reader, value any) error {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n == 0 || n > MaxFrame {
		return fmt.Errorf("invalid frame size %d", n)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return err
	}
	if err := decodeStrictJSON(data, value); err != nil {
		return err
	}
	return nil
}

func Payload[T any](value T) json.RawMessage {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}

func ParsePayload[T any](msg Message) (T, error) {
	var value T
	if len(msg.Payload) == 0 {
		return value, nil
	}
	err := decodeStrictJSON(msg.Payload, &value)
	return value, err
}

func decodeStrictJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("trailing JSON data: %w", err)
		}
		return errors.New("trailing JSON value")
	}
	return nil
}
