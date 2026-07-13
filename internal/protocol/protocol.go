package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const MaxFrame = 1 << 20

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
	Runtime     RuntimeSpec       `json:"runtime"`
}

type ShellRequest struct {
	Cwd          string            `json:"cwd"`
	Shell        string            `json:"shell"`
	SourceUserRC bool              `json:"source_user_rc"`
	Nonce        string            `json:"nonce"`
	SessionID    string            `json:"session_id"`
	BrokerSocket string            `json:"broker_socket,omitempty"`
	BrokerToken  string            `json:"broker_token,omitempty"`
	Environment  map[string]string `json:"environment,omitempty"`
	Runtime      RuntimeSpec       `json:"runtime"`
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
	if !json.Valid(data) {
		return errors.New("invalid JSON frame")
	}
	if err := json.Unmarshal(data, value); err != nil {
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
	err := json.Unmarshal(msg.Payload, &value)
	return value, err
}
