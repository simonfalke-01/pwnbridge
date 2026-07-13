package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/fsutil"
	"github.com/simonfalke-01/pwnbridge/internal/identity"
	"github.com/simonfalke-01/pwnbridge/internal/paths"
	"golang.org/x/sys/unix"
)

var unsafeSlug = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

type Workspace struct {
	ID           string `json:"id"`
	MachineID    string `json:"machine_id"`
	HostID       string `json:"host_id"`
	LocalRoot    string `json:"local_root"`
	RemoteRoot   string `json:"remote_root"`
	RemotePath   string `json:"remote_path"`
	Slug         string `json:"slug"`
	StatePath    string `json:"state_path"`
	LockPath     string `json:"lock_path"`
	RecoveryPath string `json:"recovery_path"`
}

type State struct {
	Schema            int       `json:"schema"`
	WorkspaceID       string    `json:"workspace_id"`
	HostID            string    `json:"host_id"`
	MutagenIdentifier string    `json:"mutagen_identifier,omitempty"`
	SyncFingerprint   string    `json:"sync_fingerprint,omitempty"`
	RuntimeID         string    `json:"runtime_id,omitempty"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type Binding struct {
	Schema int    `json:"schema"`
	HostID string `json:"host_id"`
}

type Manager struct{ Paths paths.Paths }

func (m Manager) MachineID() (string, error) {
	path := filepath.Join(m.Paths.State, "machine-id")
	lock, err := AcquireLock(path + ".lock")
	if err != nil {
		return "", err
	}
	defer lock.Close()
	data, err := os.ReadFile(path)
	if err == nil {
		id := strings.TrimSpace(string(data))
		if !isHexID(id, 32) {
			return "", fmt.Errorf("invalid machine id in %s", path)
		}
		return id, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	id, err := identity.Random(16)
	if err != nil {
		return "", err
	}
	if err := fsutil.AtomicWrite(path, []byte(id+"\n"), 0o600); err != nil {
		return "", err
	}
	return id, nil
}

func isHexID(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func (m Manager) Resolve(localRoot, hostID, remoteRoot string) (Workspace, error) {
	root, err := filepath.Abs(localRoot)
	if err != nil {
		return Workspace{}, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return Workspace{}, fmt.Errorf("canonicalize workspace: %w", err)
	}
	machineID, err := m.MachineID()
	if err != nil {
		return Workspace{}, err
	}
	h := sha256.Sum256([]byte(machineID + "\x00" + root + "\x00" + hostID))
	id := hex.EncodeToString(h[:])[:16]
	slug := workspaceSlug(filepath.Base(root))
	name := slug + "-" + id
	stateDir := filepath.Join(m.Paths.State, "workspaces", id)
	return Workspace{
		ID: id, MachineID: machineID, HostID: hostID, LocalRoot: root,
		RemoteRoot: remoteRoot, RemotePath: strings.TrimRight(remoteRoot, "/") + "/" + machineID + "/" + name,
		Slug: slug, StatePath: filepath.Join(stateDir, "state.json"), LockPath: filepath.Join(stateDir, "workspace.lock"),
		RecoveryPath: filepath.Join(m.Paths.Data, "recovery", id),
	}, nil
}

func workspaceSlug(base string) string {
	slug := unsafeSlug.ReplaceAllString(base, "-")
	slug = strings.Trim(slug, "-.")
	if slug == "" {
		slug = "workspace"
	}
	if len(slug) > 48 {
		slug = slug[:48]
	}
	return slug
}

func (m Manager) LoadState(ws Workspace) (State, error) {
	var state State
	if err := fsutil.ReadJSON(ws.StatePath, &state); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{Schema: 1, WorkspaceID: ws.ID, HostID: ws.HostID}, nil
		}
		return State{}, err
	}
	if state.Schema != 1 || state.WorkspaceID != ws.ID || state.HostID != ws.HostID {
		return State{}, fmt.Errorf("workspace state identity mismatch in %s", ws.StatePath)
	}
	return state, nil
}

func (m Manager) SaveState(ws Workspace, state State) error {
	state.Schema, state.WorkspaceID, state.HostID, state.UpdatedAt = 1, ws.ID, ws.HostID, time.Now().UTC()
	return fsutil.WriteJSON(ws.StatePath, state)
}

func (m Manager) Binding(localRoot string) (string, error) {
	root, err := canonicalLocalRoot(localRoot)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(root))
	path := filepath.Join(m.Paths.State, "bindings", hex.EncodeToString(h[:])[:16]+".json")
	var binding Binding
	if err := fsutil.ReadJSON(path, &binding); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	if binding.Schema != 1 {
		return "", fmt.Errorf("unsupported binding schema")
	}
	return binding.HostID, nil
}

func (m Manager) SetBinding(localRoot, hostID string) error {
	root, err := canonicalLocalRoot(localRoot)
	if err != nil {
		return err
	}
	h := sha256.Sum256([]byte(root))
	path := filepath.Join(m.Paths.State, "bindings", hex.EncodeToString(h[:])[:16]+".json")
	return fsutil.WriteJSON(path, Binding{Schema: 1, HostID: hostID})
}

func canonicalLocalRoot(localRoot string) (string, error) {
	root, err := filepath.Abs(localRoot)
	if err != nil {
		return "", err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("canonicalize binding root: %w", err)
	}
	return root, nil
}

type Lock struct{ file *os.File }

func AcquireLock(path string) (*Lock, error) {
	lock, acquired, err := acquireLock(path, false)
	if err != nil {
		return nil, err
	}
	if !acquired {
		return nil, errors.New("unexpected blocking lock result")
	}
	return lock, nil
}

// TryAcquireLock returns acquired=false when another live process owns the
// advisory lease. Callers must establish any required file trust first.
func TryAcquireLock(path string) (lock *Lock, acquired bool, err error) {
	return acquireLock(path, true)
}

func acquireLock(path string, nonblocking bool) (*Lock, bool, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, err
	}
	operation := unix.LOCK_EX
	if nonblocking {
		operation |= unix.LOCK_NB
	}
	if err := unix.Flock(int(f.Fd()), operation); err != nil {
		f.Close()
		if nonblocking && (errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN)) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return &Lock{file: f}, true, nil
}

func (l *Lock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err1 := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	err2 := l.file.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func Fingerprint(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
