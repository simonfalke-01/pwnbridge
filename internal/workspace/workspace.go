package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/fsutil"
	"github.com/simonfalke-01/pwnbridge/internal/identity"
	"github.com/simonfalke-01/pwnbridge/internal/paths"
	"golang.org/x/sys/unix"
)

var unsafeSlug = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

const maxWorkspaceStateBytes = 1 << 20
const maxMachineIDBytes = 64
const maxCatalogEntries = 4096

const workspaceStateSchema = 2
const bindingSchema = 2

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
	LocalRoot         string    `json:"local_root,omitempty"`
	RemotePath        string    `json:"remote_path,omitempty"`
	RemoteRetained    bool      `json:"remote_retained,omitempty"`
	MutagenIdentifier string    `json:"mutagen_identifier,omitempty"`
	SyncFingerprint   string    `json:"sync_fingerprint,omitempty"`
	RuntimeID         string    `json:"runtime_id,omitempty"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type Binding struct {
	Schema    int    `json:"schema"`
	HostID    string `json:"host_id"`
	LocalRoot string `json:"local_root,omitempty"`
}

type StoredState struct {
	State
	Legacy bool `json:"legacy,omitempty"`
}

type StoredBinding struct {
	Binding
	Legacy bool `json:"legacy,omitempty"`
}

type RecoveryRoot struct {
	WorkspaceID string `json:"workspace_id"`
	Path        string `json:"path"`
}

type Manager struct{ Paths paths.Paths }

func (m Manager) MachineID() (string, error) {
	path := filepath.Join(m.Paths.State, "machine-id")
	lock, err := AcquireLock(path + ".lock")
	if err != nil {
		return "", err
	}
	defer lock.Close()
	data, err := fsutil.ReadPrivateFileLimit(path, maxMachineIDBytes)
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
	if err := fsutil.ReadPrivateJSONLimit(ws.StatePath, maxWorkspaceStateBytes, &state); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{Schema: workspaceStateSchema, WorkspaceID: ws.ID, HostID: ws.HostID, LocalRoot: ws.LocalRoot, RemotePath: ws.RemotePath}, nil
		}
		return State{}, err
	}
	if err := validateState(ws, state); err != nil {
		return State{}, fmt.Errorf("invalid workspace state in %s: %w", ws.StatePath, err)
	}
	if state.Schema == 1 {
		state.LocalRoot, state.RemotePath, state.RemoteRetained = ws.LocalRoot, ws.RemotePath, true
	}
	return state, nil
}

func (m Manager) SaveState(ws Workspace, state State) error {
	state.Schema, state.WorkspaceID, state.HostID = workspaceStateSchema, ws.ID, ws.HostID
	state.LocalRoot, state.RemotePath, state.UpdatedAt = ws.LocalRoot, ws.RemotePath, time.Now().UTC()
	if err := validateState(ws, state); err != nil {
		return err
	}
	return fsutil.WriteJSON(ws.StatePath, state)
}

func validateState(ws Workspace, state State) error {
	if state.WorkspaceID != ws.ID || state.HostID != ws.HostID {
		return errors.New("identity mismatch")
	}
	switch state.Schema {
	case 1:
		if state.LocalRoot != "" || state.RemotePath != "" || state.RemoteRetained {
			return errors.New("schema-one state contains schema-two fields")
		}
	case workspaceStateSchema:
		if state.LocalRoot != ws.LocalRoot {
			return errors.New("workspace path mismatch")
		}
	default:
		return errors.New("unsupported workspace state schema")
	}
	return validateStateValues(state)
}

func validateStateValues(state State) error {
	if !isHexID(state.WorkspaceID, 16) || !validStateName(state.HostID, 64) {
		return errors.New("invalid workspace identity")
	}
	if state.Schema == workspaceStateSchema {
		if !validStoredLocalRoot(state.LocalRoot) || !validStoredRemotePath(state.RemotePath) {
			return errors.New("invalid workspace paths")
		}
	}
	if !validMutagenIdentifier(state.MutagenIdentifier) {
		return errors.New("invalid Mutagen identifier")
	}
	if state.SyncFingerprint != "" && !isHexID(state.SyncFingerprint, 64) {
		return errors.New("invalid synchronization fingerprint")
	}
	if state.RuntimeID != "" && !validStateName(state.RuntimeID, 128) {
		return errors.New("invalid runtime identifier")
	}
	return nil
}

func validStoredLocalRoot(value string) bool {
	return value != "" && len(value) <= 4096 && filepath.IsAbs(value) && filepath.Clean(value) == value && strings.IndexByte(value, 0) < 0
}

func validStoredRemotePath(value string) bool {
	return value != "" && len(value) <= 4096 && strings.IndexByte(value, 0) < 0 && !strings.ContainsAny(value, "\r\n") &&
		(strings.HasPrefix(value, "~/") || filepath.IsAbs(value))
}

func validMutagenIdentifier(value string) bool {
	if value == "" {
		return true
	}
	if len(value) < len("sync_")+32 || len(value) > 128 || !strings.HasPrefix(value, "sync_") {
		return false
	}
	for _, r := range strings.TrimPrefix(value, "sync_") {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func validStateName(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.HasPrefix(value, "-") {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func (m Manager) Binding(localRoot string) (string, error) {
	root, err := canonicalLocalRoot(localRoot)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(root))
	path := filepath.Join(m.Paths.State, "bindings", hex.EncodeToString(h[:])[:16]+".json")
	var binding Binding
	if err := fsutil.ReadPrivateJSONLimit(path, maxWorkspaceStateBytes, &binding); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	if err := validateBinding(binding, root, strings.TrimSuffix(filepath.Base(path), ".json")); err != nil {
		return "", err
	}
	return binding.HostID, nil
}

func (m Manager) SetBinding(localRoot, hostID string) error {
	if hostID != "" && !validStateName(hostID, 64) {
		return errors.New("invalid binding host ID")
	}
	root, err := canonicalLocalRoot(localRoot)
	if err != nil {
		return err
	}
	h := sha256.Sum256([]byte(root))
	path := filepath.Join(m.Paths.State, "bindings", hex.EncodeToString(h[:])[:16]+".json")
	return fsutil.WriteJSON(path, Binding{Schema: bindingSchema, HostID: hostID, LocalRoot: root})
}

func validateBinding(binding Binding, root, fileID string) error {
	if binding.HostID != "" && !validStateName(binding.HostID, 64) {
		return errors.New("invalid binding host ID")
	}
	if !isHexID(fileID, 16) {
		return errors.New("invalid binding filename")
	}
	switch binding.Schema {
	case 1:
		if binding.LocalRoot != "" {
			return errors.New("schema-one binding contains schema-two fields")
		}
	case bindingSchema:
		if !validStoredLocalRoot(binding.LocalRoot) {
			return errors.New("invalid binding local root")
		}
		h := sha256.Sum256([]byte(binding.LocalRoot))
		if hex.EncodeToString(h[:])[:16] != fileID || root != "" && binding.LocalRoot != root {
			return errors.New("binding project identity mismatch")
		}
	default:
		return errors.New("unsupported binding schema")
	}
	return nil
}

func (m Manager) ListStates() ([]StoredState, error) {
	root := filepath.Join(m.Paths.State, "workspaces")
	entries, err := fsutil.ReadPrivateDirectoryLimit(root, maxCatalogEntries)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	states := make([]StoredState, 0, len(entries))
	for _, entry := range entries {
		id := entry.Name()
		if !isHexID(id, 16) || entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("invalid workspace catalog entry %s", filepath.Join(root, id))
		}
		directory := filepath.Join(root, id)
		if err := fsutil.ValidatePrivateDirectory(directory); err != nil {
			return nil, err
		}
		var state State
		path := filepath.Join(directory, "state.json")
		if err := fsutil.ReadPrivateJSONLimit(path, maxWorkspaceStateBytes, &state); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		legacy := state.Schema == 1
		if state.WorkspaceID != id {
			return nil, fmt.Errorf("workspace catalog identity mismatch in %s", path)
		}
		if legacy {
			if state.LocalRoot != "" || state.RemotePath != "" || state.RemoteRetained {
				return nil, fmt.Errorf("invalid schema-one workspace state in %s", path)
			}
			state.RemoteRetained = true
		} else if state.Schema != workspaceStateSchema {
			return nil, fmt.Errorf("unsupported workspace state schema in %s", path)
		}
		if err := validateStateValues(state); err != nil {
			return nil, fmt.Errorf("invalid workspace state in %s: %w", path, err)
		}
		states = append(states, StoredState{State: state, Legacy: legacy})
	}
	sort.Slice(states, func(i, j int) bool { return states[i].WorkspaceID < states[j].WorkspaceID })
	return states, nil
}

func (m Manager) ListBindings() ([]StoredBinding, error) {
	root := filepath.Join(m.Paths.State, "bindings")
	entries, err := fsutil.ReadPrivateDirectoryLimit(root, maxCatalogEntries)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	bindings := make([]StoredBinding, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".pwnbridge-tmp-") {
			continue
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || filepath.Ext(name) != ".json" {
			return nil, fmt.Errorf("invalid binding catalog entry %s", filepath.Join(root, name))
		}
		id := strings.TrimSuffix(name, ".json")
		var binding Binding
		path := filepath.Join(root, name)
		if err := fsutil.ReadPrivateJSONLimit(path, maxWorkspaceStateBytes, &binding); err != nil {
			return nil, err
		}
		if err := validateBinding(binding, "", id); err != nil {
			return nil, fmt.Errorf("invalid binding in %s: %w", path, err)
		}
		bindings = append(bindings, StoredBinding{Binding: binding, Legacy: binding.Schema == 1})
	}
	sort.Slice(bindings, func(i, j int) bool {
		if bindings[i].LocalRoot == bindings[j].LocalRoot {
			return bindings[i].HostID < bindings[j].HostID
		}
		return bindings[i].LocalRoot < bindings[j].LocalRoot
	})
	return bindings, nil
}

func (m Manager) ListRecoveryRoots() ([]RecoveryRoot, error) {
	root := filepath.Join(m.Paths.Data, "recovery")
	entries, err := fsutil.ReadPrivateDirectoryLimit(root, maxCatalogEntries)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	recoveryRoots := make([]RecoveryRoot, 0, len(entries))
	for _, entry := range entries {
		id := entry.Name()
		path := filepath.Join(root, id)
		if !isHexID(id, 16) || entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("invalid recovery catalog entry %s", path)
		}
		nonEmpty, err := fsutil.PrivateDirectoryNonEmpty(path)
		if err != nil {
			return nil, err
		}
		if nonEmpty {
			recoveryRoots = append(recoveryRoots, RecoveryRoot{WorkspaceID: id, Path: path})
		}
	}
	sort.Slice(recoveryRoots, func(i, j int) bool { return recoveryRoots[i].WorkspaceID < recoveryRoots[j].WorkspaceID })
	return recoveryRoots, nil
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
