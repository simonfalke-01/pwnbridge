package workspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/paths"
)

func TestStableWorkspaceIdentity(t *testing.T) {
	root := t.TempDir()
	p := paths.Paths{State: filepath.Join(root, "state"), Data: filepath.Join(root, "data")}
	m := Manager{Paths: p}
	a, err := m.Resolve(root, "x86", "~/.local/share/pwnbridge/workspaces")
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Resolve(root, "x86", "~/.local/share/pwnbridge/workspaces")
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != b.ID || a.RemotePath != b.RemotePath {
		t.Fatalf("identity not stable: %#v %#v", a, b)
	}
	c, err := m.Resolve(root, "other", "~/.local/share/pwnbridge/workspaces")
	if err != nil {
		t.Fatal(err)
	}
	if c.ID == a.ID {
		t.Fatal("host must affect workspace identity")
	}
}

func TestStateIdentityCheck(t *testing.T) {
	root := t.TempDir()
	m := Manager{Paths: paths.Paths{State: filepath.Join(root, "state"), Data: filepath.Join(root, "data")}}
	ws, err := m.Resolve(root, "x86", "~/work")
	if err != nil {
		t.Fatal(err)
	}
	state, err := m.LoadState(ws)
	if err != nil {
		t.Fatal(err)
	}
	state.MutagenIdentifier = "sync_0123456789abcdef0123456789abcdef"
	if err := m.SaveState(ws, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := m.LoadState(ws)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.MutagenIdentifier != "sync_0123456789abcdef0123456789abcdef" {
		t.Fatalf("bad state: %#v", loaded)
	}
}

func TestStateRejectsUntrustedFilesAndValues(t *testing.T) {
	newWorkspace := func(t *testing.T) (Manager, Workspace, State) {
		t.Helper()
		root := t.TempDir()
		manager := Manager{Paths: paths.Paths{State: filepath.Join(root, "state"), Data: filepath.Join(root, "data")}}
		workspace, err := manager.Resolve(root, "x86", "~/work")
		if err != nil {
			t.Fatal(err)
		}
		state, err := manager.LoadState(workspace)
		if err != nil {
			t.Fatal(err)
		}
		state.MutagenIdentifier = "sync_0123456789abcdef0123456789abcdef"
		state.SyncFingerprint = strings.Repeat("a", 64)
		return manager, workspace, state
	}

	t.Run("symbolic link", func(t *testing.T) {
		manager, workspace, state := newWorkspace(t)
		if err := manager.SaveState(workspace, state); err != nil {
			t.Fatal(err)
		}
		target := workspace.StatePath + ".target"
		if err := os.Rename(workspace.StatePath, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, workspace.StatePath); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.LoadState(workspace); err == nil {
			t.Fatal("symbolic-link workspace state was accepted")
		}
	})

	t.Run("permissive mode", func(t *testing.T) {
		manager, workspace, state := newWorkspace(t)
		if err := manager.SaveState(workspace, state); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(workspace.StatePath, 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.LoadState(workspace); err == nil {
			t.Fatal("group-readable workspace state was accepted")
		}
	})

	t.Run("unknown field", func(t *testing.T) {
		manager, workspace, state := newWorkspace(t)
		if err := manager.SaveState(workspace, state); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(workspace.StatePath)
		if err != nil {
			t.Fatal(err)
		}
		data = []byte(strings.TrimSuffix(strings.TrimSpace(string(data)), "}") + ",\"unknown\":true}\n")
		if err := os.WriteFile(workspace.StatePath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.LoadState(workspace); err == nil {
			t.Fatal("unknown workspace state field was accepted")
		}
	})

	t.Run("unsafe mutagen identifier", func(t *testing.T) {
		manager, workspace, state := newWorkspace(t)
		if err := manager.SaveState(workspace, state); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(workspace.StatePath)
		if err != nil {
			t.Fatal(err)
		}
		data = []byte(strings.Replace(string(data), state.MutagenIdentifier, "--help", 1))
		if err := os.WriteFile(workspace.StatePath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.LoadState(workspace); err == nil {
			t.Fatal("option-like Mutagen identifier was accepted")
		}
	})
}

func TestBinding(t *testing.T) {
	root := t.TempDir()
	m := Manager{Paths: paths.Paths{State: filepath.Join(root, "state")}}
	if err := m.SetBinding(root, "x86"); err != nil {
		t.Fatal(err)
	}
	got, err := m.Binding(root)
	if err != nil {
		t.Fatal(err)
	}
	if got != "x86" {
		t.Fatalf("got %q", got)
	}
}

func TestBindingCanonicalizesSymlinkRoot(t *testing.T) {
	base := t.TempDir()
	realRoot := filepath.Join(base, "real")
	aliasRoot := filepath.Join(base, "alias")
	if err := os.Mkdir(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realRoot, aliasRoot); err != nil {
		t.Fatal(err)
	}
	m := Manager{Paths: paths.Paths{State: filepath.Join(base, "state")}}
	if err := m.SetBinding(aliasRoot, "remote"); err != nil {
		t.Fatal(err)
	}
	got, err := m.Binding(realRoot)
	if err != nil {
		t.Fatal(err)
	}
	if got != "remote" {
		t.Fatalf("binding through symlink was not visible from canonical root: %q", got)
	}
}

func TestStateAndBindingCatalogMigration(t *testing.T) {
	projectRoot := t.TempDir()
	manager := Manager{Paths: paths.Paths{State: filepath.Join(t.TempDir(), "state"), Data: filepath.Join(t.TempDir(), "data")}}
	ws, err := manager.Resolve(projectRoot, "x86", "~/.local/share/pwnbridge/workspaces")
	if err != nil {
		t.Fatal(err)
	}
	state, err := manager.LoadState(ws)
	if err != nil {
		t.Fatal(err)
	}
	state.RemoteRetained = true
	state.MutagenIdentifier = "sync_0123456789abcdef0123456789abcdef"
	if err := manager.SaveState(ws, state); err != nil {
		t.Fatal(err)
	}
	states, err := manager.ListStates()
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].Schema != 2 || states[0].Legacy || states[0].LocalRoot != ws.LocalRoot || states[0].RemotePath != ws.RemotePath || !states[0].RemoteRetained {
		t.Fatalf("schema-two state inventory = %#v", states)
	}

	legacy := State{Schema: 1, WorkspaceID: ws.ID, HostID: ws.HostID, MutagenIdentifier: state.MutagenIdentifier, UpdatedAt: time.Now().UTC()}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ws.StatePath, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := manager.LoadState(ws)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Schema != 1 || loaded.LocalRoot != ws.LocalRoot || loaded.RemotePath != ws.RemotePath || !loaded.RemoteRetained {
		t.Fatalf("legacy state was not conservatively hydrated: %#v", loaded)
	}
	states, err = manager.ListStates()
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || !states[0].Legacy || states[0].LocalRoot != "" || !states[0].RemoteRetained {
		t.Fatalf("legacy state inventory = %#v", states)
	}
	if err := manager.SaveState(ws, loaded); err != nil {
		t.Fatal(err)
	}
	states, err = manager.ListStates()
	if err != nil || len(states) != 1 || states[0].Schema != 2 || states[0].Legacy {
		t.Fatalf("migrated state inventory = %#v, %v", states, err)
	}
	changedRoot, err := manager.Resolve(projectRoot, "x86", "/srv/pwnbridge/workspaces")
	if err != nil {
		t.Fatal(err)
	}
	changedState, err := manager.LoadState(changedRoot)
	if err != nil {
		t.Fatalf("workspace-root configuration change rejected stored lifecycle path: %v", err)
	}
	if changedState.RemotePath != ws.RemotePath {
		t.Fatalf("stored remote lifecycle path was not retained: %q", changedState.RemotePath)
	}

	if err := manager.SetBinding(projectRoot, "x86"); err != nil {
		t.Fatal(err)
	}
	bindings, err := manager.ListBindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 || bindings[0].Schema != 2 || bindings[0].LocalRoot != ws.LocalRoot || bindings[0].Legacy {
		t.Fatalf("schema-two binding inventory = %#v", bindings)
	}
	bindingEntries, err := os.ReadDir(filepath.Join(manager.Paths.State, "bindings"))
	if err != nil || len(bindingEntries) != 1 {
		t.Fatalf("binding files = %#v, %v", bindingEntries, err)
	}
	bindingPath := filepath.Join(manager.Paths.State, "bindings", bindingEntries[0].Name())
	data, err = json.Marshal(Binding{Schema: 1, HostID: "x86"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bindingPath, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	bindings, err = manager.ListBindings()
	if err != nil || len(bindings) != 1 || !bindings[0].Legacy || bindings[0].LocalRoot != "" {
		t.Fatalf("legacy binding inventory = %#v, %v", bindings, err)
	}
}

func TestCatalogsRejectIdentityMismatchAndUnsafeRecoveryRoots(t *testing.T) {
	projectRoot := t.TempDir()
	manager := Manager{Paths: paths.Paths{State: filepath.Join(t.TempDir(), "state"), Data: filepath.Join(t.TempDir(), "data")}}
	if err := manager.SetBinding(projectRoot, "x86"); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(manager.Paths.State, "bindings"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("binding entries = %#v, %v", entries, err)
	}
	path := filepath.Join(manager.Paths.State, "bindings", entries[0].Name())
	var binding Binding
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &binding); err != nil {
		t.Fatal(err)
	}
	binding.LocalRoot = filepath.Join(projectRoot, "different")
	data, err = json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ListBindings(); err == nil || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("mismatched binding was accepted: %v", err)
	}

	recoveryRoot := filepath.Join(manager.Paths.Data, "recovery")
	valid := filepath.Join(recoveryRoot, "0123456789abcdef")
	if err := os.MkdirAll(valid, 0o700); err != nil {
		t.Fatal(err)
	}
	if roots, err := manager.ListRecoveryRoots(); err != nil || len(roots) != 0 {
		t.Fatalf("empty recovery root = %#v, %v", roots, err)
	}
	if err := os.WriteFile(filepath.Join(valid, "archive"), []byte("recovery"), 0o600); err != nil {
		t.Fatal(err)
	}
	if roots, err := manager.ListRecoveryRoots(); err != nil || len(roots) != 1 || roots[0].WorkspaceID != "0123456789abcdef" {
		t.Fatalf("recovery roots = %#v, %v", roots, err)
	}
	if err := os.Symlink(valid, filepath.Join(recoveryRoot, "fedcba9876543210")); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ListRecoveryRoots(); err == nil {
		t.Fatal("symbolic-link recovery root was accepted")
	}
}

func BenchmarkListStates100(b *testing.B) {
	base := b.TempDir()
	manager := Manager{Paths: paths.Paths{State: filepath.Join(base, "state"), Data: filepath.Join(base, "data")}}
	for index := range 100 {
		root := filepath.Join(base, "projects", string(rune('a'+index/26)), string(rune('a'+index%26)))
		if err := os.MkdirAll(root, 0o700); err != nil {
			b.Fatal(err)
		}
		ws, err := manager.Resolve(root, "x86", "~/.local/share/pwnbridge/workspaces")
		if err != nil {
			b.Fatal(err)
		}
		state, err := manager.LoadState(ws)
		if err != nil {
			b.Fatal(err)
		}
		state.RemoteRetained = true
		if err := manager.SaveState(ws, state); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for b.Loop() {
		states, err := manager.ListStates()
		if err != nil || len(states) != 100 {
			b.Fatalf("states=%d err=%v", len(states), err)
		}
	}
}

func TestMachineIDConcurrentInitialization(t *testing.T) {
	root := t.TempDir()
	manager := Manager{Paths: paths.Paths{State: filepath.Join(root, "state")}}
	const workers = 32
	ids := make(chan string, workers)
	errs := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			id, err := manager.MachineID()
			ids <- id
			errs <- err
		}()
	}
	group.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	want := ""
	for id := range ids {
		if want == "" {
			want = id
		}
		if id != want {
			t.Fatalf("concurrent installation identities diverged: %q != %q", id, want)
		}
	}
}

func FuzzWorkspaceSlug(f *testing.F) {
	f.Add("ret2win")
	f.Add("../../\x00πwn challenge")
	f.Fuzz(func(t *testing.T, input string) {
		slug := workspaceSlug(input)
		if slug == "" || len(slug) > 48 || slug == "." || slug == ".." || unsafeSlug.MatchString(slug) {
			t.Fatalf("unsafe slug %q from %q", slug, input)
		}
	})
}

func TestTryAcquireLockDistinguishesLiveLease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lease")
	owner, err := AcquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if lock, acquired, err := TryAcquireLock(path); err != nil || acquired || lock != nil {
		t.Fatalf("live lease was acquired twice: lock=%#v acquired=%t err=%v", lock, acquired, err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	lock, acquired, err := TryAcquireLock(path)
	if err != nil || !acquired || lock == nil {
		t.Fatalf("released lease was not acquired: lock=%#v acquired=%t err=%v", lock, acquired, err)
	}
	_ = lock.Close()
}

func TestMachineIDRejectsPathCharacters(t *testing.T) {
	root := t.TempDir()
	manager := Manager{Paths: paths.Paths{State: filepath.Join(root, "state"), Data: filepath.Join(root, "data")}}
	if err := os.MkdirAll(manager.Paths.State, 0o700); err != nil {
		t.Fatal(err)
	}
	malicious := "../../outside" + strings.Repeat("x", 32-len("../../outside"))
	if err := os.WriteFile(filepath.Join(manager.Paths.State, "machine-id"), []byte(malicious), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.MachineID(); err == nil {
		t.Fatal("path-bearing machine ID was accepted")
	}
}

func TestMachineIDRejectsNamedPipe(t *testing.T) {
	root := t.TempDir()
	manager := Manager{Paths: paths.Paths{State: filepath.Join(root, "state"), Data: filepath.Join(root, "data")}}
	if err := os.MkdirAll(manager.Paths.State, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(manager.Paths.State, "machine-id")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	holder, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holder.WriteString(strings.Repeat("a", 32) + "\n"); err != nil {
		holder.Close()
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() {
		time.Sleep(25 * time.Millisecond)
		_ = holder.Close()
		close(closed)
	}()
	if _, err := manager.MachineID(); err == nil {
		t.Fatal("named-pipe machine identity was accepted")
	}
	<-closed
}
