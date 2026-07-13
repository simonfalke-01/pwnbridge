package workspace

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/pwnbridge/pwnbridge/internal/paths"
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
	state.MutagenIdentifier = "abc"
	if err := m.SaveState(ws, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := m.LoadState(ws)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.MutagenIdentifier != "abc" {
		t.Fatalf("bad state: %#v", loaded)
	}
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
