package workspace

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

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
