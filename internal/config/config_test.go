package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"github.com/pwnbridge/pwnbridge/internal/paths"
)

func testPaths(root string) paths.Paths {
	return paths.Paths{Config: filepath.Join(root, "config"), State: filepath.Join(root, "state"), Data: filepath.Join(root, "data"), Cache: filepath.Join(root, "cache")}
}

func TestLoadDefaults(t *testing.T) {
	t.Setenv("PWNBRIDGE_CONFIG", "")
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	e, err := Load(root, testPaths(root))
	if err != nil {
		t.Fatal(err)
	}
	if e.ProjectRoot != root {
		t.Fatalf("root = %q, want %q", e.ProjectRoot, root)
	}
	if e.Global.Sync.Mode != "two-way-safe" || !e.Global.Sync.PauseOnIdle {
		t.Fatalf("bad defaults: %#v", e.Global.Sync)
	}
	if e.Global.Terminal.Provider != "auto" || !e.Global.Terminal.Focus {
		t.Fatalf("bad terminal defaults: %#v", e.Global.Terminal)
	}
}

func TestStrictUnknownKey(t *testing.T) {
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	p := testPaths(root)
	if err := os.MkdirAll(p.Config, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.Config, "config.toml"), []byte("schema=1\nunknown=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(root, p)
	if err == nil {
		t.Fatal("expected strict decode error")
	}
}

func TestProjectDiscoveryAndFalseOverride(t *testing.T) {
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	child := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	project := "schema=1\n[shell]\nsource_user_rc=false\n"
	if err := os.WriteFile(filepath.Join(root, ".pwnbridge.toml"), []byte(project), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := Load(child, testPaths(root))
	if err != nil {
		t.Fatal(err)
	}
	if e.ProjectRoot != root {
		t.Fatalf("root = %q", e.ProjectRoot)
	}
	if e.Project.Shell.SourceUserRC {
		t.Fatal("false override was lost")
	}
}

func TestEnvironmentHostValidation(t *testing.T) {
	t.Setenv("PWNBRIDGE_HOST", "missing")
	root := t.TempDir()
	_, err := Load(root, testPaths(root))
	if err == nil {
		t.Fatal("expected missing host error")
	}
}

func TestGlobalRuntimeIsProjectBase(t *testing.T) {
	t.Setenv("PWNBRIDGE_CONFIG", "")
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	p := testPaths(root)
	if err := os.MkdirAll(p.Config, 0o700); err != nil {
		t.Fatal(err)
	}
	global := "schema=1\n[runtime.container]\nengine='podman'\nnetwork='none'\n"
	if err := os.WriteFile(filepath.Join(p.Config, "config.toml"), []byte(global), 0o600); err != nil {
		t.Fatal(err)
	}
	project := "schema=1\n[runtime]\nkind='container'\n[runtime.container]\nimage='example.invalid/pwn@sha256:abcd'\n"
	if err := os.WriteFile(filepath.Join(root, ".pwnbridge.toml"), []byte(project), 0o600); err != nil {
		t.Fatal(err)
	}
	effective, err := Load(root, p)
	if err != nil {
		t.Fatal(err)
	}
	if effective.Project.Runtime.Container.Engine != "podman" || effective.Project.Runtime.Container.Network != "none" {
		t.Fatalf("global runtime base was lost: %#v", effective.Project.Runtime.Container)
	}
}

func TestRejectsUnsafeExecutionConfiguration(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Effective)
	}{
		{"workspace escape", func(e *Effective) { e.Project.Workspace.Root = "../.." }},
		{"remote container terminal", func(e *Effective) {
			e.Global.Terminal.Scope = "remote"
			e.Project.Runtime.Kind = "container"
			e.Project.Runtime.Container.Image = "image:tag"
		}},
		{"host option injection", func(e *Effective) {
			e.Global.Hosts["x"] = Host{Destination: "-oProxyCommand=bad", Platform: "linux/amd64"}
		}},
		{"unsafe provider", func(e *Effective) { e.Global.Terminal.Provider = "custom:../../bad" }},
		{"invalid tty layout", func(e *Effective) { e.Global.Terminal.Placement = "diagonal" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			effective := Defaults()
			tc.mutate(&effective)
			if err := effective.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidHostName(t *testing.T) {
	for _, name := range []string{"x86", "pwn-box_2", "lab.example"} {
		if !ValidHostName(name) {
			t.Errorf("ValidHostName(%q) = false", name)
		}
	}
	for _, name := range []string{"", "has space", "../escape", "line\nbreak", "πwn", strings.Repeat("a", 65)} {
		if ValidHostName(name) {
			t.Errorf("ValidHostName(%q) = true", name)
		}
	}
}

func FuzzStrictProjectTOML(f *testing.F) {
	f.Add([]byte("schema=1\ntarget='linux/amd64'\n[runtime]\nkind='host'\n"))
	f.Add([]byte("schema=999\nunknown=true\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		var layer projectLayer
		decoder := toml.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&layer) != nil {
			return
		}
		project := Defaults().Project
		_ = applyProject(&project, layer)
	})
}
