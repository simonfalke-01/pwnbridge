package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"github.com/simonfalke-01/pwnbridge/internal/paths"
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
	if e.Global.Sync.Mode != "two-way-safe" || e.Global.Sync.PauseOnIdle {
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
	if err := os.WriteFile(filepath.Join(p.Config, "config.toml"), []byte("schema=1\nunknown=true\nanother=false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(root, p)
	if err == nil {
		t.Fatal("expected strict decode error")
	}
	var strict *toml.StrictMissingError
	if !errors.As(err, &strict) {
		t.Fatalf("strict error type was not preserved: %T: %v", err, err)
	}
	if detail := err.Error(); !strings.Contains(detail, "config.toml:2:1") ||
		!strings.Contains(detail, `unknown configuration key "unknown"`) ||
		!strings.Contains(detail, "(and 1 more unknown key(s))") {
		t.Fatalf("strict error lacks path, position, or key: %v", err)
	}
}

func TestConfigDecodeErrorIncludesPathPositionAndKey(t *testing.T) {
	root := t.TempDir()
	p := testPaths(root)
	if err := os.MkdirAll(p.Config, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(p.Config, "config.toml")
	if err := os.WriteFile(path, []byte("schema = 2\n[sync]\nengine = []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadGlobal(p)
	if err == nil {
		t.Fatal("invalid typed configuration was accepted")
	}
	var decode *toml.DecodeError
	if !errors.As(err, &decode) {
		t.Fatalf("decode error type was not preserved: %T: %v", err, err)
	}
	line, column := decode.Position()
	if line != 3 || column < 1 {
		t.Fatalf("decode position = %d:%d, want line 3", line, column)
	}
	detail := err.Error()
	if !strings.Contains(detail, path+":3:") || !strings.Contains(detail, `"sync.engine"`) {
		t.Fatalf("decode error lacks path, position, or key: %v", err)
	}
}

func TestConfigRejectsPathologicalValueNesting(t *testing.T) {
	root := t.TempDir()
	p := testPaths(root)
	if err := os.MkdirAll(p.Config, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(p.Config, "config.toml")
	const depth = 100_000
	for _, test := range []struct {
		name, value string
	}{
		{name: "array", value: strings.Repeat("[", depth) + strings.Repeat("]", depth)},
		{name: "inline-table", value: strings.Repeat("{k=", depth) + "1" + strings.Repeat("}", depth)},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := []byte("schema = 2\nunknown = " + test.value + "\n")
			if len(data) >= maxConfigBytes {
				t.Fatalf("regression input is %d bytes, outside parser boundary", len(data))
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadGlobal(p)
			if err == nil {
				t.Fatal("pathologically nested configuration was accepted")
			}
			var decode *toml.DecodeError
			if !errors.As(err, &decode) {
				t.Fatalf("nesting error type was not preserved: %T: %v", err, err)
			}
			if detail := err.Error(); !strings.Contains(detail, path+":2:") || !strings.Contains(detail, "nested more than the maximum") {
				t.Fatalf("nesting error lacks bounded parser detail: %v", err)
			}
		})
	}
}

func TestConfigRejectsOversizedFile(t *testing.T) {
	root := t.TempDir()
	p := testPaths(root)
	if err := os.MkdirAll(p.Config, 0o700); err != nil {
		t.Fatal(err)
	}
	data := "schema=1\n#" + strings.Repeat("x", (1<<20)+1) + "\n"
	if err := os.WriteFile(filepath.Join(p.Config, "config.toml"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGlobal(p); err == nil {
		t.Fatal("oversized global configuration was accepted")
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
		{"container workdir outside mount", func(e *Effective) {
			e.Project.Runtime.Kind = "container"
			e.Project.Runtime.Container.Image = "image@sha256:abcd"
			e.Project.Runtime.Container.Workdir = "/tmp"
		}},
		{"container workdir traversal", func(e *Effective) {
			e.Project.Runtime.Kind = "container"
			e.Project.Runtime.Container.Image = "image@sha256:abcd"
			e.Project.Runtime.Container.Workdir = "/work/../../etc"
		}},
		{"remote workspace escape", func(e *Effective) {
			e.Global.Hosts["x"] = Host{Destination: "pwnbox", Platform: "linux/amd64", WorkspaceRoot: "~/../escape", BootstrapProfile: "pwn"}
		}},
		{"unknown bootstrap profile", func(e *Effective) {
			e.Global.Hosts["x"] = Host{Destination: "pwnbox", Platform: "linux/amd64", WorkspaceRoot: "~/.local/share/pwnbridge/workspaces", BootstrapProfile: "mystery"}
		}},
		{"unknown shell transport", func(e *Effective) {
			e.Global.Hosts["x"] = Host{Destination: "pwnbox", Platform: "linux/amd64", ShellTransport: "telnet"}
		}},
		{"unsafe Mosh port", func(e *Effective) {
			e.Global.Hosts["x"] = Host{Destination: "pwnbox", Platform: "linux/amd64", ShellTransport: "mosh", MoshPort: "60000;touch-pwned"}
		}},
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

func TestWorkspaceRootCannotEscapeThroughSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".pwnbridge.toml"), []byte("schema=1\n[workspace]\nroot='linked'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root, testPaths(root)); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("symlink escape was not rejected: %v", err)
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

func TestProjectEnvironmentRejectsReservedAndMalformedNames(t *testing.T) {
	for key, value := range map[string]string{
		"PWNBRIDGE_BROKER_TOKEN": "secret",
		"1INVALID":               "value",
		"HAS-DASH":               "value",
	} {
		effective := Defaults()
		effective.Project.Environment.Set = map[string]string{key: value}
		if err := effective.Validate(); err == nil {
			t.Fatalf("environment key %q was accepted", key)
		}
	}
	effective := Defaults()
	effective.Project.Environment.Set = map[string]string{"LD_PRELOAD": "./libc.so.6", "PWNLIB_NOTERM": "1"}
	if err := effective.Validate(); err != nil {
		t.Fatalf("valid pwn environment was rejected: %v", err)
	}
}

func TestRemoteWorkspaceRootAllowsSafeHomeAndAbsoluteRoots(t *testing.T) {
	for _, root := range []string{"~/.local/share/pwnbridge/workspaces", "/srv/pwnbridge/workspaces"} {
		if !validRemoteWorkspaceRoot(root) {
			t.Fatalf("safe remote workspace root %q was rejected", root)
		}
	}
	for _, root := range []string{"~/../escape", "relative/path", "/", "~/bad:port"} {
		if validRemoteWorkspaceRoot(root) {
			t.Fatalf("unsafe remote workspace root %q was accepted", root)
		}
	}
}

func TestMoshPortValidation(t *testing.T) {
	for _, value := range []string{"60000", "60000:61000", "1", "65535"} {
		if !validMoshPort(value) {
			t.Errorf("valid Mosh port %q was rejected", value)
		}
	}
	for _, value := range []string{"", "0", "65536", "61000:60000", "60000-61000", "060000", "1:2:3"} {
		if validMoshPort(value) {
			t.Errorf("invalid Mosh port %q was accepted", value)
		}
	}
}

func TestLegacyGlobalSchemaMigratesOnWriteOnly(t *testing.T) {
	root := t.TempDir()
	p := testPaths(root)
	if err := os.MkdirAll(p.Config, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(p.Config, "config.toml")
	legacy := []byte("schema=1\n")
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	effective, err := LoadGlobal(p)
	if err != nil {
		t.Fatal(err)
	}
	if effective.Global.Schema != 2 {
		t.Fatalf("in-memory schema = %d", effective.Global.Schema)
	}
	data, _ := os.ReadFile(path)
	if string(data) != string(legacy) {
		t.Fatal("read-only load rewrote global config")
	}
	if err := SaveGlobal(path, effective.Global); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if !strings.Contains(string(data), "schema = 2") {
		t.Fatalf("write did not migrate schema: %s", data)
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

func BenchmarkStrictProjectDecode(b *testing.B) {
	data := []byte(`schema = 1
target = "linux/amd64"

[workspace]
root = "."
ignore = [".git", "build", "core.*"]

[environment]
profile = "pwn"

[environment.set]
PWNLIB_NOTERM = "1"
LC_ALL = "C.UTF-8"

[shell]
command = "bash"
source_user_rc = true

[runtime]
kind = "container"

[runtime.container]
engine = "auto"
image = "example.invalid/pwn:latest"
workdir = "/work"
network = "bridge"
`)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		var layer projectLayer
		decoder := toml.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&layer); err != nil {
			b.Fatal(err)
		}
	}
}
