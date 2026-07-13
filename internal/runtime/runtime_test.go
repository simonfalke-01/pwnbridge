package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pwnbridge/pwnbridge/internal/protocol"
)

func TestHostCommandPreservesArgv(t *testing.T) {
	cmd, err := Command(protocol.RuntimeSpec{Kind: "host"}, false, "/tmp", map[string]string{"A": "b c"}, []string{"printf", "%s", "a b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cmd.Args) != 3 || cmd.Args[2] != "a b" {
		t.Fatalf("argv reconstructed incorrectly: %#v", cmd.Args)
	}
}

func TestHostCommandUsesOverlayPATH(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "only-in-overlay")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd, err := Command(protocol.RuntimeSpec{Kind: "host"}, false, dir, map[string]string{"PATH": dir}, []string{"only-in-overlay"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Path != path {
		t.Fatalf("got %q want %q", cmd.Path, path)
	}
}

func TestContainerCommand(t *testing.T) {
	spec := protocol.RuntimeSpec{Kind: "container", Engine: "docker", ID: "pwnbridge-x", Workdir: "/work", Workspace: "/home/me/chal"}
	cmd, err := Command(spec, true, "/home/me/chal/sub", map[string]string{"A": "b"}, []string{"gdb", "./x"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"docker", "exec", "-i", "-t", "-w", "/work/sub", "-e", "A=b", "pwnbridge-x", "gdb", "./x"}
	if len(cmd.Args) != len(want) {
		t.Fatalf("got %#v", cmd.Args)
	}
	for i := range want {
		if cmd.Args[i] != want[i] {
			t.Fatalf("arg %d: got %q want %q", i, cmd.Args[i], want[i])
		}
	}
}

func TestContainerCommandPreservesContainerCwd(t *testing.T) {
	spec := protocol.RuntimeSpec{Kind: "container", Engine: "podman", ID: "pwnbridge-x", Workdir: "/work", Workspace: "/home/me/chal"}
	cmd, err := Command(spec, false, "/work/nested", nil, []string{"pwd"})
	if err != nil {
		t.Fatal(err)
	}
	for index, argument := range cmd.Args {
		if argument == "-w" && index+1 < len(cmd.Args) && cmd.Args[index+1] == "/work/nested" {
			return
		}
	}
	t.Fatalf("container cwd was not preserved: %#v", cmd.Args)
}

func TestPodmanEnsureUsesIsolationAndOwnedMounts(t *testing.T) {
	dir := t.TempDir()
	engine := filepath.Join(dir, "podman")
	logPath := filepath.Join(dir, "calls")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$PWNBRIDGE_RUNTIME_TEST_LOG"
case "$1" in
	image) printf 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; exit 0 ;;
  inspect) exit 1 ;;
  rm) exit 0 ;;
  run) printf container-id; exit 0 ;;
esac
exit 1
`
	if err := os.WriteFile(engine, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PWNBRIDGE_RUNTIME_TEST_LOG", logPath)
	workspace, session := filepath.Join(dir, "workspace"), filepath.Join(dir, "session")
	if err := os.MkdirAll(filepath.Join(session, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	spec := protocol.RuntimeSpec{
		Kind: "container", Engine: "podman", Image: "image@sha256:abcd", Workdir: "/work", Network: "bridge",
		Workspace: workspace, WorkspaceID: "workspace123", SessionDir: session,
	}
	state, err := Ensure(context.Background(), &spec, "session123")
	if err != nil {
		t.Fatal(err)
	}
	if !state.Running || state.Engine != "podman" {
		t.Fatalf("unexpected state: %#v", state)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	call := string(data)
	for _, wanted := range []string{"image inspect --format {{.Id}} image@sha256:abcd", "--userns keep-id", "--cap-add SYS_PTRACE", "seccomp=unconfined", "--network bridge", "pwnbridge.workspace=workspace123", session + "/bin:/run/pwnbridge/bin:ro", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		if !strings.Contains(call, wanted) {
			t.Fatalf("missing %q in runtime argv:\n%s", wanted, call)
		}
	}
}

func TestEnsureReusesRunningContainerWithoutResolvingTag(t *testing.T) {
	dir := t.TempDir()
	engine := filepath.Join(dir, "docker")
	logPath := filepath.Join(dir, "calls")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$PWNBRIDGE_RUNTIME_TEST_LOG"
case "$1" in
  inspect) printf true; exit 0 ;;
  image|pull|run) exit 99 ;;
esac
exit 1
`
	if err := os.WriteFile(engine, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PWNBRIDGE_RUNTIME_TEST_LOG", logPath)
	spec := protocol.RuntimeSpec{
		Kind: "container", Engine: "docker", Image: "image:tag", ID: "pwnbridge-session123",
		Workspace: filepath.Join(dir, "workspace"), WorkspaceID: "workspace123", SessionDir: filepath.Join(dir, "session"),
	}
	state, err := Ensure(context.Background(), &spec, "session123")
	if err != nil {
		t.Fatal(err)
	}
	if !state.Running || state.ID != spec.ID {
		t.Fatalf("unexpected state: %#v", state)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "image inspect") || strings.Contains(string(data), "pull ") {
		t.Fatalf("running container still depended on configured tag:\n%s", data)
	}
}

func TestResolveImagePullsAndRejectsMutableEngineOutput(t *testing.T) {
	dir := t.TempDir()
	engine := filepath.Join(dir, "docker")
	count := filepath.Join(dir, "count")
	script := `#!/bin/sh
case "$1 $2" in
  "image inspect")
    if test -e "$PWNBRIDGE_RUNTIME_COUNT"; then
      printf 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
      exit 0
    fi
    exit 1 ;;
  "pull image:tag") touch "$PWNBRIDGE_RUNTIME_COUNT"; exit 0 ;;
esac
exit 1
`
	if err := os.WriteFile(engine, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PWNBRIDGE_RUNTIME_COUNT", count)
	id, err := resolveImage(context.Background(), engine, "image:tag")
	if err != nil {
		t.Fatal(err)
	}
	if id != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("resolved ID = %q", id)
	}

	bad := filepath.Join(dir, "bad-engine")
	if err := os.WriteFile(bad, []byte("#!/bin/sh\nprintf mutable-tag\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveImage(context.Background(), bad, "image:tag"); err == nil {
		t.Fatal("mutable engine output was accepted as an image ID")
	}
}
