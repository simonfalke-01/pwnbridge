package runtime

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/protocol"
	"github.com/simonfalke-01/pwnbridge/internal/subprocess"
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
	  "pull --quiet") test "$3" = image:tag || exit 2; touch "$PWNBRIDGE_RUNTIME_COUNT"; exit 0 ;;
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

type cancelProgressWriter struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	cancel context.CancelFunc
	once   sync.Once
}

func (w *cancelProgressWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	written, err := w.buffer.Write(data)
	w.mu.Unlock()
	w.once.Do(w.cancel)
	return written, err
}

func (w *cancelProgressWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.String()
}

func TestResolveImageStreamsInteractivePullAndCancels(t *testing.T) {
	dir := t.TempDir()
	engine := filepath.Join(dir, "podman")
	logPath := filepath.Join(dir, "calls")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$PWNBRIDGE_RUNTIME_TEST_LOG"
case "$1 $2" in
  "image inspect") exit 1 ;;
  "pull image:tag") printf 'pull-started\n'; sleep 10 ;;
esac
exit 1
`
	if err := os.WriteFile(engine, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PWNBRIDGE_RUNTIME_TEST_LOG", logPath)
	ctx, cancel := context.WithCancel(context.Background())
	progress := &cancelProgressWriter{cancel: cancel}
	started := time.Now()
	_, err := resolveImageProgress(ctx, engine, "image:tag", progress)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled pull error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("cancelled pull took %v", elapsed)
	}
	if !strings.Contains(progress.String(), "pull-started") {
		t.Fatalf("progress = %q", progress.String())
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), "pull image:tag") || strings.Contains(string(log), "--quiet") {
		t.Fatalf("interactive pull argv = %q", log)
	}
}

func TestResolveImageQuietPullBoundsFinalDiagnostic(t *testing.T) {
	dir := t.TempDir()
	engine := filepath.Join(dir, "docker")
	logPath := filepath.Join(dir, "calls")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$PWNBRIDGE_RUNTIME_TEST_LOG"
case "$1 $2" in
  "image inspect") exit 1 ;;
  "pull --quiet")
    dd if=/dev/zero bs=1048576 count=1 >&2 2>/dev/null
    printf 'final-pull-error\n' >&2
    exit 7 ;;
esac
exit 1
`
	if err := os.WriteFile(engine, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PWNBRIDGE_RUNTIME_TEST_LOG", logPath)
	_, err := resolveImage(context.Background(), engine, "image:tag")
	if err == nil || !strings.Contains(err.Error(), "[output truncated]") || !strings.HasSuffix(err.Error(), "final-pull-error") {
		t.Fatalf("quiet pull error = %q", err)
	}
	if len(err.Error()) > subprocess.DiagnosticLimit+1024 {
		t.Fatalf("quiet pull error length = %d", len(err.Error()))
	}
	log, readErr := os.ReadFile(logPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !strings.Contains(string(log), "pull --quiet image:tag") {
		t.Fatalf("quiet pull argv = %q", log)
	}
}

func TestEnsureRejectsOversizedManagementReply(t *testing.T) {
	dir := t.TempDir()
	engine := filepath.Join(dir, "docker")
	marker := filepath.Join(dir, "mutated")
	script := `#!/bin/sh
if [ "$1" = inspect ]; then
  dd if=/dev/zero bs=65537 count=1 2>/dev/null
  exit 0
fi
touch "$PWNBRIDGE_RUNTIME_MARKER"
exit 0
`
	if err := os.WriteFile(engine, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PWNBRIDGE_RUNTIME_MARKER", marker)
	spec := protocol.RuntimeSpec{Kind: "container", Engine: "docker", Image: "image:tag", ID: "pwnbridge-existing"}
	_, err := Ensure(context.Background(), &spec, "session")
	if err == nil || !strings.Contains(err.Error(), "65536-byte limit") {
		t.Fatalf("oversized inspect error = %v", err)
	}
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("oversized inspect continued into mutation: %v", statErr)
	}
}

func TestRuntimeOperationsPreserveCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	spec := protocol.RuntimeSpec{Kind: "host"}
	if _, err := Ensure(ctx, &spec, "session"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ensure = %v", err)
	}
	if _, err := Inspect(ctx, protocol.RuntimeSpec{Kind: "container", Engine: "docker", ID: "id"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled inspect = %v", err)
	}
	if err := Stop(ctx, protocol.RuntimeSpec{Kind: "container", Engine: "docker", ID: "id"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled stop = %v", err)
	}
}

func TestRuntimeInspectBoundsInheritedOutputPipes(t *testing.T) {
	engine := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(engine, []byte("#!/bin/sh\nprintf true\nsleep 4 &\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err := Inspect(context.Background(), protocol.RuntimeSpec{Kind: "container", Engine: engine, ID: "id"})
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("inherited runtime inspect error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("inherited runtime inspect took %v", elapsed)
	}
}

func TestRuntimeStopCapturesBoundedDiagnosticsAndRemovalRace(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		engine := filepath.Join(t.TempDir(), "docker")
		if err := os.WriteFile(engine, []byte("#!/bin/sh\nprintf container-name\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := Stop(context.Background(), protocol.RuntimeSpec{Kind: "container", Engine: engine, ID: "id"}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("removed despite engine diagnostic", func(t *testing.T) {
		engine := filepath.Join(t.TempDir(), "podman")
		script := "#!/bin/sh\ncase \"$1\" in rm) printf cleanup-failed >&2; exit 1 ;; inspect) exit 1 ;; esac\n"
		if err := os.WriteFile(engine, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := Stop(context.Background(), protocol.RuntimeSpec{Kind: "container", Engine: engine, ID: "id"}); err != nil {
			t.Fatalf("post-remove diagnostic = %v", err)
		}
	})

	t.Run("final failure tail", func(t *testing.T) {
		engine := filepath.Join(t.TempDir(), "podman")
		script := `#!/bin/sh
case "$1" in
  rm) dd if=/dev/zero bs=1048576 count=1 >&2 2>/dev/null; printf 'final-remove-error\n' >&2; exit 1 ;;
  inspect) exit 0 ;;
esac
`
		if err := os.WriteFile(engine, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
		err := Stop(context.Background(), protocol.RuntimeSpec{Kind: "container", Engine: engine, ID: "id"})
		if err == nil || !strings.Contains(err.Error(), "[output truncated]") || !strings.HasSuffix(err.Error(), "final-remove-error") {
			t.Fatalf("remove diagnostic = %q", err)
		}
	})
}
