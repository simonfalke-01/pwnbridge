package syncer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/subprocess"
	"github.com/simonfalke-01/pwnbridge/internal/workspace"
)

type fakeRunner struct {
	calls     [][]string
	responses []fakeResponse
}
type fakeResponse struct {
	out string
	err error
}

func (f *fakeRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	if len(f.responses) == 0 {
		return nil, errors.New("unexpected call")
	}
	r := f.responses[0]
	f.responses = f.responses[1:]
	return []byte(r.out), r.err
}

func TestBarrierValidatesAfterFlush(t *testing.T) {
	runner := &fakeRunner{responses: []fakeResponse{{out: "ok"}, {out: `{"paused":false,"status":"Watching","conflicts":[{"path":"solve.py"}]}`}}}
	m := Mutagen{Runner: runner}
	report, err := m.Barrier(context.Background(), "id")
	if err == nil {
		t.Fatal("flush success with conflict must fail")
	}
	if report.Healthy || len(report.Problems) == 0 {
		t.Fatalf("bad report: %#v", report)
	}
	if got := strings.Join(runner.calls[0], " "); got != "sync flush id" {
		t.Fatalf("first command: %s", got)
	}
}

func TestPrepareUsesDirectBarrierForMatchingStoredSession(t *testing.T) {
	spec := Spec{}
	state := workspace.State{MutagenIdentifier: "sync_existing", SyncFingerprint: Fingerprint(spec)}
	runner := &fakeRunner{responses: []fakeResponse{
		{out: "resumed"},
		{out: "flushed"},
		{out: `[{"paused":false,"status":"watching","alpha":{"connected":true},"beta":{"connected":true}}]`},
	}}
	report, err := (Mutagen{Runner: runner}).Prepare(context.Background(), spec, &state)
	if err != nil || !report.Healthy {
		t.Fatalf("prepare = %#v, %v", report, err)
	}
	want := []string{"sync resume sync_existing", "sync flush sync_existing", "sync list --template {{ json . }} sync_existing"}
	if len(runner.calls) != len(want) {
		t.Fatalf("prepare calls = %#v", runner.calls)
	}
	for i := range want {
		if got := strings.Join(runner.calls[i], " "); got != want[i] {
			t.Fatalf("prepare call %d = %q, want %q", i, got, want[i])
		}
	}
}

func TestPrepareDoesNotRecreateUnhealthyStoredSession(t *testing.T) {
	spec := Spec{}
	state := workspace.State{MutagenIdentifier: "sync_existing", SyncFingerprint: Fingerprint(spec)}
	runner := &fakeRunner{responses: []fakeResponse{
		{out: "resumed"},
		{out: "flushed"},
		{out: `[{"paused":false,"status":"watching","conflicts":[{"path":"not found.txt"}]}]`},
	}}
	_, err := (Mutagen{Runner: runner}).Prepare(context.Background(), spec, &state)
	if err == nil || len(runner.calls) != 3 {
		t.Fatalf("unhealthy prepare recreated session: calls=%#v err=%v", runner.calls, err)
	}
}

func TestPrepareRecreatesOnlyDefinitelyMissingStoredSession(t *testing.T) {
	spec := Spec{}
	state := workspace.State{MutagenIdentifier: "sync_missing", SyncFingerprint: Fingerprint(spec)}
	created := "sync_QPHUoxd7sGevWnZNPQVNuwGvbkHi2ON3Jhz0KCZveJG"
	runner := &fakeRunner{responses: []fakeResponse{
		{err: errors.New("did not match any sessions")},
		{out: "0.18.1"},
		{out: "started"},
		{out: "[]"},
		{out: "Created session " + created},
		{out: "resumed"},
		{out: "flushed"},
		{out: `[{"paused":false,"status":"watching","alpha":{"connected":true},"beta":{"connected":true}}]`},
	}}
	report, err := (Mutagen{Runner: runner}).Prepare(context.Background(), spec, &state)
	if err != nil || !report.Healthy || state.MutagenIdentifier != created {
		t.Fatalf("missing-session recovery = %#v, state=%#v, err=%v", report, state, err)
	}
}

func TestHealthyStatus(t *testing.T) {
	runner := &fakeRunner{responses: []fakeResponse{{out: `[{"identifier":"sync_QPHUoxd7sGevWnZNPQVNuwGvbkHi2ON3Jhz0KCZveJG","paused":false,"status":"watching","conflicts":[],"excludedConflicts":0,"alpha":{"connected":true,"problems":[]},"beta":{"connected":true,"problems":[]},"lastError":""}]`}}}
	report, err := (Mutagen{Runner: runner}).Status(context.Background(), "id")
	if err != nil {
		t.Fatal(err)
	}
	if !report.Healthy {
		t.Fatalf("report: %#v", report)
	}
}

func TestEndpointResourceProblemsBlockExecution(t *testing.T) {
	for _, problem := range []string{"no space left on device", "permission denied"} {
		raw := fmt.Sprintf(`[{"identifier":"sync_QPHUoxd7sGevWnZNPQVNuwGvbkHi2ON3Jhz0KCZveJG","paused":false,"status":"watching","alpha":{"connected":true,"problems":[]},"beta":{"connected":true,"transitionProblems":[{"error":%q}]}}]`, problem)
		runner := &fakeRunner{responses: []fakeResponse{{out: raw}}}
		report, err := (Mutagen{Runner: runner}).Status(context.Background(), "sync_QPHUoxd7sGevWnZNPQVNuwGvbkHi2ON3Jhz0KCZveJG")
		if err != nil {
			t.Fatal(err)
		}
		if report.Healthy || !strings.Contains(strings.Join(report.Problems, " "), "transitionProblems") {
			t.Fatalf("resource problem %q was accepted: %#v", problem, report)
		}
	}
}

func TestVersionGate(t *testing.T) {
	runner := &fakeRunner{responses: []fakeResponse{{out: "0.19.0\n"}}}
	err := (Mutagen{Runner: runner}).CheckVersion(context.Background())
	if err == nil || !strings.Contains(err.Error(), "0.18.1") {
		t.Fatalf("wrong error: %v", err)
	}
}

func TestDecodeMultipleValues(t *testing.T) {
	values, err := decodeJSONValues([]byte("{\"a\":1}\n{\"b\":2}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 2 {
		t.Fatalf("got %d", len(values))
	}
}

func TestConflictPaths(t *testing.T) {
	raw := map[string]any{"conflicts": []any{map[string]any{"alphaChanges": []any{map[string]any{"path": "solve.py"}}, "betaChanges": []any{map[string]any{"path": "solve.py"}}}}, "alpha": map[string]any{"path": "/not/a/conflict"}}
	paths := ConflictPaths(raw)
	if len(paths) != 1 || paths[0] != "solve.py" {
		t.Fatalf("got %#v", paths)
	}
}

func TestCommandEnvironmentDoesNotLeakLocalMuxOrBrokerState(t *testing.T) {
	t.Setenv("TMUX", "/tmp/tmux")
	t.Setenv("TMUX_PANE", "%1")
	t.Setenv("ZELLIJ_SESSION_NAME", "local")
	t.Setenv("PWNBRIDGE_BROKER_TOKEN", "secret")
	t.Setenv("MUTAGEN_DATA_DIRECTORY", "/wrong")
	environment := commandEnvironment("/private/mutagen")
	joined := "\n" + strings.Join(environment, "\n") + "\n"
	for _, forbidden := range []string{"\nTMUX=", "\nTMUX_PANE=", "\nZELLIJ_SESSION_NAME=", "\nPWNBRIDGE_BROKER_TOKEN="} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("unsafe environment entry survived: %s", forbidden)
		}
	}
	if strings.Count(joined, "\nMUTAGEN_DATA_DIRECTORY=/private/mutagen\n") != 1 {
		t.Fatalf("isolated Mutagen data directory is missing or duplicated: %q", joined)
	}
}

func TestCommandRunnerBoundsInheritedOutputPipes(t *testing.T) {
	script := filepath.Join(t.TempDir(), "mutagen")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 4 &\nprintf done\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err := (CommandRunner{Path: script, DataDir: t.TempDir()}).Run(context.Background(), "version")
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("command with inherited output pipe returned %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("inherited command output pipe remained open for %v", elapsed)
	}
}

func TestCommandRunnerOmitsEmptyOutputSeparator(t *testing.T) {
	_, err := (CommandRunner{Path: filepath.Join(t.TempDir(), "missing"), DataDir: t.TempDir()}).Run(context.Background(), "version")
	if err == nil {
		t.Fatal("missing command succeeded")
	}
	if strings.HasSuffix(err.Error(), ":") {
		t.Fatalf("empty command output left a dangling separator: %q", err)
	}
}

func TestCommandRunnerBoundsStructuredOutputAndDiagnosticTail(t *testing.T) {
	t.Run("maximum structured response", func(t *testing.T) {
		script := writeMutagenTestScript(t, `
dd if=/dev/zero bs=1048576 count=16 2>/dev/null
`)
		output, err := (CommandRunner{Path: script, DataDir: t.TempDir()}).Run(context.Background(), "sync", "list")
		if err != nil || len(output) != maxMutagenStateOutputBytes {
			t.Fatalf("maximum output = %d bytes, %v", len(output), err)
		}
	})

	t.Run("structured overflow", func(t *testing.T) {
		script := writeMutagenTestScript(t, `
dd if=/dev/zero bs=1048576 count=17 2>/dev/null
`)
		output, err := (CommandRunner{Path: script, DataDir: t.TempDir()}).Run(context.Background(), "sync", "list")
		if err == nil || !strings.Contains(err.Error(), "16777216-byte limit") {
			t.Fatalf("overflow error = %v", err)
		}
		if len(output) != maxMutagenStateOutputBytes || len(err.Error()) > subprocess.DiagnosticLimit+1024 {
			t.Fatalf("overflow sizes = output %d/error %d", len(output), len(err.Error()))
		}
	})

	t.Run("version limit", func(t *testing.T) {
		script := writeMutagenTestScript(t, `
dd if=/dev/zero bs=65537 count=1 2>/dev/null
`)
		output, err := (CommandRunner{Path: script, DataDir: t.TempDir()}).Run(context.Background(), "version")
		if err == nil || !strings.Contains(err.Error(), "65536-byte limit") || len(output) != maxMutagenVersionOutputBytes {
			t.Fatalf("version output = %d bytes, %v", len(output), err)
		}
	})

	t.Run("management limit", func(t *testing.T) {
		script := writeMutagenTestScript(t, `
dd if=/dev/zero bs=1048577 count=1 2>/dev/null
`)
		output, err := (CommandRunner{Path: script, DataDir: t.TempDir()}).Run(context.Background(), "sync", "flush", "id")
		if err == nil || !strings.Contains(err.Error(), "1048576-byte limit") || len(output) != maxMutagenCommandOutputBytes {
			t.Fatalf("management output = %d bytes, %v", len(output), err)
		}
	})

	t.Run("final diagnostic", func(t *testing.T) {
		script := writeMutagenTestScript(t, `
dd if=/dev/zero bs=1048576 count=1 >&2 2>/dev/null
printf 'final-mutagen-error\n' >&2
exit 9
`)
		_, err := (CommandRunner{Path: script, DataDir: t.TempDir()}).Run(context.Background(), "version")
		if err == nil || !strings.Contains(err.Error(), "[output truncated]") || !strings.HasSuffix(err.Error(), "final-mutagen-error") {
			t.Fatalf("diagnostic error = %q", err)
		}
		if len(err.Error()) > subprocess.DiagnosticLimit+1024 {
			t.Fatalf("diagnostic error length = %d", len(err.Error()))
		}
	})
}

func TestCommandRunnerStartDaemonUsesNormalStartWhenAvailable(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "calls")
	t.Setenv("PWNBRIDGE_TEST_MARKER", marker)
	script := writeMutagenTestScript(t, `
printf '%s\n' "$*" >> "$PWNBRIDGE_TEST_MARKER"
exit 0
`)
	dataDir := filepath.Join(t.TempDir(), "mutagen")
	if err := (CommandRunner{Path: script, DataDir: dataDir}).StartDaemon(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "daemon start\n" {
		t.Fatalf("daemon calls = %q", data)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "daemon.log")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("normal daemon start unexpectedly opened a fallback log: %v", err)
	}
}

func TestCommandRunnerStartDaemonFallback(t *testing.T) {
	script := writeMutagenTestScript(t, `
if [ "$2" = start ]; then
  exit 1
fi
printf 'fallback daemon\n'
`)
	dataDir := filepath.Join(t.TempDir(), "mutagen")
	if err := (CommandRunner{Path: script, DataDir: dataDir}).StartDaemon(context.Background()); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dataDir, "daemon.log")
	waitForTestFileContent(t, logPath, "fallback daemon")
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("daemon log mode = %o", info.Mode().Perm())
	}
}

func TestCommandRunnerStartDaemonHonorsCancellation(t *testing.T) {
	t.Run("already cancelled", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), "run")
		t.Setenv("PWNBRIDGE_TEST_MARKER", marker)
		script := writeMutagenTestScript(t, `
printf invoked > "$PWNBRIDGE_TEST_MARKER"
exit 1
`)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		dataDir := filepath.Join(t.TempDir(), "mutagen")
		err := (CommandRunner{Path: script, DataDir: dataDir}).StartDaemon(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled startup returned %v", err)
		}
		if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("cancelled startup invoked Mutagen: %v", err)
		}
		if _, err := os.Stat(dataDir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("cancelled startup created Mutagen state: %v", err)
		}
	})

	t.Run("deadline during normal start", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), "fallback")
		t.Setenv("PWNBRIDGE_TEST_MARKER", marker)
		script := writeMutagenTestScript(t, `
if [ "$2" = start ]; then
  while :; do :; done
fi
printf fallback > "$PWNBRIDGE_TEST_MARKER"
`)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		started := time.Now()
		err := (CommandRunner{Path: script, DataDir: filepath.Join(t.TempDir(), "mutagen")}).StartDaemon(ctx)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("deadline startup returned %v", err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("deadline startup took %v", elapsed)
		}
		if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("deadline startup launched fallback: %v", err)
		}
	})
}

func TestCommandRunnerStartDaemonRejectsUnsafeLogs(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{name: "symlink", setup: func(t *testing.T, path string) {
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "fifo", setup: func(t *testing.T, path string) {
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "directory", setup: func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "group-readable", setup: func(t *testing.T, path string) {
			if err := os.WriteFile(path, nil, 0o640); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "fallback")
			t.Setenv("PWNBRIDGE_TEST_MARKER", marker)
			script := writeMutagenTestScript(t, `
if [ "$2" = start ]; then
  exit 1
fi
printf fallback > "$PWNBRIDGE_TEST_MARKER"
`)
			dataDir := filepath.Join(t.TempDir(), "mutagen")
			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			test.setup(t, filepath.Join(dataDir, "daemon.log"))
			started := time.Now()
			if err := (CommandRunner{Path: script, DataDir: dataDir}).StartDaemon(context.Background()); err == nil {
				t.Fatal("unsafe daemon log was accepted")
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("unsafe log rejection took %v", elapsed)
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsafe log launched fallback: %v", err)
			}
		})
	}
}

func TestCommandRunnerStartDaemonRejectsUnsafeDataDirectory(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*testing.T) string
	}{
		{name: "non-private", setup: func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "mutagen")
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{name: "symlink", setup: func(t *testing.T) string {
			target := filepath.Join(t.TempDir(), "actual")
			if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "mutagen")
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			return path
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "invoked")
			t.Setenv("PWNBRIDGE_TEST_MARKER", marker)
			script := writeMutagenTestScript(t, `
printf invoked > "$PWNBRIDGE_TEST_MARKER"
exit 0
`)
			err := (CommandRunner{Path: script, DataDir: test.setup(t)}).StartDaemon(context.Background())
			if err == nil || !strings.Contains(err.Error(), "validate Mutagen data directory") {
				t.Fatalf("unsafe data directory returned %v", err)
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsafe data directory invoked Mutagen: %v", err)
			}
		})
	}
}

func TestCommandRunnerStartDaemonRotatesOversizedLog(t *testing.T) {
	script := writeMutagenTestScript(t, `
if [ "$2" = start ]; then
  exit 1
fi
printf 'new daemon log\n'
`)
	dataDir := filepath.Join(t.TempDir(), "mutagen")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dataDir, "daemon.log")
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxMutagenDaemonLogBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := (CommandRunner{Path: script, DataDir: dataDir}).StartDaemon(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitForTestFileContent(t, logPath, "new daemon log")
	previous, err := os.Stat(logPath + ".previous")
	if err != nil {
		t.Fatal(err)
	}
	if previous.Size() != maxMutagenDaemonLogBytes+1 {
		t.Fatalf("rotated log size = %d", previous.Size())
	}
}

func TestCommandRunnerStartDaemonSurfacesRotationAndStartFailures(t *testing.T) {
	t.Run("rotation destination directory", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), "fallback")
		t.Setenv("PWNBRIDGE_TEST_MARKER", marker)
		script := writeMutagenTestScript(t, `
if [ "$2" = start ]; then
  exit 1
fi
printf fallback > "$PWNBRIDGE_TEST_MARKER"
`)
		dataDir := filepath.Join(t.TempDir(), "mutagen")
		if err := os.MkdirAll(filepath.Join(dataDir, "daemon.log.previous"), 0o700); err != nil {
			t.Fatal(err)
		}
		logPath := filepath.Join(dataDir, "daemon.log")
		file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(maxMutagenDaemonLogBytes + 1); err != nil {
			file.Close()
			t.Fatal(err)
		}
		file.Close()
		if err := (CommandRunner{Path: script, DataDir: dataDir}).StartDaemon(context.Background()); err == nil {
			t.Fatal("unsafe rotation succeeded")
		}
		if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed rotation launched fallback: %v", err)
		}
	})

	t.Run("fallback executable disappears", func(t *testing.T) {
		script := writeMutagenTestScript(t, `
if [ "$2" = start ]; then
  rm -- "$0"
  exit 1
fi
`)
		dataDir := filepath.Join(t.TempDir(), "mutagen")
		err := (CommandRunner{Path: script, DataDir: dataDir}).StartDaemon(context.Background())
		if err == nil || !strings.Contains(err.Error(), "start isolated Mutagen daemon process") {
			t.Fatalf("missing executable returned %v", err)
		}
		file, openErr := os.OpenFile(filepath.Join(dataDir, "daemon.log"), os.O_WRONLY|os.O_APPEND, 0)
		if openErr != nil {
			t.Fatalf("daemon log descriptor remained unusable: %v", openErr)
		}
		file.Close()
	})
}

func TestCommandRunnerStartDaemonRejectsChangedLongPathAlias(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), strings.Repeat("long-path-", 14))
	unsafeTarget := t.TempDir()
	t.Setenv("PWNBRIDGE_TEST_ALIAS_TARGET", unsafeTarget)
	script := writeMutagenTestScript(t, `
if [ "$2" = start ]; then
  rm -- "$MUTAGEN_DATA_DIRECTORY"
  ln -s "$PWNBRIDGE_TEST_ALIAS_TARGET" "$MUTAGEN_DATA_DIRECTORY"
  exit 1
fi
printf fallback
`)
	runner := CommandRunner{Path: script, DataDir: dataDir}
	alias, err := runner.effectiveDataDir()
	if err != nil {
		t.Fatal(err)
	}
	if alias == dataDir {
		t.Fatal("test data directory did not require an alias")
	}
	t.Cleanup(func() { _ = os.Remove(alias) })
	if err := runner.StartDaemon(context.Background()); err == nil || !strings.Contains(err.Error(), "unsafe Mutagen data alias") {
		t.Fatalf("changed alias returned %v", err)
	}
	for _, path := range []string{filepath.Join(dataDir, "daemon.log"), filepath.Join(unsafeTarget, "daemon.log")} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("changed alias opened %s: %v", path, err)
		}
	}
}

func writeMutagenTestScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mutagen")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func waitForTestFileContent(t *testing.T, path, expected string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil && strings.Contains(string(data), expected) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	data, err := os.ReadFile(path)
	t.Fatalf("%s never contained %q: %q, %v", path, expected, data, err)
}

func FuzzMutagenHealthJSON(f *testing.F) {
	f.Add([]byte(`{"paused":false,"status":"watching","conflicts":[]}`))
	f.Add([]byte(`{"status":"disconnected","lastError":"network"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var value any
		if json.Unmarshal(data, &value) != nil {
			return
		}
		_ = inspectHealth(value)
		_ = ConflictPaths(value)
	})
}
