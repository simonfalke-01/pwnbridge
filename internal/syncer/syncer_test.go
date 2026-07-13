package syncer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
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
