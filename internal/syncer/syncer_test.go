package syncer

import (
	"context"
	"encoding/json"
	"errors"
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
