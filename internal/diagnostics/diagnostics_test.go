package diagnostics

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/simonfalke-01/pwnbridge/internal/bootstrap"
	"github.com/simonfalke-01/pwnbridge/internal/syncer"
)

type versionRunner struct{}

func (versionRunner) Run(context.Context, ...string) ([]byte, error) {
	return []byte("0.18.1\n"), nil
}

func TestReportNormalizesHostileDetailAndCompleteness(t *testing.T) {
	hostile := "safe\nforged\x1b[2J\x1b]0;title\a\u202e" + strings.Repeat("x", 600)
	report := NewReport([]Check{{Name: "remote", OK: true, Detail: hostile}}, true)
	if !report.OK || !report.Complete {
		t.Fatalf("healthy report = %#v", report)
	}
	detail := report.Checks[0].Detail
	if strings.ContainsAny(detail, "\r\n\x1b") || strings.Contains(detail, "\u202e") || len(detail) > maxDetailBytes || !strings.HasSuffix(detail, "…") {
		t.Fatalf("unsafe normalized detail %q (%d bytes)", detail, len(detail))
	}
	report = NewReport(report.Checks, false)
	if report.OK || report.Complete {
		t.Fatalf("incomplete report = %#v", report)
	}
}

func TestFailureClassifiesContextErrors(t *testing.T) {
	for _, test := range []struct {
		err   error
		state string
	}{
		{nil, "failed"},
		{context.DeadlineExceeded, "timeout"},
		{context.Canceled, "cancelled"},
		{errors.New("broken"), "failed"},
	} {
		check := Failure("probe", test.err, "fix it", 3*time.Second)
		if check.OK || check.State != test.state || check.Severity != "error" {
			t.Fatalf("failure check = %#v", check)
		}
	}
}

func TestRenderUsesOneSafeWriteAndPropagatesFailure(t *testing.T) {
	report := NewReport([]Check{{Name: "one", OK: true, Detail: "ready"}, {Name: "two", OK: false, Detail: "missing", Remediation: "install it"}}, true)
	var output bytes.Buffer
	if err := Render(&output, report); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"ok    one", "FAIL  two", "fix: install it", "FAIL  doctor (complete)"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("doctor output missing %q: %q", expected, output.String())
		}
	}
	if err := Render(errorWriter{}, report); err == nil {
		t.Fatal("render ignored output failure")
	}
	output.Reset()
	if err := RenderStatus(&output, report, "host check"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "FAIL  host check (complete)") || strings.Contains(output.String(), "doctor") {
		t.Fatalf("labeled report output = %q", output.String())
	}
}

func TestRegistrationTreatsInstallableWorkAsPendingAndBlockersAsFailures(t *testing.T) {
	inventory := bootstrap.Inventory{
		Host: "pwnbox", OS: "linux", Architecture: "amd64", Distro: "debian", DistroVersion: "13",
		PackageManager: bootstrap.ManagerAPT, DiskAvailableKiB: 2 * 1024 * 1024, InodesAvailable: 2000,
		HomeWritable: true, SudoAvailable: true, PtraceScope: "1", Tools: map[string]bool{},
	}
	recipe, ok := bootstrap.BuiltinRecipe("minimal")
	if !ok {
		t.Fatal("minimal recipe unavailable")
	}
	plan, err := bootstrap.BuildPlan(inventory, recipe, nil, bootstrap.PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	report := NewReport(Registration(inventory, plan), true)
	if !report.OK {
		t.Fatalf("installable pending plan was rejected: %#v", report)
	}
	var planCheck Check
	for _, check := range report.Checks {
		if check.Name == "bootstrap-plan" {
			planCheck = check
		}
	}
	if !planCheck.OK || planCheck.State != "ready" || !strings.Contains(planCheck.Detail, "pending_actions=") {
		t.Fatalf("bootstrap readiness = %#v", planCheck)
	}

	plan.Blockers = append(plan.Blockers, "synthetic blocker")
	report = NewReport(Registration(inventory, plan), true)
	if report.OK {
		t.Fatalf("blocked plan was accepted: %#v", report)
	}
	plan.Blockers = nil
	inventory.PtraceScope = "3"
	report = NewReport(Registration(inventory, plan), true)
	if report.OK {
		t.Fatalf("blocked ptrace policy was accepted: %#v", report)
	}
}

func FuzzDiagnosticDetail(f *testing.F) {
	f.Add("ordinary detail")
	f.Add("safe\nforged\x1b[2J\x1b]0;title\a")
	f.Fuzz(func(t *testing.T, value string) {
		report := NewReport([]Check{{Name: "probe", OK: true, Detail: value, Remediation: value}}, true)
		detail, remediation := report.Checks[0].Detail, report.Checks[0].Remediation
		if len(detail) > maxDetailBytes || len(remediation) > maxRemediationBytes {
			t.Fatalf("normalized diagnostic exceeded bounds")
		}
		for _, normalized := range []string{detail, remediation} {
			if !utf8.ValidString(normalized) || strings.ContainsAny(normalized, "\r\n\x1b") {
				t.Fatalf("normalized diagnostic retained unsafe text %q", normalized)
			}
			for _, r := range normalized {
				if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
					t.Fatalf("normalized diagnostic retained control rune %U", r)
				}
			}
		}
		if err := Render(io.Discard, report); err != nil {
			t.Fatal(err)
		}
	})
}

func BenchmarkDoctorReport32Checks(b *testing.B) {
	checks := make([]Check, 32)
	for index := range checks {
		checks[index] = Check{Name: "remote-tool", OK: index%3 != 0, Detail: "available=false\x1b[2J", Remediation: "run pwnbridge host bootstrap"}
	}
	for b.Loop() {
		report := NewReport(checks, true)
		if err := Render(io.Discard, report); err != nil {
			b.Fatal(err)
		}
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestLocalReportsMissingConflictDiffUtility(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	checks := Local(context.Background(), syncer.Mutagen{Runner: versionRunner{}}, "ssh")
	for _, check := range checks {
		if check.Name == "diff" {
			if check.OK || check.Remediation == "" {
				t.Fatalf("diff check = %#v", check)
			}
			return
		}
	}
	t.Fatal("local diagnostics omitted diff")
}
