package support

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func TestErrorCategory(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{context.DeadlineExceeded, "timeout"},
		{context.Canceled, "canceled"},
		{os.ErrPermission, "permission"},
		{os.ErrNotExist, "not-found"},
		{errors.New("SECRET raw error"), "unavailable"},
	}
	for _, test := range tests {
		if got := ErrorCategory(test.err); got != test.want {
			t.Fatalf("ErrorCategory(%v) = %q, want %q", test.err, got, test.want)
		}
	}
}

func TestRenderIsDeterministicAndPropagatesWriteFailure(t *testing.T) {
	report := NewReport(Client{Version: "dev", Commit: "unknown", BuildDate: "unknown", Protocol: 4, GlobalConfigSchema: 2, ProjectConfigSchema: 1, RequiredMutagen: "0.18.1", GoVersion: "go1.25.12", OS: "darwin", Architecture: "arm64"})
	report.Configuration = Configuration{Readable: true, HostCount: 1, HostSelected: true, SelectedHostAvailable: true, LogLevel: "info"}
	report.Local = []Capability{{Name: "ssh", Available: true}}
	var first, second bytes.Buffer
	if err := Render(&first, report); err != nil {
		t.Fatal(err)
	}
	if err := Render(&second, report); err != nil || first.String() != second.String() {
		t.Fatalf("render is not deterministic: %v", err)
	}
	if !strings.Contains(first.String(), "review before sharing") || !strings.Contains(first.String(), "tokens") {
		t.Fatalf("privacy notice missing:\n%s", first.String())
	}
	if err := Render(failingWriter{}, report); err == nil {
		t.Fatal("output failure was ignored")
	}
}

func TestRenderFullReportAndPartialFailures(t *testing.T) {
	report := NewReport(Client{Version: "v0.1.13", Commit: "69fac0a", BuildDate: "2026-07-14T10:00:00Z", Protocol: 4, GlobalConfigSchema: 2, ProjectConfigSchema: 1, RequiredMutagen: "0.18.1", GoVersion: "go1.25.12", OS: "darwin", Architecture: "arm64"})
	report.Configuration = Configuration{Readable: true, ProjectFile: true, HostCount: 2, HostSelected: true, SelectedHostAvailable: true, BootstrapProfileCount: 1, LogLevel: "info"}
	report.Project = &Project{
		Target: "linux/amd64", Runtime: "container", ContainerEngine: "podman", ContainerNetwork: "custom",
		TerminalProvider: "zellij", TerminalScope: "host", TerminalPlacement: "right", ShellTransport: "mosh",
		SourceUserRC: true, WorkspaceIgnoreCount: 2, EnvironmentVariableCount: 1,
		Sync: SyncConfig{Mode: "two-way-safe", WatchMode: "portable", SymlinkMode: "portable", PauseOnIdle: true, BarrierTimeout: "2m0s"},
	}
	report.Workspace = &Workspace{
		Available: true, SyncCreated: true,
		Sync:     &SyncState{Available: true, Healthy: true, State: "healthy", ProblemCount: 1, ConflictCount: 2},
		Recovery: RecoverySummary{Available: true, Entries: 3, Verified: 2, Unverified: 1, Legacy: 1, Bytes: 4096},
	}
	report.Local = []Capability{{Name: "ssh", Available: true}}
	report.Remote = Remote{
		Requested: true, Available: true, OS: "linux", Architecture: "amd64", Distro: "debian", DistroVersion: "12",
		PackageManager: "apt", Libc: "glibc", ServiceManager: "systemd", DiskAvailableKiB: 2048, InodesAvailable: 1024,
		HomeWritable: true, SudoAvailable: true, PtraceScope: "1", PwntoolsVersion: "4.15.0", PwndbgVersion: "2026.02.18",
		Tools: []Capability{{Name: "gdb", Available: true}},
	}
	var output bytes.Buffer
	if err := Render(&output, report); err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{
		"Project: target=linux/amd64 runtime=container", "Execution: shell_transport=mosh container_engine=podman container_network=custom",
		"Sync state: available=true healthy=true", "Recovery: available=true entries=3", "Remote: available=true platform=linux/amd64",
		"- remote-gdb: available=true", "Excluded by design:",
	} {
		if !strings.Contains(output.String(), wanted) {
			t.Fatalf("full report missing %q:\n%s", wanted, output.String())
		}
	}

	report.Project = &Project{Target: "linux/amd64", Runtime: "host", TerminalProvider: "auto", TerminalScope: "host", TerminalPlacement: "right"}
	report.Configuration = Configuration{ErrorCategory: "invalid"}
	report.Workspace = &Workspace{ErrorCategory: "permission", SyncCreated: true, Sync: &SyncState{ErrorCategory: "timeout"}, Recovery: RecoverySummary{ErrorCategory: "not-found"}}
	report.Remote = Remote{Requested: true, ErrorCategory: "unavailable"}
	output.Reset()
	if err := Render(&output, report); err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{"error=invalid", "error=permission", "error=timeout", "error=not-found", "Remote: available=false error=unavailable"} {
		if !strings.Contains(output.String(), wanted) {
			t.Fatalf("partial report missing %q:\n%s", wanted, output.String())
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func BenchmarkRender(b *testing.B) {
	report := NewReport(Client{Version: "dev", Protocol: 4, GoVersion: "go1.25.12", OS: "darwin", Architecture: "arm64"})
	report.Local = []Capability{{Name: "ssh", Available: true}, {Name: "mutagen", Available: true}}
	for b.Loop() {
		if err := Render(io.Discard, report); err != nil {
			b.Fatal(err)
		}
	}
}
