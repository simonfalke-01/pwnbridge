package cli

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simonfalke-01/pwnbridge/internal/broker"
	"github.com/simonfalke-01/pwnbridge/internal/config"
	"github.com/simonfalke-01/pwnbridge/internal/protocol"
	"github.com/simonfalke-01/pwnbridge/internal/workspace"
)

func configureRemovalHosts(t *testing.T, app *App, defaultHost string) {
	t.Helper()
	effective := config.Defaults()
	effective.Global.Hosts["keep"] = config.Host{
		Destination: "keep.example", Platform: "linux/amd64", WorkspaceRoot: "~/.local/share/pwnbridge/workspaces", BootstrapProfile: "pwn", ShellTransport: "auto", MoshPort: "60000:61000",
	}
	effective.Global.Hosts["retire"] = config.Host{
		Destination: "retire.example", Platform: "linux/amd64", WorkspaceRoot: "~/.local/share/pwnbridge/workspaces", BootstrapProfile: "pwn", ShellTransport: "auto", MoshPort: "60000:61000",
	}
	effective.Global.DefaultHost = defaultHost
	if err := config.SaveGlobal(filepath.Join(app.Paths.Config, "config.toml"), effective.Global); err != nil {
		t.Fatal(err)
	}
}

func TestHostRemoveRequiresPreviewOrConfirmationAndProtectsDefault(t *testing.T) {
	app, output := testApp(t)
	configureRemovalHosts(t, app, "retire")
	for _, args := range [][]string{
		{"host", "remove", "retire"},
		{"host", "remove", "retire", "--dry-run", "--yes"},
	} {
		if err := execute(t, app, args...); err == nil || !strings.Contains(err.Error(), "exactly one") {
			t.Fatalf("invalid confirmation grammar %q = %v", args, err)
		}
	}
	output.Reset()
	if err := execute(t, app, "host", "remove", "retire", "--dry-run"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "machine-wide default") || !strings.Contains(output.String(), "resolve references") {
		t.Fatalf("default preview = %s", output)
	}
	output.Reset()
	if err := execute(t, app, "host", "remove", "retire", "--yes"); err == nil || !strings.Contains(err.Error(), "still referenced") {
		t.Fatalf("default removal was not blocked: %v", err)
	}
	effective, err := config.LoadGlobal(app.Paths)
	if err != nil || effective.Global.DefaultHost != "retire" {
		t.Fatalf("blocked removal changed config: default=%q err=%v", effective.Global.DefaultHost, err)
	}
	output.Reset()
	if err := execute(t, app, "host", "remove", "retire", "--force", "--yes"); err != nil {
		t.Fatalf("explicit forced default removal failed: %v", err)
	}
	effective, err = config.LoadGlobal(app.Paths)
	if err != nil || effective.Global.DefaultHost != "" {
		t.Fatalf("forced default removal did not clear default: %q, %v", effective.Global.DefaultHost, err)
	}
	if _, ok := effective.Global.Hosts["retire"]; ok {
		t.Fatal("forced default removal retained host")
	}
}

func TestHostRemoveInventoriesAndPreservesForcedReferences(t *testing.T) {
	app, output := testApp(t)
	configureRemovalHosts(t, app, "keep")
	projectRoot := filepath.Join(t.TempDir(), "challenge\nname")
	if err := os.Mkdir(projectRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	manager := workspace.Manager{Paths: app.Paths}
	if err := manager.SetBinding(projectRoot, "retire"); err != nil {
		t.Fatal(err)
	}
	ws, err := manager.Resolve(projectRoot, "retire", "~/.local/share/pwnbridge/workspaces")
	if err != nil {
		t.Fatal(err)
	}
	state, err := manager.LoadState(ws)
	if err != nil {
		t.Fatal(err)
	}
	state.RemoteRetained = true
	state.MutagenIdentifier = "sync_0123456789abcdef0123456789abcdef"
	if err := manager.SaveState(ws, state); err != nil {
		t.Fatal(err)
	}
	recoveryRoot := filepath.Join(app.Paths.Data, "recovery", ws.ID)
	if err := os.MkdirAll(recoveryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(recoveryRoot, "archive"), []byte("valuable"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := execute(t, app, "host", "remove", "retire", "--dry-run", "--json"); err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Schema int               `json:"schema"`
		Data   hostRemovalReport `json:"data"`
	}
	if err := json.Unmarshal(output.Bytes(), &envelope); err != nil {
		t.Fatalf("decode preview: %v\n%s", err, output)
	}
	if envelope.Schema != 1 || envelope.Data.Safe || envelope.Data.Allowed || len(envelope.Data.Bindings) != 1 || len(envelope.Data.Workspaces) != 1 || !envelope.Data.Workspaces[0].RecoveryPresent {
		t.Fatalf("preview report = %#v", envelope)
	}
	effective, err := config.LoadGlobal(app.Paths)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := effective.Global.Hosts["retire"]; !ok {
		t.Fatal("dry-run removed the host")
	}

	output.Reset()
	if err := execute(t, app, "host", "remove", "retire", "--yes"); err == nil {
		t.Fatal("referenced host was removed without force")
	}
	output.Reset()
	if err := execute(t, app, "host", "remove", "retire", "--force", "--yes"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "challenge\nname") || !strings.Contains(output.String(), `challenge\nname`) || !strings.Contains(output.String(), "same name") {
		t.Fatalf("forced output was unsafe or unclear: %q", output.String())
	}
	effective, err = config.LoadGlobal(app.Paths)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := effective.Global.Hosts["retire"]; ok {
		t.Fatal("forced removal retained global host")
	}
	if bound, err := manager.Binding(projectRoot); err != nil || bound != "retire" {
		t.Fatalf("forced removal destroyed binding: %q, %v", bound, err)
	}
	if _, err := manager.LoadState(ws); err != nil {
		t.Fatalf("forced removal destroyed workspace state: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(recoveryRoot, "archive")); err != nil || string(data) != "valuable" {
		t.Fatalf("forced removal destroyed recovery: %q, %v", data, err)
	}
}

func TestHostRemoveBlocksUnattributedRecoveryButForceCanPreserveIt(t *testing.T) {
	app, output := testApp(t)
	configureRemovalHosts(t, app, "keep")
	orphan := filepath.Join(app.Paths.Data, "recovery", "0123456789abcdef")
	if err := os.MkdirAll(orphan, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orphan, "copy"), []byte("unknown"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := execute(t, app, "host", "remove", "retire", "--dry-run"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "host=unknown") || !strings.Contains(output.String(), "cannot be attributed") {
		t.Fatalf("orphan preview = %s", output)
	}
	output.Reset()
	if err := execute(t, app, "host", "remove", "retire", "--force", "--yes"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(orphan, "copy")); err != nil {
		t.Fatalf("forced removal deleted orphan recovery: %v", err)
	}
}

func TestHostRemoveNeverOverridesLiveSession(t *testing.T) {
	app, output := testApp(t)
	configureRemovalHosts(t, app, "keep")
	projectRoot := t.TempDir()
	manager := workspace.Manager{Paths: app.Paths}
	ws, err := manager.Resolve(projectRoot, "retire", "~/.local/share/pwnbridge/workspaces")
	if err != nil {
		t.Fatal(err)
	}
	state, err := manager.LoadState(ws)
	if err != nil {
		t.Fatal(err)
	}
	state.RemoteRetained = true
	if err := manager.SaveState(ws, state); err != nil {
		t.Fatal(err)
	}
	sessionID := "abcdef0123456789"
	recordPath := filepath.Join(app.Paths.State, "sessions", sessionID+".json")
	leasePath := recordPath + ".lease"
	remoteSession := "/tmp/pwnbridge-session"
	record := broker.SessionRecord{
		OwnerPID: os.Getpid(), ID: sessionID, Token: strings.Repeat("a", 64),
		RemoteSessionDir: remoteSession, LocalWorkspace: ws.LocalRoot,
		RecordPath: recordPath, LeasePath: leasePath,
		Runtime: protocol.RuntimeSpec{Kind: "host", Workspace: ws.RemotePath, WorkspaceID: ws.ID, SessionDir: remoteSession},
	}
	if err := broker.SaveSession(recordPath, record); err != nil {
		t.Fatal(err)
	}
	lease, err := workspace.AcquireLock(leasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if err := execute(t, app, "host", "remove", "retire", "--force", "--yes"); err == nil || !strings.Contains(err.Error(), "live session") {
		t.Fatalf("live session was overridden: %v", err)
	}
	if !strings.Contains(output.String(), "cannot be overridden") || !strings.Contains(output.String(), "active_sessions=1") {
		t.Fatalf("live session report = %s", output)
	}
	effective, err := config.LoadGlobal(app.Paths)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := effective.Global.Hosts["retire"]; !ok {
		t.Fatal("live-session refusal removed host")
	}
}

func TestHostRemoveSafePathIgnoresProjectConfigAndOutputFailure(t *testing.T) {
	app, output := testApp(t)
	configureRemovalHosts(t, app, "keep")
	cwd := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	if err := os.WriteFile(filepath.Join(cwd, ".pwnbridge.toml"), []byte("not valid toml = ["), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := execute(t, app, "host", "remove", "retire", "--dry-run"); err != nil {
		t.Fatalf("project config affected global preview: %v", err)
	}
	if !strings.Contains(output.String(), "ready") {
		t.Fatalf("safe preview = %s", output)
	}
	app.Out = hostRemovalFailWriter{}
	if err := execute(t, app, "host", "remove", "retire", "--dry-run"); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("preview output failure = %v", err)
	}
	effective, err := config.LoadGlobal(app.Paths)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := effective.Global.Hosts["retire"]; !ok {
		t.Fatal("failed preview output removed host")
	}
	app.Out = output
	output.Reset()
	if err := execute(t, app, "host", "remove", "retire", "--yes"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "removed host retire") {
		t.Fatalf("safe confirmed output = %s", output)
	}
}

func TestHostRemoveFailsClosedOnUnsafeCatalog(t *testing.T) {
	app, _ := testApp(t)
	configureRemovalHosts(t, app, "keep")
	bindingRoot := filepath.Join(app.Paths.State, "bindings")
	if err := os.MkdirAll(bindingRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bindingRoot, "0123456789abcdef.json"), []byte(`{"schema":2,"host_id":"retire","local_root":"/tmp/project"}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := execute(t, app, "host", "remove", "retire", "--force", "--yes"); err == nil || !strings.Contains(err.Error(), "owner-private") {
		t.Fatalf("unsafe catalog did not fail closed: %v", err)
	}
	effective, err := config.LoadGlobal(app.Paths)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := effective.Global.Hosts["retire"]; !ok {
		t.Fatal("unsafe catalog failure removed host")
	}
}

func TestSaveCleanedWorkspaceRetainsOnlyRequiredLifecycleState(t *testing.T) {
	app, _ := testApp(t)
	projectRoot := t.TempDir()
	manager := workspace.Manager{Paths: app.Paths}
	ws, err := manager.Resolve(projectRoot, "retire", "~/.local/share/pwnbridge/workspaces")
	if err != nil {
		t.Fatal(err)
	}
	project := &projectContext{Manager: manager, WS: ws, State: workspace.State{
		RemoteRetained: true, MutagenIdentifier: "sync_0123456789abcdef0123456789abcdef",
		SyncFingerprint: strings.Repeat("a", 64), RuntimeID: "runtime-1",
	}}
	if err := saveCleanedWorkspace(project, false); err != nil {
		t.Fatal(err)
	}
	state, err := manager.LoadState(ws)
	if err != nil {
		t.Fatal(err)
	}
	if !state.RemoteRetained || state.MutagenIdentifier != "" || state.SyncFingerprint != "" || state.RuntimeID != "" {
		t.Fatalf("local clean state = %#v", state)
	}
	project.State = state
	if err := saveCleanedWorkspace(project, true); err != nil {
		t.Fatal(err)
	}
	state, err = manager.LoadState(ws)
	if err != nil || state.RemoteRetained {
		t.Fatalf("remote clean state = %#v, %v", state, err)
	}
}

type hostRemovalFailWriter struct{}

func (hostRemovalFailWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
