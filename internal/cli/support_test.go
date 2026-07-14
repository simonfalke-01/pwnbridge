package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/bootstrap"
	"github.com/simonfalke-01/pwnbridge/internal/config"
	"github.com/simonfalke-01/pwnbridge/internal/diagnostics"
	"github.com/simonfalke-01/pwnbridge/internal/recovery"
	"github.com/simonfalke-01/pwnbridge/internal/support"
	"github.com/simonfalke-01/pwnbridge/internal/syncer"
	"github.com/simonfalke-01/pwnbridge/internal/workspace"
)

func TestSupportReportOmitsSensitiveConfiguration(t *testing.T) {
	const (
		secretHost        = "private-host"
		secretDestination = "account@private.example"
		secretRemoteRoot  = "/private/remote/root"
		secretIgnore      = "private-flag.txt"
		secretEnvKey      = "CHALLENGE_SECRET"
		secretEnvValue    = "flag-value-never-share"
		secretProvider    = "private-provider"
		secretImage       = "private.registry/challenge-image"
		secretMutagen     = "/private/bin/mutagen"
		secretAgent       = "/private/bin/pwnbridge-agent"
		secretLogLevel    = "SECRET_LOG_LEVEL"
		secretNetwork     = "private-network-name"
	)
	app, output := testApp(t)
	if err := app.Paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	effective := config.Defaults()
	effective.Global.DefaultHost = secretHost
	effective.Global.Hosts[secretHost] = config.Host{Destination: secretDestination, Platform: "linux/amd64", WorkspaceRoot: secretRemoteRoot, ShellTransport: "ssh"}
	effective.Global.Terminal.Provider = "custom:" + secretProvider
	globalPath := filepath.Join(app.Paths.Config, "config.toml")
	if err := config.SaveGlobal(globalPath, effective.Global); err != nil {
		t.Fatal(err)
	}
	projectRoot := t.TempDir()
	projectData := "schema = 1\ntarget = \"linux/amd64\"\n\n[workspace]\nroot = \".\"\nignore = [\"" + secretIgnore + "\"]\n\n[environment]\nprofile = \"pwn\"\nset = { " + secretEnvKey + " = \"" + secretEnvValue + "\" }\n\n[shell]\ncommand = \"bash\"\nsource_user_rc = true\n\n[runtime]\nkind = \"container\"\n\n[runtime.container]\nengine = \"docker\"\nimage = \"" + secretImage + "\"\nworkdir = \"/work\"\nnetwork = \"" + secretNetwork + "\"\n"
	if err := os.WriteFile(filepath.Join(projectRoot, ".pwnbridge.toml"), []byte(projectData), 0o600); err != nil {
		t.Fatal(err)
	}
	old, _ := os.Getwd()
	if err := os.Chdir(projectRoot); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	t.Setenv("PWNBRIDGE_CONFIG", globalPath)
	t.Setenv("PWNBRIDGE_MUTAGEN_PATH", secretMutagen)
	t.Setenv("PWNBRIDGE_AGENT_PATH", secretAgent)
	t.Setenv("PWNBRIDGE_LOG", secretLogLevel)
	if err := execute(t, app, "support", "--local-only", "--json"); err != nil {
		t.Fatal(err)
	}
	assertSupportSecretsAbsent(t, output.String(), []string{
		secretHost, secretDestination, secretRemoteRoot, secretIgnore, secretEnvKey, secretEnvValue,
		secretProvider, secretImage, secretMutagen, secretAgent, secretLogLevel, secretNetwork, projectRoot,
	})
	if !strings.Contains(output.String(), `"terminal_provider": "custom"`) || !strings.Contains(output.String(), `"container_network": "custom"`) || !strings.Contains(output.String(), `"environment_variable_count": 1`) {
		t.Fatalf("safe configuration summary missing:\n%s", output.String())
	}
	output.Reset()
	if err := execute(t, app, "support", "--local-only"); err != nil {
		t.Fatal(err)
	}
	assertSupportSecretsAbsent(t, output.String(), []string{
		secretHost, secretDestination, secretRemoteRoot, secretIgnore, secretEnvKey, secretEnvValue,
		secretProvider, secretImage, secretMutagen, secretAgent, secretLogLevel, secretNetwork, projectRoot,
	})
}

func TestSupportBuildMetadataUsesNarrowGrammars(t *testing.T) {
	for _, release := range []string{"v0.1.13", "0.2.0-rc.1", "0.1.13-SNAPSHOT-69fac0a"} {
		if supportReleaseVersion(release) != release {
			t.Fatalf("release version %q was rejected", release)
		}
	}
	for _, value := range []string{"private-host", "0.1.13-private-host", "0.1.13-SNAPSHOT-privatehost"} {
		if supportReleaseVersion(value) != "unavailable" {
			t.Fatalf("private release value %q was accepted", value)
		}
	}
	if supportReleaseVersion("0.1.13-alpha.1") != "0.1.13-alpha.1" {
		t.Fatal("release version grammar is too broad")
	}
	if supportCommit("69FAC0A") != "69fac0a" || supportCommit("private-host") != "unavailable" {
		t.Fatal("commit grammar is too broad")
	}
	if supportBuildDate("2026-07-14T12:00:00+02:00") != "2026-07-14T10:00:00Z" || supportBuildDate("private-host") != "unavailable" {
		t.Fatal("build date grammar is too broad")
	}
	if supportGoVersion("go1.25.12") != "go1.25.12" || supportGoVersion("devel go1.25-private-host") != "unavailable" {
		t.Fatal("Go version grammar is too broad")
	}
}

func FuzzSupportReleaseVersion(f *testing.F) {
	for _, seed := range []string{"dev", "v0.1.13", "0.2.0-rc.1", "0.1.13-SNAPSHOT-69fac0a", "private-host", "0.1.13-SNAPSHOT-privatehost", "\x1b[2J"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		got := supportReleaseVersion(value)
		if got == "unavailable" {
			return
		}
		if got != value || len(got) > 64 || strings.ContainsAny(got, "/@:\x00\r\n\x1b") {
			t.Fatalf("unsafe release version %q produced %q", value, got)
		}
	})
}

func TestSupportCapabilitiesRejectUnknownLabels(t *testing.T) {
	capabilities := supportCapabilities([]diagnostics.Check{
		{Name: "ssh", OK: true},
		{Name: "SECRET_CAPABILITY_LABEL", OK: true},
	})
	if len(capabilities) != 1 || capabilities[0].Name != "ssh" {
		t.Fatalf("capabilities = %#v", capabilities)
	}
}

func TestSupportReportSurvivesInvalidConfiguration(t *testing.T) {
	app, output := testApp(t)
	path := filepath.Join(t.TempDir(), "private-config.toml")
	const secret = "SECRET_INVALID_CONFIG_VALUE"
	if err := os.WriteFile(path, []byte("unknown = \""+secret+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PWNBRIDGE_CONFIG", path)
	t.Setenv("PATH", t.TempDir())
	if err := execute(t, app, "support", "--local-only", "--json"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), secret) || strings.Contains(output.String(), path) {
		t.Fatalf("invalid config details leaked:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"readable": false`) || !strings.Contains(output.String(), `"error_category": "invalid"`) {
		t.Fatalf("partial invalid-config report missing:\n%s", output.String())
	}
}

func TestSupportLocalOnlyDoesNotInvokeSSH(t *testing.T) {
	app, _ := testApp(t)
	directory := t.TempDir()
	marker := filepath.Join(directory, "ssh-was-run")
	commands := map[string]string{
		"ssh":     "#!/bin/sh\ntouch \"" + marker + "\"\nexit 99\n",
		"scp":     "#!/bin/sh\nexit 0\n",
		"diff":    "#!/bin/sh\nexit 0\n",
		"mutagen": "#!/bin/sh\nprintf '0.18.1\\n'\n",
	}
	for name, script := range commands {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", directory)
	projectRoot := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(projectRoot); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	if err := execute(t, app, "host", "add", "selected", "fake-destination"); err != nil {
		t.Fatal(err)
	}
	if err := execute(t, app, "support", "--local-only"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("--local-only invoked SSH: %v", err)
	}
}

func TestSupportRemoteFailureIsCategorizedWithoutRawError(t *testing.T) {
	const secret = "SECRET_SSH_DESTINATION_AND_ERROR"
	app, output := testApp(t)
	directory := t.TempDir()
	commands := map[string]string{
		"ssh":     "#!/bin/sh\nprintf '" + secret + "\\n' >&2\nexit 42\n",
		"scp":     "#!/bin/sh\nexit 0\n",
		"diff":    "#!/bin/sh\nexit 0\n",
		"mutagen": "#!/bin/sh\nprintf '0.18.1\\n'\n",
	}
	for name, script := range commands {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", directory)
	root := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	if err := execute(t, app, "host", "add", "selected", secret); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := execute(t, app, "support", "--json"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), secret) || !strings.Contains(output.String(), `"requested": true`) || !strings.Contains(output.String(), `"error_category": "unavailable"`) {
		t.Fatalf("remote failure was not safely categorized:\n%s", output.String())
	}
}

func TestSupportRemoteInventoryRejectsHostileFreeText(t *testing.T) {
	const secret = "SECRET_REMOTE_SENTINEL"
	report := supportRemote(bootstrap.Inventory{
		OS: secret, Architecture: secret, Distro: secret, DistroVersion: secret,
		PackageManager: bootstrap.Manager(secret), Libc: secret, ServiceManager: secret,
		PtraceScope: secret, PwntoolsVersion: secret, PwndbgVersion: secret,
		Tools: map[string]bool{secret: true, "gdb": true},
	})
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) || !strings.Contains(string(data), `"name":"gdb","available":true`) {
		t.Fatalf("hostile remote inventory was exposed or safe tools omitted: %s", data)
	}
}

type supportStatusRunner struct{}

func (supportStatusRunner) Run(context.Context, ...string) ([]byte, error) {
	return []byte(`{"status":"SECRET_SYNC_STATUS","conflicts":[{"path":"SECRET_CONFLICT_PATH"}]}`), nil
}

func TestSupportWorkspaceOmitsSyncAndRecoveryNames(t *testing.T) {
	const (
		secretConflict = "SECRET_CONFLICT_PATH"
		secretRecovery = "SECRET_RECOVERY_ORIGINAL"
		secretStatus   = "SECRET_SYNC_STATUS"
	)
	recoveryRoot := t.TempDir()
	archive := recovery.ArchiveName(time.Now())
	id, err := recovery.BackupID(archive, "local", secretRecovery)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Join(recoveryRoot, id)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(recoveryRoot, id), []byte("artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Record(recoveryRoot, archive, "local", secretRecovery); err != nil {
		t.Fatal(err)
	}
	app, _ := testApp(t)
	project := &projectContext{
		WS:    workspace.Workspace{RecoveryPath: recoveryRoot},
		State: workspace.State{MutagenIdentifier: "sync_0123456789abcdef0123456789abcdef"},
		Sync:  syncer.Mutagen{Runner: supportStatusRunner{}},
	}
	report := app.supportWorkspace(context.Background(), project)
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{secretConflict, secretRecovery, secretStatus} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("support workspace leaked %q: %s", secret, data)
		}
	}
	if report.Recovery.Entries != 1 || report.Recovery.Verified != 1 || report.Sync == nil || report.Sync.State != "unhealthy" {
		t.Fatalf("safe workspace summary = %#v", report)
	}
}

func assertSupportSecretsAbsent(t *testing.T, output string, values []string) {
	t.Helper()
	for _, value := range values {
		if strings.Contains(output, value) {
			t.Fatalf("support report contains forbidden value %q:\n%s", value, output)
		}
	}
}

func TestSupportReportUsesStandardSchema(t *testing.T) {
	app, output := testApp(t)
	command, _, err := app.Root().Find([]string{"support"})
	if err != nil || command.Name() != "support" {
		t.Fatalf("support command = %v, %v", command, err)
	}
	root := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	if err := execute(t, app, "support", "--local-only", "--json"); err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Schema int            `json:"schema"`
		Data   support.Report `json:"data"`
	}
	if err := json.Unmarshal(output.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Schema != support.Schema || envelope.Data.Privacy.Mode != "positive-allowlist" || !envelope.Data.Privacy.ReviewBeforeSharing {
		t.Fatalf("support envelope = %#v", envelope)
	}
}
