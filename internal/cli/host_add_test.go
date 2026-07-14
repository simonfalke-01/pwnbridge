package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/config"
	"github.com/simonfalke-01/pwnbridge/internal/diagnostics"
)

const registrationInventoryFixture = doctorInventoryFixture + `__PB_SUDO__1
`

func installHostAddSSHFixture(t *testing.T, inventory string, forwardingOK bool) (string, string) {
	t.Helper()
	bin := t.TempDir()
	calls := filepath.Join(t.TempDir(), "ssh-calls")
	scpCalls := filepath.Join(t.TempDir(), "scp-calls")
	t.Setenv("PWNBRIDGE_HOST_ADD_SSH_CALLS", calls)
	t.Setenv("PWNBRIDGE_HOST_ADD_SCP_CALLS", scpCalls)
	forward := "exit 42"
	if forwardingOK {
		forward = "printf 43123; exit 0"
	}
	ssh := `#!/bin/sh
printf '%s\n' "$*" >> "$PWNBRIDGE_HOST_ADD_SSH_CALLS"
case " $* " in
  *" -O check "*) exit 0 ;;
  *" -O exit "*) exit 0 ;;
  *" -O forward "*)
    if test -n "$PWNBRIDGE_HOST_ADD_FORWARD_WAIT"; then
      while test ! -e "$PWNBRIDGE_HOST_ADD_FORWARD_WAIT"; do sleep 0.01; done
    fi
    ` + forward + ` ;;
  *" -M -N "*) trap 'exit 0' INT TERM; while :; do sleep 1; done ;;
  *"__PB_HOST__"*)
    cat <<'EOF'
` + inventory + `EOF
    exit 0 ;;
esac
exit 42
`
	for name, content := range map[string]string{
		"ssh": ssh,
		"scp": "#!/bin/sh\nprintf invoked >> \"$PWNBRIDGE_HOST_ADD_SCP_CALLS\"\nexit 1\n",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(content), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	return calls, scpCalls
}

func TestHostAddCheckPersistsHealthyGlobalCandidateAndJSON(t *testing.T) {
	app, output := testApp(t)
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, ".pwnbridge.toml"), []byte("unknown = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	calls, scpCalls := installHostAddSSHFixture(t, registrationInventoryFixture, true)

	if err := execute(t, app, "host", "add", "x86", "fake-destination", "--check", "--json"); err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Schema int `json:"schema"`
		Data   struct {
			Persisted bool `json:"persisted"`
			Default   bool `json:"default"`
			Check     struct {
				OK       bool `json:"ok"`
				Complete bool `json:"complete"`
			} `json:"check"`
		} `json:"data"`
	}
	if err := json.Unmarshal(output.Bytes(), &envelope); err != nil {
		t.Fatalf("decode output %q: %v", output.String(), err)
	}
	if envelope.Schema != 1 || !envelope.Data.Persisted || !envelope.Data.Default || !envelope.Data.Check.OK || !envelope.Data.Check.Complete {
		t.Fatalf("host add result = %#v", envelope)
	}
	effective, err := config.LoadGlobal(app.Paths)
	if err != nil {
		t.Fatal(err)
	}
	if effective.Global.DefaultHost != "x86" || effective.Global.Hosts["x86"].Destination != "fake-destination" {
		t.Fatalf("persisted global config = %#v", effective.Global)
	}
	transcript, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"pwnbridge-agent", "mkdir -p", "mktemp", "apt-get update", "dpkg --configure"} {
		if strings.Contains(string(transcript), forbidden) {
			t.Fatalf("checked add performed mutating operation %q: %s", forbidden, transcript)
		}
	}
	if _, err := os.Stat(scpCalls); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("checked add invoked SCP: %v", err)
	}
}

func TestHostAddCheckFailureReportsJSONWithoutPersisting(t *testing.T) {
	app, output := testApp(t)
	badInventory := strings.Replace(registrationInventoryFixture, "__PB_ARCH__x86_64", "__PB_ARCH__aarch64", 1)
	installHostAddSSHFixture(t, badInventory, true)
	err := execute(t, app, "host", "add", "x86", "private-destination", "--check", "--json")
	if err == nil || !strings.Contains(err.Error(), "configuration was not changed") || strings.Contains(err.Error(), "private-destination") {
		t.Fatalf("failed checked add error = %v", err)
	}
	if !strings.Contains(output.String(), `"persisted": false`) || !strings.Contains(output.String(), `"ok": false`) || !strings.Contains(output.String(), `"remote-platform"`) {
		t.Fatalf("failed checked add output = %s", output)
	}
	if _, err := os.Stat(filepath.Join(app.Paths.Config, "config.toml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed checked add persisted config: %v", err)
	}
}

func TestHostAddRequiresReplaceBeforeNetworkAndKeepsOldRecordOnFailedCheck(t *testing.T) {
	app, output := testApp(t)
	if err := execute(t, app, "host", "add", "x86", "old-destination"); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	calls, _ := installHostAddSSHFixture(t, strings.Replace(registrationInventoryFixture, "__PB_HOME_WRITABLE__1", "__PB_HOME_WRITABLE__0", 1), true)
	if err := execute(t, app, "host", "add", "x86", "new-destination", "--check"); err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Fatalf("duplicate add error = %v", err)
	}
	if _, err := os.Stat(calls); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("duplicate refusal invoked SSH: %v", err)
	}
	if err := execute(t, app, "host", "add", "x86", "new-destination", "--replace", "--check"); err == nil {
		t.Fatal("failed replacement check unexpectedly succeeded")
	}
	effective, err := config.LoadGlobal(app.Paths)
	if err != nil {
		t.Fatal(err)
	}
	if got := effective.Global.Hosts["x86"].Destination; got != "old-destination" {
		t.Fatalf("failed replacement changed destination to %q", got)
	}
}

func TestHostAddDefaultAndOfflineReplacement(t *testing.T) {
	app, output := testApp(t)
	t.Setenv("PATH", t.TempDir())
	if err := execute(t, app, "host", "add", "first", "first-host"); err != nil {
		t.Fatal(err)
	}
	if err := execute(t, app, "host", "add", "second", "second-host", "--default"); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := execute(t, app, "host", "add", "second", "replacement-host", "--replace"); err != nil {
		t.Fatal(err)
	}
	effective, err := config.LoadGlobal(app.Paths)
	if err != nil {
		t.Fatal(err)
	}
	if effective.Global.DefaultHost != "second" || effective.Global.Hosts["second"].Destination != "replacement-host" {
		t.Fatalf("replaced/default global config = %#v", effective.Global)
	}
	if !strings.Contains(output.String(), "replaced host second (replacement-host; default)") {
		t.Fatalf("replacement output = %q", output.String())
	}
}

func TestHostAddCheckHumanOutputAndOptionalForwarding(t *testing.T) {
	app, output := testApp(t)
	effective := config.Defaults()
	effective.Global.Terminal.Scope = "remote"
	if err := config.SaveGlobal(filepath.Join(app.Paths.Config, "config.toml"), effective.Global); err != nil {
		t.Fatal(err)
	}
	installHostAddSSHFixture(t, registrationInventoryFixture, false)
	if err := execute(t, app, "host", "add", "x86", "fake-destination", "--check"); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"bootstrap-plan", "pending_actions=", "unavailable; terminal.scope=remote", "ok    host check (complete)", "added host x86"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("human checked add omitted %q: %s", expected, output)
		}
	}
}

func TestHostAddCheckRejectsConcurrentTerminalPolicyChange(t *testing.T) {
	app, _ := testApp(t)
	effective := config.Defaults()
	effective.Global.Terminal.Scope = "remote"
	if err := config.SaveGlobal(filepath.Join(app.Paths.Config, "config.toml"), effective.Global); err != nil {
		t.Fatal(err)
	}
	calls, _ := installHostAddSSHFixture(t, registrationInventoryFixture, false)
	release := filepath.Join(t.TempDir(), "release-forward")
	t.Setenv("PWNBRIDGE_HOST_ADD_FORWARD_WAIT", release)
	t.Cleanup(func() { _ = os.WriteFile(release, []byte("release"), 0o600) })
	done := make(chan error, 1)
	go func() {
		done <- execute(t, app, "host", "add", "x86", "fake-destination", "--check")
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		transcript, _ := os.ReadFile(calls)
		if strings.Contains(string(transcript), " -O forward ") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("checked add did not reach the forwarding probe")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := app.updateGlobal(context.Background(), func(latest *config.Effective) error {
		latest.Global.Terminal.Scope = "host"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(release, []byte("release"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil || !strings.Contains(err.Error(), "terminal scope changed") {
		t.Fatalf("concurrent policy change error = %v", err)
	}
	effective, err := config.LoadGlobal(app.Paths)
	if err != nil {
		t.Fatal(err)
	}
	if effective.Global.Terminal.Scope != "host" || len(effective.Global.Hosts) != 0 {
		t.Fatalf("checked add overwrote concurrent policy: %#v", effective.Global)
	}
}

func TestCollectHostRegistrationTimeoutCancellationAndRequiredForwarding(t *testing.T) {
	client := &fakeDoctorRemote{waitInventory: true}
	checks, complete, err := collectHostRegistration(context.Background(), client, true, doctorTimeouts{Inventory: 20 * time.Millisecond, Forwarding: time.Second})
	if err != nil || complete || len(checks) != 2 || checks[0].State != "timeout" {
		t.Fatalf("timed registration = complete %t checks %#v error %v", complete, checks, err)
	}

	client = &fakeDoctorRemote{inventory: registrationInventoryFixture, forwardErr: errors.New("disabled")}
	checks, complete, err = collectHostRegistration(context.Background(), client, true, doctorTimeouts{Inventory: time.Second, Forwarding: time.Second})
	if err != nil || !complete {
		t.Fatalf("forwarding registration = complete %t error %v", complete, err)
	}
	if report := diagnostics.NewReport(checks, complete); report.OK {
		t.Fatalf("required forwarding failure was healthy: %#v", checks)
	}
	client = &fakeDoctorRemote{inventory: registrationInventoryFixture, waitForward: true}
	checks, complete, err = collectHostRegistration(context.Background(), client, true, doctorTimeouts{Inventory: time.Second, Forwarding: 20 * time.Millisecond})
	if err != nil || complete || len(checks) < 2 || checks[len(checks)-1].State != "timeout" {
		t.Fatalf("forward timeout = complete %t checks %#v error %v", complete, checks, err)
	}

	client = &fakeDoctorRemote{waitInventory: true}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	checks, complete, err = collectHostRegistration(ctx, client, true, doctorTimeouts{Inventory: time.Hour, Forwarding: time.Hour})
	if !errors.Is(err, context.Canceled) || complete || len(client.calls) != 1 || len(checks) != 1 || checks[0].State != "cancelled" {
		t.Fatalf("cancelled registration = complete %t calls %#v checks %#v error %v", complete, client.calls, checks, err)
	}
}

func TestHostAddCheckCancellationAndOutputErrorsDoNotWriteFailedCandidate(t *testing.T) {
	app, output := testApp(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	command := app.Root()
	command.SetOut(app.Out)
	command.SetErr(app.Err)
	command.SetArgs([]string{"host", "add", "x86", "fake-destination", "--check", "--json"})
	err := command.ExecuteContext(ctx)
	if !errors.Is(err, context.Canceled) || !strings.Contains(output.String(), `"persisted": false`) || !strings.Contains(output.String(), `"state": "cancelled"`) {
		t.Fatalf("cancelled add = %v, output %s", err, output)
	}
	if _, err := os.Stat(filepath.Join(app.Paths.Config, "config.toml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled add persisted config: %v", err)
	}

	app, _ = testApp(t)
	app.Out = closedWriter{}
	if err := execute(t, app, "host", "add", "x86", "fake-destination"); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("successful mutation output failure = %v", err)
	}
	if _, err := config.LoadGlobal(app.Paths); err != nil {
		t.Fatalf("output failure corrupted persisted config: %v", err)
	}

	app, _ = testApp(t)
	app.Out = closedWriter{}
	badInventory := strings.Replace(registrationInventoryFixture, "__PB_DISK__2097152", "__PB_DISK__1", 1)
	installHostAddSSHFixture(t, badInventory, true)
	if err := execute(t, app, "host", "add", "failed", "fake-destination", "--check"); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("failed check output failure = %v", err)
	}
	if _, err := os.Stat(filepath.Join(app.Paths.Config, "config.toml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unreportable failed check persisted config: %v", err)
	}
}

func TestHostAddHelpExplainsSafetyFlags(t *testing.T) {
	app, output := testApp(t)
	if err := execute(t, app, "host", "add", "--help"); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"--check", "read-only SSH", "--replace", "existing", "--default", "--json"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("host add help omitted %q: %s", expected, output)
		}
	}
}

func BenchmarkCollectHostRegistration(b *testing.B) {
	client := &fakeDoctorRemote{inventory: registrationInventoryFixture}
	options := doctorTimeouts{Inventory: time.Hour, Forwarding: time.Hour}
	for b.Loop() {
		client.calls = client.calls[:0]
		checks, complete, err := collectHostRegistration(context.Background(), client, true, options)
		if err != nil || !complete || len(checks) == 0 {
			b.Fatalf("registration collection failed: complete=%t checks=%d error=%v", complete, len(checks), err)
		}
	}
}
