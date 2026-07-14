package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/bootstrap"
	"github.com/simonfalke-01/pwnbridge/internal/diagnostics"
	"github.com/simonfalke-01/pwnbridge/internal/syncer"
)

const doctorInventoryFixture = `__PB_HOST__pwnbox
__PB_OS__Linux
__PB_ARCH__x86_64
__PB_DISTRO__debian
__PB_DISTRO_VERSION__13
__PB_MANAGER__apt
__PB_SERVICE__systemd
__PB_LIBC__glibc
__PB_DISK__2097152
__PB_INODES__2000
__PB_HOME_WRITABLE__1
__PB_TOOL__mosh-server=1
__PB_TOOL__podman=1
__PB_PWNTOOLS__4.15.0
__PB_PTRACE__1
`

type fakeDoctorRemote struct {
	inventory     string
	inventoryErr  error
	waitInventory bool
	forwardErr    error
	waitForward   bool
	calls         []string
}

func (f *fakeDoctorRemote) RawBounded(ctx context.Context, _ string, limit int) ([]byte, error) {
	f.calls = append(f.calls, "inventory")
	if limit != 1<<20 {
		return nil, errors.New("unexpected inventory limit")
	}
	if f.waitInventory {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return []byte(f.inventory), f.inventoryErr
}

func (f *fakeDoctorRemote) CheckRemoteForwarding(ctx context.Context) error {
	f.calls = append(f.calls, "forwarding")
	if f.waitForward {
		<-ctx.Done()
		return ctx.Err()
	}
	return f.forwardErr
}

func TestCollectRemoteDoctorContinuesAfterInventoryTimeout(t *testing.T) {
	client := &fakeDoctorRemote{waitInventory: true}
	recipe, _ := bootstrap.BuiltinRecipe("minimal")
	started := time.Now()
	checks, complete, err := collectRemoteDoctor(context.Background(), client, remoteDoctorOptions{
		Recipe: recipe, RequireForwarding: true,
		Timeouts: doctorTimeouts{Inventory: 20 * time.Millisecond, Forwarding: 50 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	if complete {
		t.Fatal("timed-out inventory reported a complete evaluation")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("bounded doctor took %v", elapsed)
	}
	if strings.Join(client.calls, ",") != "inventory,forwarding" {
		t.Fatalf("probe calls = %#v", client.calls)
	}
	if len(checks) != 2 || checks[0].Name != "remote-inventory" || checks[0].State != "timeout" || checks[1].Name != "ssh-reverse-forwarding" || !checks[1].OK {
		t.Fatalf("partial checks = %#v", checks)
	}
}

func TestCollectRemoteDoctorParentCancellationStopsFurtherProbes(t *testing.T) {
	client := &fakeDoctorRemote{waitInventory: true}
	recipe, _ := bootstrap.BuiltinRecipe("minimal")
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	checks, complete, err := collectRemoteDoctor(ctx, client, remoteDoctorOptions{
		Recipe: recipe, RequireForwarding: true,
		Timeouts: doctorTimeouts{Inventory: time.Second, Forwarding: time.Second},
	})
	if !errors.Is(err, context.Canceled) || complete {
		t.Fatalf("cancelled collector = complete %t, error %v", complete, err)
	}
	if strings.Join(client.calls, ",") != "inventory" {
		t.Fatalf("cancelled collector calls = %#v", client.calls)
	}
	if len(checks) != 1 || checks[0].State != "cancelled" {
		t.Fatalf("cancelled checks = %#v", checks)
	}
}

func TestCollectRemoteDoctorUsesRecipeAndConfiguredRequirements(t *testing.T) {
	client := &fakeDoctorRemote{inventory: doctorInventoryFixture, forwardErr: errors.New("disabled")}
	recipe, _ := bootstrap.BuiltinRecipe("minimal")
	checks, complete, err := collectRemoteDoctor(context.Background(), client, remoteDoctorOptions{
		Recipe: recipe, ContainerEngine: "auto", ShellTransport: "mosh", RequireForwarding: false,
		Timeouts: doctorTimeouts{Inventory: time.Second, Forwarding: time.Second},
	})
	if err != nil || !complete {
		t.Fatalf("configured collector = complete %t, error %v", complete, err)
	}
	wanted := map[string]bool{"bootstrap-core": false, "remote-mosh-server": false, "remote-container-engine": false, "ssh-reverse-forwarding": false}
	for _, check := range checks {
		if _, ok := wanted[check.Name]; ok {
			wanted[check.Name] = true
		}
		if check.Name == "ssh-reverse-forwarding" && (!check.OK || check.State != "unavailable-optional" || check.Severity != "info") {
			t.Fatalf("optional forwarding check = %#v", check)
		}
	}
	for name, found := range wanted {
		if !found {
			t.Errorf("configured checks omitted %s: %#v", name, checks)
		}
	}
}

func TestCollectRemoteDoctorReportsRecipeFailureAndStillChecksForwarding(t *testing.T) {
	client := &fakeDoctorRemote{inventory: doctorInventoryFixture}
	checks, complete, err := collectRemoteDoctor(context.Background(), client, remoteDoctorOptions{
		RecipeError: errors.New("unknown profile"), RequireForwarding: true,
		Timeouts: doctorTimeouts{Inventory: time.Second, Forwarding: time.Second},
	})
	if err != nil || complete {
		t.Fatalf("recipe failure = complete %t, error %v", complete, err)
	}
	if strings.Join(client.calls, ",") != "inventory,forwarding" || len(checks) != 2 || checks[0].Name != "bootstrap-profile" || checks[1].Name != "ssh-reverse-forwarding" {
		t.Fatalf("recipe failure checks = %#v, calls %#v", checks, client.calls)
	}
}

type blockingVersionRunner struct{}

func (blockingVersionRunner) Run(ctx context.Context, _ ...string) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestCollectLocalDoctorBoundsMutagenAndKeepsEarlierChecks(t *testing.T) {
	checks, complete, err := collectLocalDoctor(context.Background(), syncer.Mutagen{Runner: blockingVersionRunner{}}, "ssh", doctorTimeouts{Local: 20 * time.Millisecond})
	if err != nil || complete {
		t.Fatalf("local collector = complete %t, error %v", complete, err)
	}
	if len(checks) < 5 || checks[len(checks)-1].Name != "mutagen" || checks[len(checks)-1].State != "timeout" {
		t.Fatalf("local checks = %#v", checks)
	}
}

func TestEmitDoctorJSONIncludesCompletenessEnvelope(t *testing.T) {
	app, output := testApp(t)
	report := diagnostics.NewReport([]diagnostics.Check{{Name: "probe", OK: false, Detail: "failed"}}, false)
	if err := app.emitDoctor(report, true); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`"schema": 1`, `"complete": false`, `"checks"`} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("JSON doctor output missing %s: %s", expected, output.String())
		}
	}
}

func TestProjectDoctorIsReadOnlyAndEmitsCompletePartialHealth(t *testing.T) {
	app, output := testApp(t)
	cwd := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	bin := t.TempDir()
	calls := filepath.Join(t.TempDir(), "ssh-calls")
	scpCalls := filepath.Join(t.TempDir(), "scp-calls")
	t.Setenv("PWNBRIDGE_DOCTOR_SSH_CALLS", calls)
	t.Setenv("PWNBRIDGE_DOCTOR_SCP_CALLS", scpCalls)
	ssh := `#!/bin/sh
printf '%s\n' "$*" >> "$PWNBRIDGE_DOCTOR_SSH_CALLS"
case " $* " in
  *" -O check "*) exit 0 ;;
  *" -O exit "*) exit 0 ;;
  *" -O forward "*) printf 43123; exit 0 ;;
  *" -M -N "*) trap 'exit 0' INT TERM; while :; do sleep 1; done ;;
  *"__PB_HOST__"*)
    cat <<'EOF'
` + doctorInventoryFixture + `EOF
    exit 0 ;;
esac
exit 42
`
	for name, content := range map[string]string{
		"ssh":     ssh,
		"scp":     "#!/bin/sh\nprintf invoked >> \"$PWNBRIDGE_DOCTOR_SCP_CALLS\"\nexit 1\n",
		"diff":    "#!/bin/sh\nexit 0\n",
		"mutagen": "#!/bin/sh\nprintf '0.18.1\\n'\n",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(content), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":/usr/bin:/bin")

	if err := execute(t, app, "host", "add", "x86", "fake-destination"); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := execute(t, app, "doctor", "--json"); err == nil {
		t.Fatal("Linux test host unexpectedly passed macOS doctor")
	}
	if !strings.Contains(output.String(), `"complete": true`) || !strings.Contains(output.String(), `"remote-inventory"`) && !strings.Contains(output.String(), `"remote-platform"`) {
		t.Fatalf("doctor JSON omitted complete remote health: %s", output.String())
	}
	output.Reset()
	if err := execute(t, app, "host", "doctor", "x86", "--json"); err == nil {
		t.Fatal("incomplete fake host unexpectedly passed host doctor")
	}
	if !strings.Contains(output.String(), `"complete": true`) || !strings.Contains(output.String(), `"remote-platform"`) || !strings.Contains(output.String(), `"ssh-reverse-forwarding"`) {
		t.Fatalf("host doctor JSON diverged from remote report: %s", output.String())
	}
	if _, err := os.Stat(scpCalls); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("doctor invoked scp: %v", err)
	}
	data, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"pwnbridge-agent", "mkdir -p", "mktemp"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("doctor performed remote deployment operation %q: %s", forbidden, data)
		}
	}
}

func TestDoctorEmitsCancelledPartialReportAndOutputFailures(t *testing.T) {
	app, output := testApp(t)
	cwd := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	command := app.Root()
	command.SetOut(app.Out)
	command.SetErr(app.Err)
	command.SetArgs([]string{"doctor", "--json"})
	err = command.ExecuteContext(ctx)
	if !errors.Is(err, context.Canceled) || ExitCode(err) != 130 {
		t.Fatalf("cancelled doctor returned %v (exit %d)", err, ExitCode(err))
	}
	if !strings.Contains(output.String(), `"complete": false`) || !strings.Contains(output.String(), `"state": "cancelled"`) {
		t.Fatalf("cancelled doctor omitted partial report: %s", output.String())
	}

	app, _ = testApp(t)
	app.Out = closedWriter{}
	if err := execute(t, app, "doctor"); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("doctor output failure returned %v", err)
	}
}

type closedWriter struct{}

func (closedWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func BenchmarkCollectRemoteDoctor(b *testing.B) {
	client := &fakeDoctorRemote{inventory: doctorInventoryFixture}
	recipe, _ := bootstrap.BuiltinRecipe("minimal")
	options := remoteDoctorOptions{
		Recipe: recipe, RequireForwarding: true,
		Timeouts: doctorTimeouts{Inventory: time.Hour, Forwarding: time.Hour},
	}
	for b.Loop() {
		client.calls = client.calls[:0]
		checks, complete, err := collectRemoteDoctor(context.Background(), client, options)
		if err != nil || !complete || len(checks) == 0 {
			b.Fatalf("doctor collection failed: complete=%t checks=%d error=%v", complete, len(checks), err)
		}
	}
}
