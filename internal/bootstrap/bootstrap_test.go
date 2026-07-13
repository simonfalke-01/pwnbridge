package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bootstraprecipe "github.com/simonfalke-01/pwnbridge/internal/bootstrap/recipe"
	"github.com/simonfalke-01/pwnbridge/internal/protocol"
	"github.com/simonfalke-01/pwnbridge/internal/transport"
)

func TestPwnPresetRetainsHistoricalAPTPackages(t *testing.T) {
	value, _ := BuiltinRecipe("pwn")
	value, explanations, err := ResolveRecipe(value, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(Inventory{OS: "linux", Architecture: "amd64", PackageManager: ManagerAPT, HomeWritable: true, SudoAvailable: true, Tools: map[string]bool{}}, value, explanations, PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, action := range plan.Actions {
		for _, pkg := range action.Packages {
			got[pkg] = true
		}
	}
	for _, want := range Packages {
		if !got[want] {
			t.Errorf("default pwn preset lost apt package %q", want)
		}
	}
}

func TestCatalogMapsEveryPrivilegedComponentAcrossManagers(t *testing.T) {
	managers := []Manager{ManagerAPT, ManagerDNF, ManagerYUM, ManagerPacman, ManagerZypper, ManagerAPK, ManagerXBPS, ManagerEmerge, ManagerNix}
	for _, component := range Catalog() {
		if !component.Privileged || component.ID == ComponentPwntools {
			continue
		}
		for _, manager := range managers {
			if len(component.Packages[manager]) == 0 {
				t.Errorf("component %s lacks %s mapping", component.ID, manager)
			}
		}
	}
}

func TestDependenciesAndOrderingAreDeterministic(t *testing.T) {
	value := Recipe{Schema: 1, Name: "x", Components: []string{ComponentPwndbg}}
	first, explanations, err := ResolveRecipe(value, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, explanations2, err := ResolveRecipe(value, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(first.Components, ",") != strings.Join(second.Components, ",") || strings.Join(explanations, ",") != strings.Join(explanations2, ",") {
		t.Fatal("resolution was nondeterministic")
	}
	for _, required := range []string{ComponentCore, ComponentGDB, ComponentPython, ComponentPwntools, ComponentPwndbg} {
		if !strings.Contains(","+strings.Join(first.Components, ",")+",", ","+required+",") {
			t.Errorf("dependency resolution lost %s", required)
		}
	}
}

func TestHealthyRerunIsNoOp(t *testing.T) {
	value, _ := BuiltinRecipe("pwn")
	tools := map[string]bool{}
	for _, component := range Catalog() {
		for _, tool := range component.Tools {
			tools[tool] = true
		}
	}
	plan, err := BuildPlan(Inventory{OS: "linux", Architecture: "amd64", PackageManager: ManagerAPT, HomeWritable: true, SudoAvailable: true, Tools: tools, PwntoolsVersion: PwntoolsVersion}, value, nil, PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Steps) != 0 {
		t.Fatalf("healthy rerun has steps: %#v", plan.Steps)
	}
}

func TestPrintPlanSeparatesSummaryActionsStepsAndFollowingContent(t *testing.T) {
	plan := ResolvedPlan{
		Recipe:    Recipe{Name: "pwn"},
		Inventory: Inventory{Host: "lab", Distro: "ubuntu", PackageManager: ManagerAPT, Architecture: "amd64"},
		Actions:   []Action{{State: ActionSkip, Component: ComponentCore, Detail: "already healthy"}},
		Steps:     []Step{{ID: "install", Argv: []string{"apt-get", "install", "gdb"}}},
	}
	var output bytes.Buffer
	PrintPlan(&output, plan)
	got := output.String()
	for _, boundary := range []string{
		"Recipe: pwn\n\n  skip",
		"already healthy\n\nExact steps:",
		"'apt-get' 'install' 'gdb'\n\n",
	} {
		if !strings.Contains(got, boundary) {
			t.Errorf("plan output lacks boundary %q:\n%s", boundary, got)
		}
	}
}

func TestExtraPackageDedupAndPipOptionRejection(t *testing.T) {
	value, _ := BuiltinRecipe("minimal")
	value.SystemPackages = []string{"gdb", "gdb"}
	value.PipPackages = []string{"--index-url=https://evil.invalid"}
	if ValidateRecipe(value) == nil {
		t.Fatal("pip option injection was accepted")
	}
	value.PipPackages = []string{"ropper==1.13.10", "ropper==1.13.10"}
	value, _, err := ResolveRecipe(value, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(value.SystemPackages) != 1 || len(value.PipPackages) != 1 {
		t.Fatalf("packages were not deduplicated: %#v", value)
	}
}

func TestPipRequirementGrammar(t *testing.T) {
	for _, value := range []string{"requests>=2,<3", `pwntools[elf]>=4.15; python_version >= "3.10"`, "ropper==1.13.10"} {
		if !bootstraprecipe.ValidPipRequirement(value) {
			t.Errorf("valid requirement %q was rejected", value)
		}
	}
	for _, value := range []string{"garbage words", "name @ https://example.invalid/pkg.whl", "--pre", "name;"} {
		if bootstraprecipe.ValidPipRequirement(value) {
			t.Errorf("invalid requirement %q was accepted", value)
		}
	}
}

func TestSanitizeHostileTerminalControls(t *testing.T) {
	got := sanitize("safe\x1b[2Jbad\x1b]0;owned\x07\rtext")
	if got != "safebadtext" {
		t.Fatalf("sanitize = %q", got)
	}
}

func TestStructuredEventsTrackResumeState(t *testing.T) {
	var display bytes.Buffer
	tracker := newProgress([]Step{{ID: "one"}, {ID: "two"}}, &display, false)
	for _, event := range []protocol.BootstrapEvent{{Type: "start", StepID: "one", Description: "First"}, {Type: "output", StepID: "one", Output: "\x1b[2Jhostile"}, {Type: "done", StepID: "one", Description: "First"}} {
		data, _ := json.Marshal(event)
		data = append(data, '\n')
		if _, err := tracker.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	completed, pending := tracker.snapshot()
	if strings.Join(completed, ",") != "one" || strings.Join(pending, ",") != "two" {
		t.Fatalf("completed=%v pending=%v", completed, pending)
	}
	if strings.Contains(display.String(), "\x1b") {
		t.Fatal("structured output injected terminal controls")
	}
	if got := display.String(); got != "  [✓] First\n" {
		t.Fatalf("non-terminal progress should emit one aligned final row, got %q", got)
	}
}

func TestInlineProgressReplacesPendingRowAndReturnsToColumnZero(t *testing.T) {
	var display bytes.Buffer
	tracker := newProgress([]Step{{ID: "pwndbg-install"}}, &display, false)
	tracker.inline = true
	tracker.handleEvent([]string{"start", "pwndbg-install", "Install verified portable Pwndbg"})
	tracker.handleEvent([]string{"done", "pwndbg-install", "Install verified portable Pwndbg"})
	want := "\r\x1b[2K  [·] Install verified portable Pwndbg" +
		"\r\x1b[2K  [✓] Install verified portable Pwndbg\r\n"
	if got := display.String(); got != want {
		t.Fatalf("inline progress = %q, want %q", got, want)
	}
}

func TestRunResultDoesNotReprintReviewedPlan(t *testing.T) {
	value, _ := BuiltinRecipe("minimal")
	inventory := Inventory{OS: "linux", Architecture: "amd64", Distro: "ubuntu", PackageManager: ManagerAPT, HomeWritable: true, SudoAvailable: true}
	var output bytes.Buffer
	if _, err := RunResult(context.Background(), transport.Client{}, Options{
		DryRun: true, PlanPrinted: true, Recipe: value, Inventory: &inventory, Output: &output,
	}); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatalf("reviewed plan was printed again: %q", output.String())
	}
}

func FuzzPortableRequirements(f *testing.F) {
	f.Add("requests>=2")
	f.Add("--index-url=https://evil.invalid")
	f.Fuzz(func(t *testing.T, value string) {
		recipe := Recipe{Schema: 1, Name: "fuzz", Components: []string{ComponentCore}, SystemPackages: []string{value}, PipPackages: []string{value}}
		_ = ValidateRecipe(recipe)
	})
}

func FuzzBootstrapEventParsing(f *testing.F) {
	f.Add([]byte(`{"type":"start","step_id":"one","description":"safe"}`))
	f.Add([]byte("{\"type\":\"start\",\"step_id\":\"one\",\"description\":\"\\u001b[2Jhostile\"}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		var output bytes.Buffer
		tracker := newProgress([]Step{{ID: "one"}}, &output, false)
		_, _ = tracker.Write(append(append([]byte(nil), data...), '\n'))
		if strings.Contains(output.String(), "\x1b") {
			t.Fatal("event parser emitted a terminal control")
		}
	})
}

func TestNoSudoPlan(t *testing.T) {
	plan := Plan(Options{NoSudo: true})
	if len(plan) == 0 {
		t.Fatal("empty plan")
	}
	for _, command := range plan {
		if strings.Contains(command, "sudo") {
			t.Fatalf("sudo leaked: %s", command)
		}
	}
}

func TestBootstrapPreflightReportsDiskFailure(t *testing.T) {
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh")
	script := `#!/bin/sh
case " $* " in
  *" -R 127.0.0.1:0:127.0.0.1:9 "*) exit 0 ;;
  *"df -Pk"*) printf 'insufficient-disk-kib:1\n'; exit 22 ;;
  *"__PWNBRIDGE_HOME__"*) printf '__PWNBRIDGE_HOME__/home/test\n__PWNBRIDGE_OS__Linux\n__PWNBRIDGE_ARCH__x86_64\n'; exit 0 ;;
esac
exit 1
`
	if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	client := transport.Client{SSH: ssh, Destination: "fake"}
	err := Run(context.Background(), client, Options{DryRun: true})
	if err == nil || !strings.Contains(err.Error(), "insufficient-disk-kib:1") {
		t.Fatalf("disk preflight failure was not preserved: %v", err)
	}
}

func TestDryRunPerformsExactlyOneReadOnlyInventory(t *testing.T) {
	dir := t.TempDir()
	ssh, calls := filepath.Join(dir, "ssh"), filepath.Join(dir, "calls")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$PB_CALLS"
cat <<'EOF'
__PB_HOST__lab
__PB_OS__Linux
__PB_ARCH__x86_64
__PB_DISTRO__debian
__PB_DISTRO_VERSION__13
__PB_MANAGER__apt
__PB_SERVICE__systemd
__PB_LIBC__glibc 2.41
__PB_DISK__2097152
__PB_INODES__2000
__PB_HOME_WRITABLE__1
__PB_ROOT__0
__PB_SUDO__1
__PB_IMMUTABLE__0
EOF
`
	if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PB_CALLS", calls)
	value, _ := BuiltinRecipe("minimal")
	logPath := filepath.Join(dir, "must-not-exist.log")
	var output bytes.Buffer
	result, err := RunResult(context.Background(), transport.Client{SSH: ssh, SCP: filepath.Join(dir, "missing-scp"), Destination: "fake"}, Options{DryRun: true, Recipe: value, Output: &output, ErrorOutput: &output, LogPath: logPath})
	if err != nil {
		t.Fatal(err)
	}
	if !result.DryRun {
		t.Fatal("result was not marked dry-run")
	}
	data, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "-T fake set -f") != 1 || strings.Contains(string(data), "-tt") {
		t.Fatalf("dry-run SSH calls: %q", data)
	}
	if _, err := os.Stat(logPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry-run created log: %v", err)
	}
}

func TestPinnedPwntools(t *testing.T) {
	if got := strings.Join(Plan(Options{}), "\n"); !strings.Contains(got, "pwntools==4.15.0") {
		t.Fatal("pwntools must be pinned")
	}
	if !strings.Contains(strings.Join(Packages, " "), "mosh") {
		t.Fatal("bootstrap must install mosh-server")
	}
}

func TestPinnedPwndbgIsPortableAndDoesNotModifyDotfiles(t *testing.T) {
	got := strings.Join(Plan(Options{WithPwndbg: true}), "\n")
	for _, required := range []string{PwndbgVersion, PwndbgURL, PwndbgSHA256, "sha256sum -c", "pwndbg/bin/pwndbg"} {
		if !strings.Contains(got, required) {
			t.Fatalf("pwndbg plan is missing %q", required)
		}
	}
	for _, forbidden := range []string{"~/.gdbinit", "$HOME/.gdbinit", "git clone", "./setup.sh"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("pwndbg plan must be isolated from user configuration; found %q", forbidden)
		}
	}
	if strings.Contains(got, `ln -sfn "$pwndbg" "$envbin/gdb"`) {
		t.Fatal("optional pwndbg must not replace the default gdb executable")
	}
	if !strings.Contains(got, ` -nx "$@"`) {
		t.Fatal("the isolated pwndbg entrypoint must not load a conflicting user gdb plugin")
	}
}
