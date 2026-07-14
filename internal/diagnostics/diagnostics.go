package diagnostics

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/simonfalke-01/pwnbridge/internal/bootstrap"
	"github.com/simonfalke-01/pwnbridge/internal/syncer"
)

type Check struct {
	Name        string `json:"name"`
	OK          bool   `json:"ok"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
	Component   string `json:"component,omitempty"`
	Severity    string `json:"severity,omitempty"`
	State       string `json:"state,omitempty"`
}

// Bootstrap derives doctor health from the same inventory and resolved plan
// used by bootstrap. Only capabilities selected by the recipe can be fatal.
func Bootstrap(inventory bootstrap.Inventory, plan bootstrap.ResolvedPlan) []Check {
	checks := remotePrerequisiteChecks(inventory)
	selected := map[string]bool{}
	for _, id := range plan.Recipe.Components {
		selected[id] = true
	}
	for _, action := range plan.Actions {
		ok := action.State == bootstrap.ActionSkip
		severity := "error"
		state := string(action.State)
		if action.State == bootstrap.ActionUnsupported && action.Component != bootstrap.ComponentCore && !selected[action.Component] {
			severity = "info"
		}
		checks = append(checks, Check{Name: "bootstrap-" + action.Component, OK: ok, Detail: action.Detail, Remediation: "run pwnbridge host bootstrap", Component: action.Component, Severity: severity, State: state})
	}
	for _, component := range bootstrap.Catalog() {
		if selected[component.ID] || !unselectedInstalled(inventory, component) {
			continue
		}
		checks = append(checks, Check{Name: "bootstrap-" + component.ID, OK: true, Detail: "installed but not selected by recipe", Component: component.ID, Severity: "info", State: "installed-unselected"})
	}
	return checks
}

// Registration reports whether a newly configured endpoint can be prepared by
// the selected bootstrap plan. Missing installable components are pending work,
// not failures: host bootstrap is the explicit operation that installs them.
func Registration(inventory bootstrap.Inventory, plan bootstrap.ResolvedPlan) []Check {
	checks := remotePrerequisiteChecks(inventory)
	pending := 0
	for _, action := range plan.Actions {
		if action.State != bootstrap.ActionSkip {
			pending++
		}
	}
	planCheck := Check{
		Name: "bootstrap-plan", OK: true,
		Detail:      fmt.Sprintf("profile=%s pending_actions=%d", plan.Recipe.Name, pending),
		Remediation: "resolve bootstrap blockers before registering this host",
		Severity:    "error", State: "ready",
	}
	if err := plan.ValidateExecutable(); err != nil {
		planCheck.OK = false
		planCheck.Detail = err.Error()
		planCheck.State = "blocked"
	}
	checks = append(checks, planCheck)
	return checks
}

func remotePrerequisiteChecks(inventory bootstrap.Inventory) []Check {
	checks := []Check{
		{Name: "ssh", OK: inventory.OS != "", Detail: inventory.Host, Severity: "error", State: capabilityState(inventory.OS != "")},
		{Name: "remote-platform", OK: inventory.OS == "linux" && inventory.Architecture == "amd64", Detail: inventory.OS + "/" + inventory.Architecture, Remediation: "use a Linux x86-64 host", Severity: "error", State: capabilityState(inventory.OS == "linux" && inventory.Architecture == "amd64")},
		{Name: "remote-distro", OK: true, Detail: strings.TrimSpace(inventory.Distro + " " + inventory.DistroVersion), Severity: "info", State: string(inventory.PackageManager)},
		{Name: "remote-home", OK: inventory.HomeWritable, Detail: fmt.Sprintf("writable=%t", inventory.HomeWritable), Remediation: "make the remote home writable", Severity: "error", State: capabilityState(inventory.HomeWritable)},
		{Name: "remote-disk", OK: inventory.DiskAvailableKiB >= 1024*1024, Detail: fmt.Sprintf("available=%d KiB", inventory.DiskAvailableKiB), Remediation: "make at least 1 GiB available in the remote home filesystem", Severity: "error", State: capabilityState(inventory.DiskAvailableKiB >= 1024*1024)},
		{Name: "remote-inodes", OK: inventory.InodesAvailable >= 1000, Detail: fmt.Sprintf("available=%d", inventory.InodesAvailable), Remediation: "make at least 1000 inodes available in the remote home filesystem", Severity: "error", State: capabilityState(inventory.InodesAvailable >= 1000)},
	}
	if inventory.PtraceScope != "" {
		ok := inventory.PtraceScope != "3"
		checks = append(checks, Check{Name: "remote-ptrace", OK: ok, Detail: "yama.ptrace_scope=" + inventory.PtraceScope, Remediation: "allow same-user debugging or use a compatible container/host", Component: "gdb", Severity: "error", State: capabilityState(ok)})
	}
	return checks
}

func unselectedInstalled(inventory bootstrap.Inventory, component bootstrap.Component) bool {
	switch component.ID {
	case bootstrap.ComponentPwntools:
		return inventory.PwntoolsVersion == bootstrap.PwntoolsVersion
	case bootstrap.ComponentPwndbg:
		return inventory.PwndbgVersion == bootstrap.PwndbgVersion
	case bootstrap.ComponentDocker:
		return inventory.Tools["docker"]
	case bootstrap.ComponentPodman:
		return inventory.Tools["podman"]
	}
	if len(component.Tools) == 0 {
		return false
	}
	for _, tool := range component.Tools {
		if !inventory.Tools[tool] {
			return false
		}
	}
	return true
}

func Local(ctx context.Context, mutagen syncer.Mutagen, shellTransport string) []Check {
	platformOK := runtime.GOOS == "darwin" && (runtime.GOARCH == "arm64" || runtime.GOARCH == "amd64")
	platformState := "unsupported"
	if platformOK {
		platformState = "supported"
	}
	checks := []Check{{Name: "platform", OK: platformOK, Detail: runtime.GOOS + "/" + runtime.GOARCH, Severity: "error", State: platformState}}
	for _, binary := range []string{"ssh", "scp"} {
		path, err := exec.LookPath(binary)
		check := Check{Name: binary, OK: err == nil, Detail: path, Severity: "error", State: capabilityState(err == nil)}
		if err != nil {
			check.Detail = err.Error()
			check.Remediation = "install OpenSSH client tools"
		}
		checks = append(checks, check)
	}
	diffPath, diffErr := exec.LookPath("diff")
	diffCheck := Check{Name: "diff", OK: diffErr == nil, Detail: diffPath, Remediation: "install a POSIX diff utility for conflict previews", Severity: "error", State: capabilityState(diffErr == nil)}
	if diffErr != nil {
		diffCheck.Detail = diffErr.Error()
	}
	checks = append(checks, diffCheck)
	if shellTransport == "mosh" {
		path, moshErr := exec.LookPath("mosh")
		check := Check{Name: "mosh", OK: moshErr == nil, Detail: path, Remediation: "brew install mosh", Severity: "error", State: capabilityState(moshErr == nil)}
		if moshErr != nil {
			check.Detail = moshErr.Error()
		}
		checks = append(checks, check)
	}
	err := mutagen.CheckVersion(ctx)
	check := Check{Name: "mutagen", OK: err == nil, Detail: "Mutagen 0.18.1", Severity: "error", State: capabilityState(err == nil)}
	if err != nil {
		check.Detail = err.Error()
		check.Remediation = "brew install mutagen-io/mutagen/mutagen"
	}
	return append(checks, check)
}

func Healthy(checks []Check) bool {
	for _, check := range checks {
		if !check.OK && (check.Severity == "" || check.Severity == "error") {
			return false
		}
	}
	return true
}

func capabilityState(ok bool) string {
	if ok {
		return "installed"
	}
	return "missing"
}
