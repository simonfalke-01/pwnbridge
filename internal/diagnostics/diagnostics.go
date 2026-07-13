package diagnostics

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/simonfalke-01/pwnbridge/internal/bootstrap"
	"github.com/simonfalke-01/pwnbridge/internal/syncer"
	"github.com/simonfalke-01/pwnbridge/internal/transport"
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
	checks := []Check{
		{Name: "ssh", OK: inventory.OS != "", Detail: inventory.Host, Severity: "error", State: capabilityState(inventory.OS != "")},
		{Name: "remote-platform", OK: inventory.OS == "linux" && inventory.Architecture == "amd64", Detail: inventory.OS + "/" + inventory.Architecture, Severity: "error", State: capabilityState(inventory.OS == "linux" && inventory.Architecture == "amd64")},
		{Name: "remote-distro", OK: true, Detail: strings.TrimSpace(inventory.Distro + " " + inventory.DistroVersion), Severity: "info", State: string(inventory.PackageManager)},
		{Name: "remote-home", OK: inventory.HomeWritable, Detail: fmt.Sprintf("writable=%t", inventory.HomeWritable), Remediation: "make the remote home writable", Severity: "error", State: capabilityState(inventory.HomeWritable)},
		{Name: "remote-disk", OK: inventory.DiskAvailableKiB >= 1024*1024, Detail: fmt.Sprintf("available=%d KiB", inventory.DiskAvailableKiB), Remediation: "free at least 1 GiB", Severity: "error", State: capabilityState(inventory.DiskAvailableKiB >= 1024*1024)},
		{Name: "remote-inodes", OK: inventory.InodesAvailable >= 1000, Detail: fmt.Sprintf("available=%d", inventory.InodesAvailable), Remediation: "free at least 1000 inodes", Severity: "error", State: capabilityState(inventory.InodesAvailable >= 1000)},
	}
	if inventory.PtraceScope != "" {
		ok := inventory.PtraceScope != "3"
		checks = append(checks, Check{Name: "remote-ptrace", OK: ok, Detail: "yama.ptrace_scope=" + inventory.PtraceScope, Remediation: "allow same-user debugging or use a container", Component: "gdb", Severity: "error", State: capabilityState(ok)})
	}
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
	checks := []Check{{Name: "platform", OK: runtime.GOOS == "darwin" && (runtime.GOARCH == "arm64" || runtime.GOARCH == "amd64"), Detail: runtime.GOOS + "/" + runtime.GOARCH}}
	for _, binary := range []string{"ssh", "scp"} {
		path, err := exec.LookPath(binary)
		check := Check{Name: binary, OK: err == nil, Detail: path}
		if err != nil {
			check.Detail = err.Error()
			check.Remediation = "install OpenSSH client tools"
		}
		checks = append(checks, check)
	}
	if shellTransport == "mosh" {
		path, moshErr := exec.LookPath("mosh")
		check := Check{Name: "mosh", OK: moshErr == nil, Detail: path, Remediation: "brew install mosh"}
		if moshErr != nil {
			check.Detail = moshErr.Error()
		}
		checks = append(checks, check)
	}
	err := mutagen.CheckVersion(ctx)
	check := Check{Name: "mutagen", OK: err == nil, Detail: "Mutagen 0.18.1"}
	if err != nil {
		check.Detail = err.Error()
		check.Remediation = "brew install mutagen-io/mutagen/mutagen"
	}
	return append(checks, check)
}

func Remote(ctx context.Context, client transport.Client, containerEngine string, requireForwarding bool, shellTransport string) []Check {
	probe, err := client.BasicProbe(ctx)
	if err != nil {
		return []Check{{Name: "ssh", OK: false, Detail: err.Error(), Remediation: "verify destination, key authentication, and host key"}}
	}
	forwardErr := client.CheckRemoteForwarding(ctx)
	forwardOK := forwardErr == nil || !requireForwarding
	forwardDetail := detail(forwardErr, "loopback reverse TCP forwarding available")
	if forwardErr != nil && !requireForwarding {
		forwardDetail = "unavailable; terminal.scope=remote does not require it"
	}
	checks := []Check{
		{Name: "ssh", OK: true, Detail: client.Destination},
		{Name: "ssh-reverse-forwarding", OK: forwardOK, Detail: forwardDetail, Remediation: "enable AllowTcpForwarding for this SSH account, or configure terminal.scope=remote"},
		{Name: "remote-platform", OK: probe.OS == "linux" && probe.Architecture == "amd64", Detail: probe.OS + "/" + probe.Architecture},
	}
	if client.AgentPath != "" {
		agentProbe, agentErr := client.ProbeAgent(ctx)
		checks = append(checks, Check{Name: "agent", OK: agentErr == nil, Detail: detail(agentErr, agentProbe.Version)})
		if agentErr == nil {
			distroOK := agentProbe.Distro == "ubuntu" || agentProbe.Distro == "debian"
			checks = append(checks,
				Check{Name: "remote-distro", OK: true, Detail: agentProbe.Distro + " " + agentProbe.DistroVersion, Severity: "info", State: map[bool]string{true: "supported", false: "alternative"}[distroOK]},
				Check{Name: "remote-home", OK: agentProbe.HomeWritable, Detail: fmt.Sprintf("writable=%t", agentProbe.HomeWritable), Remediation: "make the remote home and ~/.cache writable"},
				Check{Name: "remote-disk", OK: agentProbe.DiskAvailableKiB >= 1024*1024, Detail: fmt.Sprintf("available=%d KiB", agentProbe.DiskAvailableKiB), Remediation: "free at least 1 GiB on the remote home filesystem"},
				Check{Name: "remote-inodes", OK: agentProbe.InodesAvailable >= 1000, Detail: fmt.Sprintf("available=%d", agentProbe.InodesAvailable), Remediation: "free at least 1000 inodes on the remote home filesystem"},
				Check{Name: "remote-ptrace", OK: agentProbe.PtraceScope != "3", Detail: "yama.ptrace_scope=" + agentProbe.PtraceScope, Remediation: "allow same-user debugging or use the container runtime"},
				Check{Name: "remote-pwntools", OK: agentProbe.PwntoolsVersion == "4.15.0", Detail: "version=" + agentProbe.PwntoolsVersion, Remediation: "run pwnbridge host bootstrap", Component: "pwntools", Severity: "error", State: capabilityState(agentProbe.PwntoolsVersion == "4.15.0")},
			)
			for _, required := range []string{"bash", "cc", "cmake", "file", "readelf", "gdb", "gdbserver", "gdb-multiarch", "patchelf", "checksec", "python3", "tmux", "strace", "ltrace", "socat", "nc"} {
				ok := agentProbe.Tools[required]
				checks = append(checks, Check{Name: "remote-" + required, OK: ok, Detail: fmt.Sprintf("available=%t", ok), Remediation: "run pwnbridge host bootstrap", Component: componentForTool(required), Severity: "error", State: capabilityState(ok)})
			}
			if shellTransport == "mosh" {
				ok := agentProbe.Tools["mosh-server"]
				check := Check{Name: "remote-mosh-server", OK: ok, Detail: fmt.Sprintf("available=%t", ok), Remediation: "run pwnbridge host bootstrap", Component: "mosh", Severity: "error", State: capabilityState(ok)}
				checks = append(checks, check)
			}
			if containerEngine != "" {
				ok := agentProbe.Tools[containerEngine]
				detailText := containerEngine
				if containerEngine == "auto" {
					ok = agentProbe.Tools["podman"] || agentProbe.Tools["docker"]
					detailText = "podman or docker"
				}
				checks = append(checks, Check{Name: "remote-container-engine", OK: ok, Detail: detailText, Remediation: "install the configured rootless container engine", Component: "containers", Severity: "error", State: capabilityState(ok)})
			}
		}
	}
	return checks
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

func componentForTool(tool string) string {
	switch tool {
	case "gdb", "gdbserver", "gdb-multiarch":
		return "gdb"
	case "python3":
		return "python"
	case "patchelf", "checksec":
		return "patching"
	case "strace", "ltrace":
		return "tracing"
	case "tmux", "socat", "nc":
		return "pane-network"
	default:
		return "core"
	}
}
func detail(err error, success string) string {
	if err != nil {
		return err.Error()
	}
	return strings.TrimSpace(success)
}
