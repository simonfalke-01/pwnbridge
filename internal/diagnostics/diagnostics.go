package diagnostics

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/pwnbridge/pwnbridge/internal/syncer"
	"github.com/pwnbridge/pwnbridge/internal/transport"
)

type Check struct {
	Name        string `json:"name"`
	OK          bool   `json:"ok"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
}

func Local(ctx context.Context, mutagen syncer.Mutagen) []Check {
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
	err := mutagen.CheckVersion(ctx)
	check := Check{Name: "mutagen", OK: err == nil, Detail: "Mutagen 0.18.1"}
	if err != nil {
		check.Detail = err.Error()
		check.Remediation = "brew install mutagen-io/mutagen/mutagen"
	}
	return append(checks, check)
}

func Remote(ctx context.Context, client transport.Client, containerEngine string, requireForwarding bool) []Check {
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
				Check{Name: "remote-distro", OK: distroOK, Detail: agentProbe.Distro + " " + agentProbe.DistroVersion, Remediation: "use an Ubuntu or Debian amd64 host"},
				Check{Name: "remote-home", OK: agentProbe.HomeWritable, Detail: fmt.Sprintf("writable=%t", agentProbe.HomeWritable), Remediation: "make the remote home and ~/.cache writable"},
				Check{Name: "remote-disk", OK: agentProbe.DiskAvailableKiB >= 1024*1024, Detail: fmt.Sprintf("available=%d KiB", agentProbe.DiskAvailableKiB), Remediation: "free at least 1 GiB on the remote home filesystem"},
				Check{Name: "remote-inodes", OK: agentProbe.InodesAvailable >= 1000, Detail: fmt.Sprintf("available=%d", agentProbe.InodesAvailable), Remediation: "free at least 1000 inodes on the remote home filesystem"},
				Check{Name: "remote-ptrace", OK: agentProbe.PtraceScope != "3", Detail: "yama.ptrace_scope=" + agentProbe.PtraceScope, Remediation: "allow same-user debugging or use the container runtime"},
				Check{Name: "remote-pwntools", OK: agentProbe.PwntoolsVersion == "4.15.0", Detail: "version=" + agentProbe.PwntoolsVersion, Remediation: "run pwnbridge host bootstrap"},
			)
			for _, required := range []string{"bash", "cc", "cmake", "file", "readelf", "gdb", "gdbserver", "gdb-multiarch", "patchelf", "checksec", "python3", "tmux", "strace", "ltrace", "socat", "nc"} {
				ok := agentProbe.Tools[required]
				checks = append(checks, Check{Name: "remote-" + required, OK: ok, Detail: fmt.Sprintf("available=%t", ok), Remediation: "run pwnbridge host bootstrap"})
			}
			if containerEngine != "" {
				ok := agentProbe.Tools[containerEngine]
				detailText := containerEngine
				if containerEngine == "auto" {
					ok = agentProbe.Tools["podman"] || agentProbe.Tools["docker"]
					detailText = "podman or docker"
				}
				checks = append(checks, Check{Name: "remote-container-engine", OK: ok, Detail: detailText, Remediation: "install the configured rootless container engine"})
			}
		}
	}
	return checks
}

func Healthy(checks []Check) bool {
	for _, check := range checks {
		if !check.OK {
			return false
		}
	}
	return true
}
func detail(err error, success string) string {
	if err != nil {
		return err.Error()
	}
	return strings.TrimSpace(success)
}
