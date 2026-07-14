package bootstrap

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

const maxInventoryOutputBytes = 1 << 20

type Inventory struct {
	Host             string          `json:"host"`
	OS               string          `json:"os"`
	Architecture     string          `json:"architecture"`
	Distro           string          `json:"distro,omitempty"`
	DistroVersion    string          `json:"distro_version,omitempty"`
	PackageManager   Manager         `json:"package_manager"`
	Libc             string          `json:"libc,omitempty"`
	DiskAvailableKiB uint64          `json:"disk_available_kib,omitempty"`
	InodesAvailable  uint64          `json:"inodes_available,omitempty"`
	HomeWritable     bool            `json:"home_writable"`
	Root             bool            `json:"root"`
	SudoAvailable    bool            `json:"sudo_available"`
	Immutable        bool            `json:"immutable"`
	ServiceManager   string          `json:"service_manager,omitempty"`
	Tools            map[string]bool `json:"tools"`
	PwntoolsVersion  string          `json:"pwntools_version,omitempty"`
	PwndbgVersion    string          `json:"pwndbg_version,omitempty"`
	PtraceScope      string          `json:"ptrace_scope,omitempty"`
}

// Inspect uses only ordinary read-only commands. In particular it does not
// invoke sudo, create probe files, deploy the agent, or refresh repositories.
func Inspect(ctx context.Context, client interface {
	RawBounded(context.Context, string, int) ([]byte, error)
}) (Inventory, error) {
	script := `set -f
printf '__PB_HOST__%s\n' "$(hostname 2>/dev/null || uname -n)"
printf '__PB_OS__%s\n' "$(uname -s 2>/dev/null)"
printf '__PB_ARCH__%s\n' "$(uname -m 2>/dev/null)"
if test -r /etc/os-release; then
  sed -n 's/^ID=//p; s/^VERSION_ID=//p' /etc/os-release | tr -d '\"' | awk 'NR==1{print "__PB_DISTRO__"$0} NR==2{print "__PB_DISTRO_VERSION__"$0}'
fi
manager=unknown
for pair in apt-get:apt dnf:dnf yum:yum pacman:pacman zypper:zypper apk:apk xbps-install:xbps emerge:emerge nix-env:nix; do
  command=${pair%%:*}; name=${pair##*:}; if command -v "$command" >/dev/null 2>&1; then manager=$name; break; fi
done
if { test -e /run/ostree-booted || test -e /sysroot/ostree; } && command -v nix-env >/dev/null 2>&1; then manager=nix; fi
printf '__PB_MANAGER__%s\n' "$manager"
service_manager=unknown
for pair in systemctl:systemd rc-service:openrc sv:runit service:sysv; do
  command=${pair%%:*}; name=${pair##*:}; if command -v "$command" >/dev/null 2>&1; then service_manager=$name; break; fi
done
printf '__PB_SERVICE__%s\n' "$service_manager"
libc=unknown
if output=$(getconf GNU_LIBC_VERSION 2>/dev/null); then libc=$output; elif ldd --version 2>&1 | grep -qi musl; then libc=musl; fi
printf '__PB_LIBC__%s\n' "$libc"
printf '__PB_DISK__%s\n' "$(df -Pk "$HOME" 2>/dev/null | awk 'END {print $4+0}')"
printf '__PB_INODES__%s\n' "$(df -Pi "$HOME" 2>/dev/null | awk 'END {print $4+0}')"
test -w "$HOME" && printf '__PB_HOME_WRITABLE__1\n' || printf '__PB_HOME_WRITABLE__0\n'
test "$(id -u)" = 0 && printf '__PB_ROOT__1\n' || printf '__PB_ROOT__0\n'
command -v sudo >/dev/null 2>&1 && printf '__PB_SUDO__1\n' || printf '__PB_SUDO__0\n'
if test -e /run/ostree-booted || test -e /sysroot/ostree; then printf '__PB_IMMUTABLE__1\n'; else printf '__PB_IMMUTABLE__0\n'; fi
for tool in bash cc cmake file readelf git curl xz gdb gdbserver gdb-multiarch python3 patchelf checksec strace ltrace tmux socat nc mosh-server podman docker systemctl sha256sum tar; do
  command -v "$tool" >/dev/null 2>&1 && value=1 || value=0
  printf '__PB_TOOL__%s=%s\n' "$tool" "$value"
done
id -nG 2>/dev/null | tr ' ' '\n' | grep -qx docker && printf '__PB_TOOL__docker-group=1\n' || printf '__PB_TOOL__docker-group=0\n'
p="$HOME/.local/share/pwnbridge/envs/pwn-v1/bin/python"
if test -x "$p"; then "$p" -B -c 'import importlib.metadata as m; print("__PB_PWNTOOLS__" + m.version("pwntools"))' 2>/dev/null || true; fi
if test -x "$HOME/.local/share/pwnbridge/pwndbg/current/bin/pwndbg"; then printf '__PB_PWNDBG__` + PwndbgVersion + `\n'; fi`
	// Reading Yama policy is optional and deliberately kept out of the shell
	// expression above so systems without /proc remain supported.
	script += `
if test -r /proc/sys/kernel/yama/ptrace_scope; then printf '__PB_PTRACE__%s\n' "$(cat /proc/sys/kernel/yama/ptrace_scope)"; fi`
	output, err := client.RawBounded(ctx, script, maxInventoryOutputBytes)
	if err != nil {
		return Inventory{}, fmt.Errorf("inspect remote host: %w", err)
	}
	value := Inventory{PackageManager: ManagerUnknown, Tools: map[string]bool{}}
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "__PB_HOST__"):
			value.Host = strings.TrimPrefix(line, "__PB_HOST__")
		case strings.HasPrefix(line, "__PB_OS__"):
			value.OS = strings.ToLower(strings.TrimPrefix(line, "__PB_OS__"))
		case strings.HasPrefix(line, "__PB_ARCH__"):
			value.Architecture = normalizeArch(strings.TrimPrefix(line, "__PB_ARCH__"))
		case strings.HasPrefix(line, "__PB_DISTRO__"):
			value.Distro = strings.TrimPrefix(line, "__PB_DISTRO__")
		case strings.HasPrefix(line, "__PB_DISTRO_VERSION__"):
			value.DistroVersion = strings.TrimPrefix(line, "__PB_DISTRO_VERSION__")
		case strings.HasPrefix(line, "__PB_MANAGER__"):
			value.PackageManager = Manager(strings.TrimPrefix(line, "__PB_MANAGER__"))
		case strings.HasPrefix(line, "__PB_LIBC__"):
			value.Libc = strings.TrimPrefix(line, "__PB_LIBC__")
		case strings.HasPrefix(line, "__PB_SERVICE__"):
			value.ServiceManager = strings.TrimPrefix(line, "__PB_SERVICE__")
		case strings.HasPrefix(line, "__PB_DISK__"):
			value.DiskAvailableKiB, _ = strconv.ParseUint(strings.TrimPrefix(line, "__PB_DISK__"), 10, 64)
		case strings.HasPrefix(line, "__PB_INODES__"):
			value.InodesAvailable, _ = strconv.ParseUint(strings.TrimPrefix(line, "__PB_INODES__"), 10, 64)
		case line == "__PB_HOME_WRITABLE__1":
			value.HomeWritable = true
		case line == "__PB_ROOT__1":
			value.Root = true
		case line == "__PB_SUDO__1":
			value.SudoAvailable = true
		case line == "__PB_IMMUTABLE__1":
			value.Immutable = true
		case strings.HasPrefix(line, "__PB_TOOL__"):
			name, raw, ok := strings.Cut(strings.TrimPrefix(line, "__PB_TOOL__"), "=")
			if ok {
				value.Tools[name] = raw == "1"
			}
		case strings.HasPrefix(line, "__PB_PWNTOOLS__"):
			value.PwntoolsVersion = strings.TrimPrefix(line, "__PB_PWNTOOLS__")
		case strings.HasPrefix(line, "__PB_PWNDBG__"):
			value.PwndbgVersion = strings.TrimPrefix(line, "__PB_PWNDBG__")
		case strings.HasPrefix(line, "__PB_PTRACE__"):
			value.PtraceScope = strings.TrimPrefix(line, "__PB_PTRACE__")
		}
	}
	if value.OS == "" || value.Architecture == "" {
		return Inventory{}, fmt.Errorf("remote inventory was incomplete: %q", output)
	}
	return value, nil
}

func normalizeArch(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}
