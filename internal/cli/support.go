package cli

import (
	"context"
	"math"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/simonfalke-01/pwnbridge/internal/bootstrap"
	"github.com/simonfalke-01/pwnbridge/internal/config"
	"github.com/simonfalke-01/pwnbridge/internal/diagnostics"
	"github.com/simonfalke-01/pwnbridge/internal/recovery"
	"github.com/simonfalke-01/pwnbridge/internal/support"
	"github.com/simonfalke-01/pwnbridge/internal/syncer"
	"github.com/simonfalke-01/pwnbridge/internal/transport"
	"github.com/simonfalke-01/pwnbridge/internal/version"
)

const (
	supportLocalTimeout  = 10 * time.Second
	supportStatusTimeout = 10 * time.Second
	supportRemoteTimeout = 20 * time.Second
)

var supportRemoteTools = []string{
	"bash", "cc", "cmake", "file", "readelf", "git", "curl", "xz", "gdb", "gdbserver",
	"gdb-multiarch", "python3", "patchelf", "checksec", "strace", "ltrace", "tmux", "socat",
	"nc", "mosh-server", "podman", "docker", "docker-group", "systemctl", "sha256sum", "tar",
}

func (a *App) supportCommand() *cobra.Command {
	var asJSON, localOnly bool
	command := &cobra.Command{
		Use:   "support",
		Short: "Print a privacy-allowlisted support report",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			report, err := a.collectSupportReport(cmd.Context(), localOnly)
			if err != nil {
				return err
			}
			if asJSON {
				return writeJSON(a.Out, report)
			}
			return support.Render(a.Out, report)
		},
	}
	command.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	command.Flags().BoolVar(&localOnly, "local-only", false, "skip the read-only SSH inventory")
	return command
}

func (a *App) collectSupportReport(ctx context.Context, localOnly bool) (support.Report, error) {
	if err := a.Paths.Ensure(); err != nil {
		return support.Report{}, err
	}
	report := support.NewReport(support.Client{
		Version: supportReleaseVersion(version.Version), Commit: supportCommit(version.Commit), BuildDate: supportBuildDate(version.Date),
		Protocol: version.ProtocolVersion, GlobalConfigSchema: version.GlobalConfigSchema,
		ProjectConfigSchema: version.ProjectConfigSchema, RequiredMutagen: supportVersion(version.MutagenVersion),
		GoVersion: supportGoVersion(runtime.Version()), OS: allowlistedValue(runtime.GOOS, "darwin", "linux"),
		Architecture: allowlistedValue(runtime.GOARCH, "amd64", "arm64"),
	})
	cwd, err := os.Getwd()
	if err != nil {
		report.Configuration.ErrorCategory = support.ErrorCategory(err)
		return report, nil
	}
	effective, configErr := config.Load(cwd, a.Paths)
	if configErr != nil {
		report.Configuration.ErrorCategory = support.ErrorCategory(configErr)
		if report.Configuration.ErrorCategory == "unavailable" {
			report.Configuration.ErrorCategory = "invalid"
		}
		effective = config.Defaults()
	} else {
		report.Configuration = supportConfiguration(effective)
		report.Project = supportProject(effective, "")
	}

	localContext, cancelLocal := context.WithTimeout(ctx, supportLocalTimeout)
	mutagen := syncer.Mutagen{Runner: syncer.DefaultRunner(effective.MutagenPath, a.Paths.State)}
	shellTransport := ""
	if host, ok := effective.Global.Hosts[effective.SelectedHost]; ok {
		shellTransport = host.ShellTransport
	}
	report.Local = supportCapabilities(diagnostics.Local(localContext, mutagen, shellTransport))
	cancelLocal()
	if configErr != nil {
		return report, nil
	}

	project, projectErr := a.loadProject(ctx, false)
	if projectErr != nil {
		report.Workspace = &support.Workspace{ErrorCategory: support.ErrorCategory(projectErr)}
		return report, nil
	}
	if project.HostID != "" {
		report.Configuration.HostSelected = true
		report.Configuration.SelectedHostAvailable = true
		report.Project = supportProject(effective, project.Host.ShellTransport)
		report.Workspace = a.supportWorkspace(ctx, project)
	}
	if localOnly || project.HostID == "" {
		return report, nil
	}
	report.Remote.Requested = true
	remoteContext, cancelRemote := context.WithTimeout(ctx, supportRemoteTimeout)
	inventory, remoteErr := bootstrap.Inspect(remoteContext, transport.New(project.Host.Destination, ""))
	cancelRemote()
	if remoteErr != nil {
		report.Remote.ErrorCategory = support.ErrorCategory(remoteErr)
		return report, nil
	}
	report.Remote = supportRemote(inventory)
	return report, nil
}

func supportConfiguration(effective config.Effective) support.Configuration {
	_, selectedAvailable := effective.Global.Hosts[effective.SelectedHost]
	return support.Configuration{
		Readable: true, ProjectFile: effective.ProjectPath != "", HostCount: len(effective.Global.Hosts),
		HostSelected: effective.SelectedHost != "", SelectedHostAvailable: effective.SelectedHost != "" && selectedAvailable,
		BootstrapProfileCount: len(effective.Global.BootstrapProfiles),
		LogLevel:              allowlistedValue(effective.LogLevel, "debug", "info", "warn", "warning", "error"),
	}
}

func supportProject(effective config.Effective, shellTransport string) *support.Project {
	provider := effective.Global.Terminal.Provider
	if strings.HasPrefix(provider, "custom:") {
		provider = "custom"
	}
	project := &support.Project{
		Target: allowlistedValue(effective.Project.Target, "linux/amd64"), Runtime: allowlistedValue(effective.Project.Runtime.Kind, "host", "container"),
		TerminalProvider: supportTerminalProvider(provider), TerminalScope: allowlistedValue(effective.Global.Terminal.Scope, "host", "remote"),
		TerminalPlacement: allowlistedValue(effective.Global.Terminal.Placement, "right", "down", "tab", "floating", "window"), SourceUserRC: effective.Project.Shell.SourceUserRC,
		WorkspaceIgnoreCount: len(effective.Project.Workspace.Ignore), EnvironmentVariableCount: len(effective.Project.Environment.Set),
		Sync: support.SyncConfig{
			Mode: allowlistedValue(effective.Global.Sync.Mode, "two-way-safe"), WatchMode: allowlistedValue(effective.Global.Sync.WatchMode, "portable"),
			SymlinkMode: allowlistedValue(effective.Global.Sync.SymlinkMode, "portable", "posix-raw"), PauseOnIdle: effective.Global.Sync.PauseOnIdle,
			BarrierTimeout: effective.Global.Sync.BarrierTimeout.String(),
		},
	}
	if shellTransport != "" {
		project.ShellTransport = allowlistedValue(shellTransport, "auto", "ssh", "mosh")
	}
	if effective.Project.Runtime.Kind == "container" {
		project.ContainerEngine = allowlistedValue(effective.Project.Runtime.Container.Engine, "auto", "docker", "podman")
		project.ContainerNetwork = allowlistedValue(effective.Project.Runtime.Container.Network, "bridge", "host", "none", "default")
		if project.ContainerNetwork == "unavailable" {
			project.ContainerNetwork = "custom"
		}
	}
	return project
}

func supportCapabilities(checks []diagnostics.Check) []support.Capability {
	result := make([]support.Capability, 0, len(checks))
	for _, check := range checks {
		name := allowlistedValue(check.Name, "platform", "ssh", "scp", "diff", "mosh", "mutagen")
		if name != "unavailable" {
			result = append(result, support.Capability{Name: name, Available: check.OK})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func (a *App) supportWorkspace(ctx context.Context, project *projectContext) *support.Workspace {
	result := &support.Workspace{Available: true, SyncCreated: project.State.MutagenIdentifier != ""}
	if result.SyncCreated {
		statusContext, cancelStatus := context.WithTimeout(ctx, supportStatusTimeout)
		health, err := project.Sync.Status(statusContext, project.State.MutagenIdentifier)
		cancelStatus()
		result.Sync = &support.SyncState{Available: err == nil, ErrorCategory: support.ErrorCategory(err)}
		if err == nil {
			result.Sync.Healthy, result.Sync.Paused = health.Healthy, health.Paused
			switch {
			case health.Paused:
				result.Sync.State = "paused"
			case health.Healthy:
				result.Sync.State = "healthy"
			default:
				result.Sync.State = "unhealthy"
			}
			result.Sync.ProblemCount = len(health.Problems)
			result.Sync.ConflictCount = len(syncer.ConflictPaths(health.Raw))
		}
	}
	entries, err := recovery.List(project.WS.RecoveryPath)
	result.Recovery.Available = err == nil
	result.Recovery.ErrorCategory = support.ErrorCategory(err)
	if err != nil {
		return result
	}
	result.Recovery.Entries = len(entries)
	for _, entry := range entries {
		if entry.Size > math.MaxInt64-result.Recovery.Bytes {
			result.Recovery.Bytes = math.MaxInt64
		} else {
			result.Recovery.Bytes += entry.Size
		}
		if entry.SHA256 == "" {
			result.Recovery.Unverified++
		} else {
			result.Recovery.Verified++
		}
		if entry.Legacy {
			result.Recovery.Legacy++
		}
	}
	return result
}

func supportRemote(inventory bootstrap.Inventory) support.Remote {
	result := support.Remote{
		Requested: true, Available: true, OS: allowlistedValue(inventory.OS, "linux"),
		Architecture: allowlistedValue(inventory.Architecture, "amd64", "arm64"), Distro: supportDistro(inventory.Distro),
		DistroVersion: supportVersion(inventory.DistroVersion), PackageManager: supportPackageManager(inventory.PackageManager),
		Libc: supportLibc(inventory.Libc), ServiceManager: allowlistedValue(inventory.ServiceManager, "systemd", "openrc", "runit", "sysv", "unknown"),
		DiskAvailableKiB: inventory.DiskAvailableKiB, InodesAvailable: inventory.InodesAvailable,
		HomeWritable: inventory.HomeWritable, Root: inventory.Root, SudoAvailable: inventory.SudoAvailable,
		Immutable: inventory.Immutable, PtraceScope: allowlistedValue(inventory.PtraceScope, "0", "1", "2", "3"),
		PwntoolsVersion: supportVersion(inventory.PwntoolsVersion), PwndbgVersion: supportVersion(inventory.PwndbgVersion),
	}
	for _, name := range supportRemoteTools {
		result.Tools = append(result.Tools, support.Capability{Name: name, Available: inventory.Tools[name]})
	}
	return result
}

func allowlistedValue(value string, allowed ...string) string {
	for _, candidate := range allowed {
		if value == candidate {
			return value
		}
	}
	return "unavailable"
}

func supportDistro(value string) string {
	return allowlistedValue(strings.ToLower(value),
		"ubuntu", "debian", "fedora", "rhel", "centos", "rocky", "almalinux", "arch",
		"opensuse", "opensuse-leap", "opensuse-tumbleweed", "alpine", "void", "gentoo", "nixos")
}

func supportVersion(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 32 {
		return "unavailable"
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r == '.') {
			return "unavailable"
		}
	}
	return value
}

func supportReleaseVersion(value string) string {
	if value == "dev" || value == "unknown" {
		return value
	}
	if len(value) > 64 {
		return "unavailable"
	}
	trimmed := strings.TrimPrefix(value, "v")
	core, suffix, hasSuffix := strings.Cut(trimmed, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return "unavailable"
	}
	for _, part := range parts {
		if !decimal(part) {
			return "unavailable"
		}
	}
	if hasSuffix && !supportReleaseSuffix(suffix) {
		return "unavailable"
	}
	return value
}

func supportReleaseSuffix(value string) bool {
	for _, prefix := range []string{"alpha.", "beta.", "rc."} {
		if strings.HasPrefix(value, prefix) {
			return decimal(strings.TrimPrefix(value, prefix))
		}
	}
	commit, ok := strings.CutPrefix(value, "SNAPSHOT-")
	if !ok || len(commit) < 7 || len(commit) > 64 {
		return false
	}
	for _, r := range commit {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func supportCommit(value string) string {
	if value == "unknown" {
		return value
	}
	if len(value) < 7 || len(value) > 64 {
		return "unavailable"
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return "unavailable"
		}
	}
	return strings.ToLower(value)
}

func supportBuildDate(value string) string {
	if value == "unknown" {
		return value
	}
	if len(value) > 64 {
		return "unavailable"
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return "unavailable"
	}
	return parsed.UTC().Format(time.RFC3339)
}

func supportGoVersion(value string) string {
	if len(value) > 32 || !strings.HasPrefix(value, "go") || !numericVersion(strings.TrimPrefix(value, "go")) {
		return "unavailable"
	}
	return value
}

func numericVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return false
	}
	for _, part := range parts {
		if !decimal(part) {
			return false
		}
	}
	return true
}

func decimal(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func supportTerminalProvider(value string) string {
	return allowlistedValue(value, "auto", "zellij", "tmux", "wezterm", "kitty", "iterm2", "terminal-app", "remote-tmux", "remote-zellij", "custom")
}

func supportPackageManager(value bootstrap.Manager) string {
	switch value {
	case bootstrap.ManagerAPT, bootstrap.ManagerDNF, bootstrap.ManagerYUM, bootstrap.ManagerPacman,
		bootstrap.ManagerZypper, bootstrap.ManagerAPK, bootstrap.ManagerXBPS, bootstrap.ManagerEmerge,
		bootstrap.ManagerNix, bootstrap.ManagerUnknown:
		return string(value)
	default:
		return "unknown"
	}
}

func supportLibc(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.HasPrefix(value, "glibc"):
		return "glibc"
	case strings.HasPrefix(value, "musl") || value == "musl":
		return "musl"
	default:
		return "unknown"
	}
}
