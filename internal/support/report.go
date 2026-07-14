package support

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

const Schema = 1

type Report struct {
	Client        Client        `json:"client"`
	Configuration Configuration `json:"configuration"`
	Project       *Project      `json:"project,omitempty"`
	Workspace     *Workspace    `json:"workspace,omitempty"`
	Local         []Capability  `json:"local_capabilities"`
	Remote        Remote        `json:"remote"`
	Privacy       Privacy       `json:"privacy"`
}

type Client struct {
	Version             string `json:"version"`
	Commit              string `json:"commit"`
	BuildDate           string `json:"build_date"`
	Protocol            int    `json:"protocol"`
	GlobalConfigSchema  int    `json:"global_config_schema"`
	ProjectConfigSchema int    `json:"project_config_schema"`
	RequiredMutagen     string `json:"required_mutagen"`
	GoVersion           string `json:"go_version"`
	OS                  string `json:"os"`
	Architecture        string `json:"architecture"`
}

type Configuration struct {
	Readable              bool   `json:"readable"`
	ErrorCategory         string `json:"error_category,omitempty"`
	ProjectFile           bool   `json:"project_file"`
	HostCount             int    `json:"host_count"`
	HostSelected          bool   `json:"host_selected"`
	SelectedHostAvailable bool   `json:"selected_host_available"`
	BootstrapProfileCount int    `json:"bootstrap_profile_count"`
	LogLevel              string `json:"log_level,omitempty"`
}

type Project struct {
	Target                   string     `json:"target"`
	Runtime                  string     `json:"runtime"`
	ContainerEngine          string     `json:"container_engine,omitempty"`
	ContainerNetwork         string     `json:"container_network,omitempty"`
	TerminalProvider         string     `json:"terminal_provider"`
	TerminalScope            string     `json:"terminal_scope"`
	TerminalPlacement        string     `json:"terminal_placement"`
	ShellTransport           string     `json:"shell_transport,omitempty"`
	SourceUserRC             bool       `json:"source_user_rc"`
	WorkspaceIgnoreCount     int        `json:"workspace_ignore_count"`
	EnvironmentVariableCount int        `json:"environment_variable_count"`
	Sync                     SyncConfig `json:"sync"`
}

type SyncConfig struct {
	Mode           string `json:"mode"`
	WatchMode      string `json:"watch_mode"`
	SymlinkMode    string `json:"symlink_mode"`
	PauseOnIdle    bool   `json:"pause_on_idle"`
	BarrierTimeout string `json:"barrier_timeout"`
}

type Workspace struct {
	Available     bool            `json:"available"`
	ErrorCategory string          `json:"error_category,omitempty"`
	SyncCreated   bool            `json:"sync_created"`
	Sync          *SyncState      `json:"sync,omitempty"`
	Recovery      RecoverySummary `json:"recovery"`
}

type SyncState struct {
	Available     bool   `json:"available"`
	ErrorCategory string `json:"error_category,omitempty"`
	Healthy       bool   `json:"healthy"`
	Paused        bool   `json:"paused"`
	State         string `json:"state,omitempty"`
	ProblemCount  int    `json:"problem_count"`
	ConflictCount int    `json:"conflict_count"`
}

type RecoverySummary struct {
	Available     bool   `json:"available"`
	ErrorCategory string `json:"error_category,omitempty"`
	Entries       int    `json:"entries"`
	Verified      int    `json:"digest_recorded"`
	Unverified    int    `json:"digest_unavailable"`
	Legacy        int    `json:"legacy"`
	Bytes         int64  `json:"bytes"`
}

type Capability struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
}

type Remote struct {
	Requested        bool         `json:"requested"`
	Available        bool         `json:"available"`
	ErrorCategory    string       `json:"error_category,omitempty"`
	OS               string       `json:"os,omitempty"`
	Architecture     string       `json:"architecture,omitempty"`
	Distro           string       `json:"distro,omitempty"`
	DistroVersion    string       `json:"distro_version,omitempty"`
	PackageManager   string       `json:"package_manager,omitempty"`
	Libc             string       `json:"libc,omitempty"`
	ServiceManager   string       `json:"service_manager,omitempty"`
	DiskAvailableKiB uint64       `json:"disk_available_kib,omitempty"`
	InodesAvailable  uint64       `json:"inodes_available,omitempty"`
	HomeWritable     bool         `json:"home_writable"`
	Root             bool         `json:"root"`
	SudoAvailable    bool         `json:"sudo_available"`
	Immutable        bool         `json:"immutable"`
	PtraceScope      string       `json:"ptrace_scope,omitempty"`
	PwntoolsVersion  string       `json:"pwntools_version,omitempty"`
	PwndbgVersion    string       `json:"pwndbg_version,omitempty"`
	Tools            []Capability `json:"tools,omitempty"`
}

type Privacy struct {
	Mode                string   `json:"mode"`
	ReviewBeforeSharing bool     `json:"review_before_sharing"`
	Excluded            []string `json:"excluded"`
}

func NewReport(client Client) Report {
	return Report{
		Client: client,
		Privacy: Privacy{
			Mode:                "positive-allowlist",
			ReviewBeforeSharing: true,
			Excluded: []string{
				"paths and file contents",
				"host names, SSH destinations, and network addresses",
				"workspace, machine, session, and runtime identifiers",
				"configuration and environment names or values",
				"shell commands, container images, and conflict paths",
				"logs, tokens, and raw command output or errors",
			},
		},
	}
}

func ErrorCategory(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, os.ErrPermission):
		return "permission"
	case errors.Is(err, os.ErrNotExist):
		return "not-found"
	default:
		return "unavailable"
	}
}

func Render(output io.Writer, report Report) error {
	var buffer bytes.Buffer
	fmt.Fprintln(&buffer, "# Pwnbridge support report")
	fmt.Fprintln(&buffer)
	fmt.Fprintln(&buffer, "Privacy: positive allowlist; review before sharing. No report was uploaded or saved.")
	fmt.Fprintf(&buffer, "Client: version=%s commit=%s build=%s protocol=%d config=%d/%d mutagen=%s go=%s platform=%s/%s\n",
		report.Client.Version, report.Client.Commit, report.Client.BuildDate, report.Client.Protocol,
		report.Client.GlobalConfigSchema, report.Client.ProjectConfigSchema, report.Client.RequiredMutagen,
		report.Client.GoVersion, report.Client.OS, report.Client.Architecture)
	fmt.Fprintf(&buffer, "Configuration: readable=%t project_file=%t hosts=%d selected=%t selected_available=%t profiles=%d",
		report.Configuration.Readable, report.Configuration.ProjectFile, report.Configuration.HostCount,
		report.Configuration.HostSelected, report.Configuration.SelectedHostAvailable, report.Configuration.BootstrapProfileCount)
	if report.Configuration.ErrorCategory != "" {
		fmt.Fprintf(&buffer, " error=%s", report.Configuration.ErrorCategory)
	}
	if report.Configuration.LogLevel != "" {
		fmt.Fprintf(&buffer, " log_level=%s", report.Configuration.LogLevel)
	}
	fmt.Fprintln(&buffer)
	if project := report.Project; project != nil {
		fmt.Fprintf(&buffer, "Project: target=%s runtime=%s terminal=%s/%s/%s source_user_rc=%t ignores=%d environment_variables=%d\n",
			project.Target, project.Runtime, project.TerminalProvider, project.TerminalScope,
			project.TerminalPlacement, project.SourceUserRC, project.WorkspaceIgnoreCount, project.EnvironmentVariableCount)
		fmt.Fprintf(&buffer, "Sync configuration: mode=%s watch=%s symlinks=%s pause_on_idle=%t barrier=%s\n",
			project.Sync.Mode, project.Sync.WatchMode, project.Sync.SymlinkMode, project.Sync.PauseOnIdle, project.Sync.BarrierTimeout)
		if project.ContainerEngine != "" || project.ShellTransport != "" {
			fmt.Fprintf(&buffer, "Execution: shell_transport=%s container_engine=%s container_network=%s\n",
				empty(project.ShellTransport), empty(project.ContainerEngine), empty(project.ContainerNetwork))
		}
	}
	if workspace := report.Workspace; workspace != nil {
		fmt.Fprintf(&buffer, "Workspace: available=%t sync_created=%t", workspace.Available, workspace.SyncCreated)
		if workspace.ErrorCategory != "" {
			fmt.Fprintf(&buffer, " error=%s", workspace.ErrorCategory)
		}
		fmt.Fprintln(&buffer)
		if syncState := workspace.Sync; syncState != nil {
			fmt.Fprintf(&buffer, "Sync state: available=%t healthy=%t paused=%t state=%s problems=%d conflicts=%d",
				syncState.Available, syncState.Healthy, syncState.Paused, syncState.State, syncState.ProblemCount, syncState.ConflictCount)
			if syncState.ErrorCategory != "" {
				fmt.Fprintf(&buffer, " error=%s", syncState.ErrorCategory)
			}
			fmt.Fprintln(&buffer)
		}
		fmt.Fprintf(&buffer, "Recovery: available=%t entries=%d digest_recorded=%d digest_unavailable=%d legacy=%d bytes=%d",
			workspace.Recovery.Available, workspace.Recovery.Entries, workspace.Recovery.Verified,
			workspace.Recovery.Unverified, workspace.Recovery.Legacy, workspace.Recovery.Bytes)
		if workspace.Recovery.ErrorCategory != "" {
			fmt.Fprintf(&buffer, " error=%s", workspace.Recovery.ErrorCategory)
		}
		fmt.Fprintln(&buffer)
	}
	fmt.Fprintln(&buffer, "Local capabilities:")
	for _, capability := range report.Local {
		fmt.Fprintf(&buffer, "- %s: available=%t\n", capability.Name, capability.Available)
	}
	switch {
	case !report.Remote.Requested:
		fmt.Fprintln(&buffer, "Remote: not requested")
	case !report.Remote.Available:
		fmt.Fprintf(&buffer, "Remote: available=false error=%s\n", report.Remote.ErrorCategory)
	default:
		fmt.Fprintf(&buffer, "Remote: available=true platform=%s/%s distro=%s/%s manager=%s libc=%s service=%s home_writable=%t root=%t sudo=%t immutable=%t disk_kib=%d inodes=%d ptrace=%s pwntools=%s pwndbg=%s\n",
			report.Remote.OS, report.Remote.Architecture, report.Remote.Distro, report.Remote.DistroVersion,
			report.Remote.PackageManager, report.Remote.Libc, report.Remote.ServiceManager, report.Remote.HomeWritable,
			report.Remote.Root, report.Remote.SudoAvailable, report.Remote.Immutable, report.Remote.DiskAvailableKiB,
			report.Remote.InodesAvailable, report.Remote.PtraceScope, report.Remote.PwntoolsVersion, report.Remote.PwndbgVersion)
		for _, capability := range report.Remote.Tools {
			fmt.Fprintf(&buffer, "- remote-%s: available=%t\n", capability.Name, capability.Available)
		}
	}
	fmt.Fprintln(&buffer, "Excluded by design:")
	for _, value := range report.Privacy.Excluded {
		fmt.Fprintln(&buffer, "- "+value)
	}
	_, err := output.Write(buffer.Bytes())
	return err
}

func empty(value string) string {
	if value == "" {
		return "not-applicable"
	}
	return value
}
