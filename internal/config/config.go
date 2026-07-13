package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/simonfalke-01/pwnbridge/internal/fsutil"
	"github.com/simonfalke-01/pwnbridge/internal/paths"
	"github.com/simonfalke-01/pwnbridge/internal/version"
)

type Host struct {
	Destination      string `toml:"destination" json:"destination"`
	Platform         string `toml:"platform" json:"platform"`
	WorkspaceRoot    string `toml:"workspace_root" json:"workspace_root"`
	BootstrapProfile string `toml:"bootstrap_profile" json:"bootstrap_profile"`
	ShellTransport   string `toml:"shell_transport,omitempty" json:"shell_transport"`
	MoshPort         string `toml:"mosh_port,omitempty" json:"mosh_port"`
}

type Sync struct {
	Engine         string        `toml:"engine" json:"engine"`
	Mode           string        `toml:"mode" json:"mode"`
	WatchMode      string        `toml:"watch_mode" json:"watch_mode"`
	SymlinkMode    string        `toml:"symlink_mode" json:"symlink_mode"`
	PauseOnIdle    bool          `toml:"pause_on_idle" json:"pause_on_idle"`
	BarrierTimeout time.Duration `toml:"-" json:"barrier_timeout"`
	BarrierText    string        `toml:"barrier_timeout" json:"-"`
}

type Terminal struct {
	Provider       string         `toml:"provider" json:"provider"`
	Scope          string         `toml:"scope" json:"scope"`
	Placement      string         `toml:"placement" json:"placement"`
	Size           string         `toml:"size" json:"size"`
	Focus          bool           `toml:"focus" json:"focus"`
	CloseOnSuccess bool           `toml:"close_on_success" json:"close_on_success"`
	HoldOnFailure  bool           `toml:"hold_on_failure" json:"hold_on_failure"`
	Zellij         ZellijTerminal `toml:"zellij" json:"zellij"`
	Tmux           TmuxTerminal   `toml:"tmux" json:"tmux"`
}

type ZellijTerminal struct {
	NearCurrentPane bool   `toml:"near_current_pane" json:"near_current_pane"`
	Direction       string `toml:"direction" json:"direction"`
	Floating        bool   `toml:"floating" json:"floating"`
}

type TmuxTerminal struct {
	Direction string `toml:"direction" json:"direction"`
	Size      string `toml:"size" json:"size"`
}

type Container struct {
	Engine  string `toml:"engine" json:"engine"`
	Image   string `toml:"image" json:"image"`
	Workdir string `toml:"workdir" json:"workdir"`
	Network string `toml:"network" json:"network"`
}

type Runtime struct {
	Kind      string    `toml:"kind" json:"kind"`
	Container Container `toml:"container" json:"container"`
}

type Workspace struct {
	Root   string   `toml:"root" json:"root"`
	Ignore []string `toml:"ignore" json:"ignore"`
}

type Environment struct {
	Profile string            `toml:"profile" json:"profile"`
	Set     map[string]string `toml:"set" json:"set"`
}

type Shell struct {
	Command      string `toml:"command" json:"command"`
	SourceUserRC bool   `toml:"source_user_rc" json:"source_user_rc"`
}

type Global struct {
	Schema      int             `toml:"schema" json:"schema"`
	DefaultHost string          `toml:"default_host,omitempty" json:"default_host"`
	Hosts       map[string]Host `toml:"hosts,omitempty" json:"hosts"`
	Sync        Sync            `toml:"sync" json:"sync"`
	Terminal    Terminal        `toml:"terminal" json:"terminal"`
	Runtime     Runtime         `toml:"runtime" json:"runtime"`
}

type Project struct {
	Schema      int         `toml:"schema" json:"schema"`
	Target      string      `toml:"target" json:"target"`
	Workspace   Workspace   `toml:"workspace" json:"workspace"`
	Environment Environment `toml:"environment" json:"environment"`
	Shell       Shell       `toml:"shell" json:"shell"`
	Runtime     Runtime     `toml:"runtime" json:"runtime"`
}

type Effective struct {
	Global       Global  `json:"global"`
	Project      Project `json:"project"`
	GlobalPath   string  `json:"global_path"`
	ProjectPath  string  `json:"project_path,omitempty"`
	ProjectRoot  string  `json:"project_root"`
	SelectedHost string  `json:"selected_host,omitempty"`
	MutagenPath  string  `json:"mutagen_path"`
	AgentPath    string  `json:"agent_path,omitempty"`
	LogLevel     string  `json:"log_level"`
}

func Defaults() Effective {
	return Effective{
		Global: Global{
			Schema: version.ConfigSchema,
			Hosts:  map[string]Host{},
			Sync: Sync{
				Engine: "mutagen", Mode: "two-way-safe", WatchMode: "portable",
				SymlinkMode: "portable", PauseOnIdle: false,
				BarrierTimeout: 2 * time.Minute, BarrierText: "2m",
			},
			Terminal: Terminal{
				Provider: "auto", Scope: "host", Placement: "right", Size: "50%",
				Focus: true, CloseOnSuccess: true, HoldOnFailure: true,
				Zellij: ZellijTerminal{NearCurrentPane: true, Direction: "right"},
				Tmux:   TmuxTerminal{Direction: "horizontal", Size: "50%"},
			},
			Runtime: Runtime{Kind: "host", Container: Container{Engine: "auto", Workdir: "/work", Network: "bridge"}},
		},
		Project: Project{
			Schema: version.ConfigSchema, Target: "linux/amd64",
			Workspace:   Workspace{Root: "."},
			Environment: Environment{Profile: "pwn", Set: map[string]string{}},
			Shell:       Shell{Command: "bash", SourceUserRC: true},
			Runtime:     Runtime{Kind: "host", Container: Container{Engine: "auto", Workdir: "/work", Network: "bridge"}},
		},
		MutagenPath: "mutagen",
		LogLevel:    "info",
	}
}

// Layer types use pointers so false and empty values can intentionally override defaults.
type globalLayer struct {
	Schema      *int            `toml:"schema"`
	DefaultHost *string         `toml:"default_host"`
	Hosts       map[string]Host `toml:"hosts"`
	Sync        *syncLayer      `toml:"sync"`
	Terminal    *terminalLayer  `toml:"terminal"`
	Runtime     *runtimeLayer   `toml:"runtime"`
}

type projectLayer struct {
	Schema      *int              `toml:"schema"`
	Target      *string           `toml:"target"`
	Workspace   *workspaceLayer   `toml:"workspace"`
	Environment *environmentLayer `toml:"environment"`
	Shell       *shellLayer       `toml:"shell"`
	Runtime     *runtimeLayer     `toml:"runtime"`
}

type syncLayer struct {
	Engine         *string `toml:"engine"`
	Mode           *string `toml:"mode"`
	WatchMode      *string `toml:"watch_mode"`
	SymlinkMode    *string `toml:"symlink_mode"`
	PauseOnIdle    *bool   `toml:"pause_on_idle"`
	BarrierTimeout *string `toml:"barrier_timeout"`
}

type terminalLayer struct {
	Provider       *string              `toml:"provider"`
	Scope          *string              `toml:"scope"`
	Placement      *string              `toml:"placement"`
	Size           *string              `toml:"size"`
	Focus          *bool                `toml:"focus"`
	CloseOnSuccess *bool                `toml:"close_on_success"`
	HoldOnFailure  *bool                `toml:"hold_on_failure"`
	Zellij         *zellijTerminalLayer `toml:"zellij"`
	Tmux           *tmuxTerminalLayer   `toml:"tmux"`
}

type zellijTerminalLayer struct {
	NearCurrentPane *bool   `toml:"near_current_pane"`
	Direction       *string `toml:"direction"`
	Floating        *bool   `toml:"floating"`
}

type tmuxTerminalLayer struct {
	Direction *string `toml:"direction"`
	Size      *string `toml:"size"`
}

type runtimeLayer struct {
	Kind      *string         `toml:"kind"`
	Container *containerLayer `toml:"container"`
}

type containerLayer struct {
	Engine  *string `toml:"engine"`
	Image   *string `toml:"image"`
	Workdir *string `toml:"workdir"`
	Network *string `toml:"network"`
}

type workspaceLayer struct {
	Root   *string   `toml:"root"`
	Ignore *[]string `toml:"ignore"`
}

type environmentLayer struct {
	Profile *string           `toml:"profile"`
	Set     map[string]string `toml:"set"`
}

type shellLayer struct {
	Command      *string `toml:"command"`
	SourceUserRC *bool   `toml:"source_user_rc"`
}

func Load(cwd string, p paths.Paths) (Effective, error) {
	e := Defaults()
	globalPath := os.Getenv("PWNBRIDGE_CONFIG")
	if globalPath == "" {
		globalPath = filepath.Join(p.Config, "config.toml")
	}
	e.GlobalPath = globalPath

	var gl globalLayer
	if err := decodeOptional(globalPath, &gl); err != nil {
		return Effective{}, err
	}
	if err := applyGlobal(&e.Global, gl); err != nil {
		return Effective{}, fmt.Errorf("global config: %w", err)
	}
	// Global runtime settings are the base layer for the portable project
	// runtime.  The project layer below can override any of them.
	e.Project.Runtime = e.Global.Runtime

	projectPath, root, err := FindProject(cwd)
	if err != nil {
		return Effective{}, err
	}
	e.ProjectPath, e.ProjectRoot = projectPath, root
	if projectPath != "" {
		var pl projectLayer
		if err := decodeOptional(projectPath, &pl); err != nil {
			return Effective{}, err
		}
		if err := applyProject(&e.Project, pl); err != nil {
			return Effective{}, fmt.Errorf("project config: %w", err)
		}
	}
	if e.Project.Workspace.Root != "." {
		base := root
		root, err = filepath.EvalSymlinks(filepath.Join(base, e.Project.Workspace.Root))
		if err != nil {
			return Effective{}, fmt.Errorf("resolve workspace root: %w", err)
		}
		relative, relErr := filepath.Rel(base, root)
		if relErr != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return Effective{}, errors.New("workspace.root resolves outside the project directory")
		}
		e.ProjectRoot = root
	}

	applyEnvironment(&e)
	if e.SelectedHost == "" {
		e.SelectedHost = e.Global.DefaultHost
	}
	if err := e.Validate(); err != nil {
		return Effective{}, err
	}
	return e, nil
}

func decodeOptional(path string, target any) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	dec := toml.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func FindProject(start string) (configPath, root string, err error) {
	root, err = filepath.Abs(start)
	if err != nil {
		return "", "", err
	}
	if root, err = filepath.EvalSymlinks(root); err != nil {
		return "", "", err
	}
	for dir := root; ; dir = filepath.Dir(dir) {
		candidate := filepath.Join(dir, ".pwnbridge.toml")
		if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
			return candidate, dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
	}
	return "", root, nil
}

func applyGlobal(dst *Global, src globalLayer) error {
	if src.Schema != nil {
		if *src.Schema != version.ConfigSchema {
			return fmt.Errorf("unsupported schema %d", *src.Schema)
		}
		dst.Schema = *src.Schema
	}
	if src.DefaultHost != nil {
		dst.DefaultHost = *src.DefaultHost
	}
	if src.Hosts != nil {
		if dst.Hosts == nil {
			dst.Hosts = map[string]Host{}
		}
		for name, host := range src.Hosts {
			dst.Hosts[name] = host
		}
	}
	if src.Sync != nil {
		if err := applySync(&dst.Sync, *src.Sync); err != nil {
			return err
		}
	}
	if src.Terminal != nil {
		applyTerminal(&dst.Terminal, *src.Terminal)
	}
	if src.Runtime != nil {
		applyRuntime(&dst.Runtime, *src.Runtime)
	}
	return nil
}

func applyProject(dst *Project, src projectLayer) error {
	if src.Schema != nil {
		if *src.Schema != version.ConfigSchema {
			return fmt.Errorf("unsupported schema %d", *src.Schema)
		}
		dst.Schema = *src.Schema
	}
	if src.Target != nil {
		dst.Target = *src.Target
	}
	if src.Workspace != nil {
		if src.Workspace.Root != nil {
			dst.Workspace.Root = *src.Workspace.Root
		}
		if src.Workspace.Ignore != nil {
			dst.Workspace.Ignore = append([]string(nil), (*src.Workspace.Ignore)...)
		}
	}
	if src.Environment != nil {
		if src.Environment.Profile != nil {
			dst.Environment.Profile = *src.Environment.Profile
		}
		if src.Environment.Set != nil {
			dst.Environment.Set = cloneMap(src.Environment.Set)
		}
	}
	if src.Shell != nil {
		if src.Shell.Command != nil {
			dst.Shell.Command = *src.Shell.Command
		}
		if src.Shell.SourceUserRC != nil {
			dst.Shell.SourceUserRC = *src.Shell.SourceUserRC
		}
	}
	if src.Runtime != nil {
		applyRuntime(&dst.Runtime, *src.Runtime)
	}
	return nil
}

func applySync(dst *Sync, src syncLayer) error {
	if src.Engine != nil {
		dst.Engine = *src.Engine
	}
	if src.Mode != nil {
		dst.Mode = *src.Mode
	}
	if src.WatchMode != nil {
		dst.WatchMode = *src.WatchMode
	}
	if src.SymlinkMode != nil {
		dst.SymlinkMode = *src.SymlinkMode
	}
	if src.PauseOnIdle != nil {
		dst.PauseOnIdle = *src.PauseOnIdle
	}
	if src.BarrierTimeout != nil {
		d, err := time.ParseDuration(*src.BarrierTimeout)
		if err != nil {
			return fmt.Errorf("invalid barrier_timeout: %w", err)
		}
		dst.BarrierText, dst.BarrierTimeout = *src.BarrierTimeout, d
	}
	return nil
}

func applyTerminal(dst *Terminal, src terminalLayer) {
	if src.Provider != nil {
		dst.Provider = *src.Provider
	}
	if src.Scope != nil {
		dst.Scope = *src.Scope
	}
	if src.Placement != nil {
		dst.Placement = *src.Placement
	}
	if src.Size != nil {
		dst.Size = *src.Size
	}
	if src.Focus != nil {
		dst.Focus = *src.Focus
	}
	if src.CloseOnSuccess != nil {
		dst.CloseOnSuccess = *src.CloseOnSuccess
	}
	if src.HoldOnFailure != nil {
		dst.HoldOnFailure = *src.HoldOnFailure
	}
	if src.Zellij != nil {
		if src.Zellij.NearCurrentPane != nil {
			dst.Zellij.NearCurrentPane = *src.Zellij.NearCurrentPane
		}
		if src.Zellij.Direction != nil {
			dst.Zellij.Direction = *src.Zellij.Direction
		}
		if src.Zellij.Floating != nil {
			dst.Zellij.Floating = *src.Zellij.Floating
		}
	}
	if src.Tmux != nil {
		if src.Tmux.Direction != nil {
			dst.Tmux.Direction = *src.Tmux.Direction
		}
		if src.Tmux.Size != nil {
			dst.Tmux.Size = *src.Tmux.Size
		}
	}
}

func applyRuntime(dst *Runtime, src runtimeLayer) {
	if src.Kind != nil {
		dst.Kind = *src.Kind
	}
	if src.Container != nil {
		if src.Container.Engine != nil {
			dst.Container.Engine = *src.Container.Engine
		}
		if src.Container.Image != nil {
			dst.Container.Image = *src.Container.Image
		}
		if src.Container.Workdir != nil {
			dst.Container.Workdir = *src.Container.Workdir
		}
		if src.Container.Network != nil {
			dst.Container.Network = *src.Container.Network
		}
	}
}

func applyEnvironment(e *Effective) {
	if value := os.Getenv("PWNBRIDGE_HOST"); value != "" {
		e.SelectedHost = value
	}
	if value := os.Getenv("PWNBRIDGE_MUTAGEN_PATH"); value != "" {
		e.MutagenPath = value
	}
	if value := os.Getenv("PWNBRIDGE_AGENT_PATH"); value != "" {
		e.AgentPath = value
	}
	if value := os.Getenv("PWNBRIDGE_LOG"); value != "" {
		e.LogLevel = value
	}
	if value := os.Getenv("PWNBRIDGE_RUNTIME"); value != "" {
		e.Project.Runtime.Kind = value
	}
}

func (e Effective) Validate() error {
	var problems []string
	if e.Global.Schema != version.ConfigSchema || e.Project.Schema != version.ConfigSchema {
		problems = append(problems, "schema must be 1")
	}
	if e.Project.Target != "linux/amd64" {
		problems = append(problems, "target must be linux/amd64")
	}
	if e.Global.Sync.Engine != "mutagen" {
		problems = append(problems, "sync.engine must be mutagen")
	}
	if e.Global.Sync.Mode != "two-way-safe" {
		problems = append(problems, "sync.mode must be two-way-safe")
	}
	if e.Global.Sync.WatchMode != "portable" {
		problems = append(problems, "sync.watch_mode must be portable")
	}
	if e.Global.Sync.SymlinkMode != "portable" && e.Global.Sync.SymlinkMode != "posix-raw" {
		problems = append(problems, "sync.symlink_mode must be portable or posix-raw")
	}
	if e.Global.Sync.BarrierTimeout <= 0 {
		problems = append(problems, "sync.barrier_timeout must be positive")
	}
	if e.Global.Terminal.Scope != "host" && e.Global.Terminal.Scope != "remote" {
		problems = append(problems, "terminal.scope must be host or remote")
	}
	if !validTerminalProvider(e.Global.Terminal.Provider, e.Global.Terminal.Scope) {
		problems = append(problems, fmt.Sprintf("terminal.provider %q is invalid for %s scope", e.Global.Terminal.Provider, e.Global.Terminal.Scope))
	}
	if !oneOf(e.Global.Terminal.Placement, "right", "down", "tab", "floating", "window") {
		problems = append(problems, "terminal.placement must be right, down, tab, floating, or window")
	}
	if e.Global.Terminal.Scope == "remote" && !oneOf(e.Global.Terminal.Placement, "right", "down") {
		problems = append(problems, "remote terminal scope supports only right or down placement")
	}
	if !validPercent(e.Global.Terminal.Size) {
		problems = append(problems, "terminal.size must be a percentage between 1% and 99%")
	}
	if !oneOf(e.Global.Terminal.Zellij.Direction, "right", "down") {
		problems = append(problems, "terminal.zellij.direction must be right or down")
	}
	if !oneOf(e.Global.Terminal.Tmux.Direction, "horizontal", "vertical", "right", "down") {
		problems = append(problems, "terminal.tmux.direction must be horizontal, vertical, right, or down")
	}
	if !validPercent(e.Global.Terminal.Tmux.Size) {
		problems = append(problems, "terminal.tmux.size must be a percentage between 1% and 99%")
	}
	if filepath.IsAbs(e.Project.Workspace.Root) || escapesParent(e.Project.Workspace.Root) {
		problems = append(problems, "workspace.root must remain inside the project directory")
	}
	if e.Project.Shell.Command != "bash" {
		problems = append(problems, "shell.command must be bash")
	}
	if e.Project.Environment.Profile != "pwn" {
		problems = append(problems, "environment.profile must be pwn")
	}
	for key, value := range e.Project.Environment.Set {
		if !validEnvironmentName(key) {
			problems = append(problems, fmt.Sprintf("environment.set key %q is invalid", key))
		}
		if strings.HasPrefix(strings.ToUpper(key), "PWNBRIDGE_") {
			problems = append(problems, fmt.Sprintf("environment.set key %q uses the reserved PWNBRIDGE_ prefix", key))
		}
		if len(value) > 64*1024 || strings.IndexByte(value, 0) >= 0 {
			problems = append(problems, fmt.Sprintf("environment.set value for %q is invalid", key))
		}
	}
	if e.Project.Runtime.Kind != "host" && e.Project.Runtime.Kind != "container" {
		problems = append(problems, "runtime.kind must be host or container")
	}
	if e.Project.Runtime.Kind == "container" && e.Project.Runtime.Container.Image == "" {
		problems = append(problems, "runtime.container.image is required for container runtime")
	}
	if e.Project.Runtime.Kind == "container" {
		container := e.Project.Runtime.Container
		if !oneOf(container.Engine, "auto", "docker", "podman") {
			problems = append(problems, "runtime.container.engine must be auto, docker, or podman")
		}
		if unsafeArgument(container.Image, 512) {
			problems = append(problems, "runtime.container.image contains unsafe characters")
		}
		cleanWorkdir := path.Clean(container.Workdir)
		if cleanWorkdir != "/work" && !strings.HasPrefix(cleanWorkdir, "/work/") {
			problems = append(problems, "runtime.container.workdir must be /work or a directory beneath /work")
		}
		if unsafeArgument(container.Network, 128) {
			problems = append(problems, "runtime.container.network contains unsafe characters")
		}
		if e.Global.Terminal.Scope == "remote" {
			problems = append(problems, "remote terminal scope is incompatible with container runtime")
		}
	}
	if e.SelectedHost != "" {
		if _, ok := e.Global.Hosts[e.SelectedHost]; !ok {
			problems = append(problems, fmt.Sprintf("selected host %q is not configured", e.SelectedHost))
		}
	}
	for name, host := range e.Global.Hosts {
		if !ValidHostName(name) {
			problems = append(problems, fmt.Sprintf("invalid host name %q", name))
		}
		if host.Destination == "" {
			problems = append(problems, fmt.Sprintf("hosts.%s.destination is required", name))
		}
		if unsafeArgument(host.Destination, 512) {
			problems = append(problems, fmt.Sprintf("hosts.%s.destination contains unsafe characters", name))
		}
		if host.Platform != "linux/amd64" {
			problems = append(problems, fmt.Sprintf("hosts.%s.platform must be linux/amd64", name))
		}
		if host.WorkspaceRoot != "" && !validRemoteWorkspaceRoot(host.WorkspaceRoot) {
			problems = append(problems, fmt.Sprintf("hosts.%s.workspace_root must be a safe ~/... or absolute path", name))
		}
		if host.BootstrapProfile != "" && host.BootstrapProfile != "pwn" {
			problems = append(problems, fmt.Sprintf("hosts.%s.bootstrap_profile must be pwn", name))
		}
		if host.ShellTransport != "" && !oneOf(host.ShellTransport, "auto", "ssh", "mosh") {
			problems = append(problems, fmt.Sprintf("hosts.%s.shell_transport must be auto, ssh, or mosh", name))
		}
		if host.MoshPort != "" && !validMoshPort(host.MoshPort) {
			problems = append(problems, fmt.Sprintf("hosts.%s.mosh_port must be a UDP port or ascending range", name))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func validMoshPort(value string) bool {
	parts := strings.Split(value, ":")
	if len(parts) < 1 || len(parts) > 2 {
		return false
	}
	ports := make([]int, len(parts))
	for index, part := range parts {
		port, err := strconv.Atoi(part)
		if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != part {
			return false
		}
		ports[index] = port
	}
	return len(ports) == 1 || ports[0] <= ports[1]
}

// ValidHostName reports whether name is safe to use as a stable configuration
// key, binding identifier, and diagnostic label. Keep this deliberately narrow:
// destinations carry the user's SSH alias, while names are local identifiers.
func ValidHostName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func validEnvironmentName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for index, r := range name {
		if index == 0 && !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return false
		}
		if index > 0 && !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func validRemoteWorkspaceRoot(value string) bool {
	if len(value) > 512 || strings.Contains(value, ":") {
		return false
	}
	for _, r := range value {
		if r == 0 || r < 32 || r == 127 {
			return false
		}
	}
	if strings.HasPrefix(value, "~/") {
		relative := path.Clean(strings.TrimPrefix(value, "~/"))
		return relative != "." && relative != ".." && !strings.HasPrefix(relative, "../") && !path.IsAbs(relative)
	}
	clean := path.Clean(value)
	return path.IsAbs(clean) && clean != "/"
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func validTerminalProvider(value, scope string) bool {
	if scope == "remote" {
		return oneOf(value, "auto", "tmux", "zellij", "remote-tmux", "remote-zellij")
	}
	if oneOf(value, "auto", "zellij", "tmux", "wezterm", "kitty", "iterm2", "terminal-app") {
		return true
	}
	if !strings.HasPrefix(value, "custom:") {
		return false
	}
	name := strings.TrimPrefix(value, "custom:")
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func validPercent(value string) bool {
	if !strings.HasSuffix(value, "%") {
		return false
	}
	n, err := strconv.Atoi(strings.TrimSuffix(value, "%"))
	return err == nil && n > 0 && n < 100
}

func escapesParent(value string) bool {
	clean := filepath.Clean(value)
	return clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator))
}

func unsafeArgument(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.HasPrefix(value, "-") {
		return true
	}
	for _, r := range value {
		if r == 0 || r < 32 || r == 127 || r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return true
		}
	}
	return false
}

func SaveGlobal(path string, g Global) error {
	g.Schema = version.ConfigSchema
	if g.Sync.BarrierText == "" {
		g.Sync.BarrierText = g.Sync.BarrierTimeout.String()
	}
	data, err := toml.Marshal(g)
	if err != nil {
		return fmt.Errorf("encode global config: %w", err)
	}
	return fsutil.AtomicWrite(path, data, 0o600)
}

func SaveProject(path string, p Project) error {
	p.Schema = version.ConfigSchema
	data, err := toml.Marshal(p)
	if err != nil {
		return fmt.Errorf("encode project config: %w", err)
	}
	return fsutil.AtomicWrite(path, data, 0o600)
}

func cloneMap(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
