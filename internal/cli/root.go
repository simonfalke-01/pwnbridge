package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/simonfalke-01/pwnbridge/internal/agent"
	"github.com/simonfalke-01/pwnbridge/internal/bootstrap"
	bootstrapui "github.com/simonfalke-01/pwnbridge/internal/bootstrap/ui"
	"github.com/simonfalke-01/pwnbridge/internal/broker"
	"github.com/simonfalke-01/pwnbridge/internal/config"
	"github.com/simonfalke-01/pwnbridge/internal/diagnostics"
	"github.com/simonfalke-01/pwnbridge/internal/fsutil"
	"github.com/simonfalke-01/pwnbridge/internal/identity"
	"github.com/simonfalke-01/pwnbridge/internal/paths"
	"github.com/simonfalke-01/pwnbridge/internal/protocol"
	"github.com/simonfalke-01/pwnbridge/internal/recovery"
	"github.com/simonfalke-01/pwnbridge/internal/shell"
	"github.com/simonfalke-01/pwnbridge/internal/syncer"
	"github.com/simonfalke-01/pwnbridge/internal/terminal/provider"
	"github.com/simonfalke-01/pwnbridge/internal/transport"
	"github.com/simonfalke-01/pwnbridge/internal/version"
	"github.com/simonfalke-01/pwnbridge/internal/workspace"
)

type App struct {
	Paths       paths.Paths
	In          *os.File
	Out         io.Writer
	Err         io.Writer
	HostFlag    string
	ProgramName string
}

type projectContext struct {
	Config  config.Effective
	HostID  string
	Host    config.Host
	WS      workspace.Workspace
	State   workspace.State
	Manager workspace.Manager
	Sync    syncer.Mutagen
}

type activeSession struct {
	app        *App
	project    *projectContext
	ID         string
	Token      string
	Nonce      string
	RemoteDir  string
	RuntimeDir string
	RecordPath string
	Record     broker.SessionRecord
	Broker     *broker.Broker
	Master     *transport.Master
	Probe      transport.HostProbe
	Lease      *workspace.Lock
	closed     bool
}

func New() (*App, error) {
	p, err := paths.Resolve()
	if err != nil {
		return nil, err
	}
	return &App{Paths: p, In: os.Stdin, Out: os.Stdout, Err: os.Stderr, ProgramName: filepath.Base(os.Args[0])}, nil
}

func (a *App) Root() *cobra.Command {
	if a.ProgramName == "pb" {
		return a.pbRoot()
	}
	root := &cobra.Command{
		Use: "pwnbridge", Short: "Make a remote Linux x86-64 pwn environment feel local",
		Version:      fmt.Sprintf("%s (%s, %s)", version.Version, version.Commit, version.Date),
		SilenceUsage: true, SilenceErrors: true,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 0 {
				return errors.New("use `pwnbridge run -- COMMAND` or the concise `pb COMMAND`")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error { return a.shell(cmd.Context()) },
	}
	root.SetVersionTemplate("pwnbridge {{.Version}}\n")
	root.Flags().BoolP("version", "v", false, "version for pwnbridge")
	root.PersistentFlags().StringVar(&a.HostFlag, "host", "", "override the configured remote host")
	root.AddCommand(
		&cobra.Command{Use: "shell", Short: "Open the managed remote shell", Long: "Open managed remote Bash in the current terminal. The default auto transport uses pwnbridge predictive echo over inline SSH. Select ssh for plain SSH or mosh for an explicit roaming, full-screen Mosh session.", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return a.shell(cmd.Context()) }},
		a.runCommand(), a.initCommand(), a.statusCommand(), a.doctorCommand(), a.supportCommand(), a.stopCommand(), a.cleanCommand(),
		a.hostCommand(), a.syncCommand(), a.terminalCommand(), a.runtimeCommand(), a.configCommand(), a.versionCommand(),
		a.paneCommand(),
	)
	root.AddCommand(completionCommand(root))
	return root
}

func (a *App) pbRoot() *cobra.Command {
	cmd := &cobra.Command{
		Use:                "pb COMMAND [ARG...]",
		Short:              "Run one command in the remote pwn environment",
		SilenceUsage:       true,
		SilenceErrors:      true,
		DisableFlagParsing: true,
		Args:               cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if args[0] == "-h" || args[0] == "--help" {
				return cmd.Help()
			}
			if args[0] == "--" {
				return errors.New("`pb` does not need `--`; use `pb COMMAND [ARG...]`")
			}
			return a.run(cmd.Context(), args, "auto")
		},
	}
	return cmd
}

func (a *App) loadProject(ctx context.Context, requireHost bool) (*projectContext, error) {
	if err := a.Paths.Ensure(); err != nil {
		return nil, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	effective, err := config.Load(cwd, a.Paths)
	if err != nil {
		return nil, err
	}
	manager := workspace.Manager{Paths: a.Paths}
	hostID := effective.SelectedHost
	if a.HostFlag != "" {
		hostID = a.HostFlag
	} else if os.Getenv("PWNBRIDGE_HOST") == "" {
		if binding, bindErr := manager.Binding(effective.ProjectRoot); bindErr != nil {
			return nil, bindErr
		} else if binding != "" {
			hostID = binding
		}
	}
	effective.SelectedHost = hostID
	if hostID == "" {
		if requireHost {
			return nil, errors.New("no host selected; run `pwnbridge host add NAME DESTINATION --check` (the first host becomes default), or select one with `pwnbridge host default NAME` or `pwnbridge host use NAME`")
		}
		mutagen := syncer.Mutagen{Runner: syncer.DefaultRunner(effective.MutagenPath, a.Paths.State)}
		return &projectContext{Config: effective, Manager: manager, Sync: mutagen}, nil
	}
	host, ok := effective.Global.Hosts[hostID]
	if !ok {
		if !requireHost {
			mutagen := syncer.Mutagen{Runner: syncer.DefaultRunner(effective.MutagenPath, a.Paths.State)}
			return &projectContext{Config: effective, Manager: manager, Sync: mutagen}, nil
		}
		return nil, fmt.Errorf("host %q is not configured", hostID)
	}
	remoteRoot := host.WorkspaceRoot
	if remoteRoot == "" {
		remoteRoot = "~/.local/share/pwnbridge/workspaces"
	}
	ws, err := manager.Resolve(effective.ProjectRoot, hostID, remoteRoot)
	if err != nil {
		return nil, err
	}
	state, err := manager.LoadState(ws)
	if err != nil {
		return nil, err
	}
	mutagen := syncer.Mutagen{Runner: syncer.DefaultRunner(effective.MutagenPath, a.Paths.State)}
	return &projectContext{Config: effective, HostID: hostID, Host: host, WS: ws, State: state, Manager: manager, Sync: mutagen}, nil
}

func (a *App) ensureSync(ctx context.Context, p *projectContext, client transport.Client) error {
	if p.Config.Global.Sync.SymlinkMode == "posix-raw" {
		fmt.Fprintln(a.Err, "warning: sync.symlink_mode=posix-raw preserves raw links and can create cross-platform escape targets; portable is safer")
	}
	lock, err := workspace.AcquireLock(p.WS.LockPath)
	if err != nil {
		return err
	}
	defer lock.Close()
	remotePath := remoteShellPath(p.WS.RemotePath)
	remoteOperation := "umask 077; mkdir -p -- " + remotePath
	operation := "create"
	if p.State.MutagenIdentifier != "" {
		remoteOperation = "test -d " + remotePath + " && test ! -L " + remotePath
		operation = "validate"
	}
	if _, remoteErr := client.Raw(ctx, remoteOperation); remoteErr != nil {
		if operation == "validate" {
			return fmt.Errorf("remote workspace root is missing or was replaced; execution is blocked to protect the local copy. Verify local files, then run `pwnbridge clean` to explicitly create new synchronization history: %w", remoteErr)
		}
		return fmt.Errorf("create remote workspace: %w", remoteErr)
	}
	ignores, err := projectIgnores(p.Config.ProjectRoot, p.Config.Project.Workspace.Ignore)
	if err != nil {
		return err
	}
	spec := syncer.Spec{Workspace: p.WS, Destination: p.Host.Destination, Config: p.Config.Global.Sync, Ignores: ignores}
	timeout, cancel := context.WithTimeout(ctx, p.Config.Global.Sync.BarrierTimeout)
	defer cancel()
	if _, err := p.Sync.Prepare(timeout, spec, &p.State); err != nil {
		return err
	}
	p.State.RemoteRetained = true
	if err := p.Manager.SaveState(p.WS, p.State); err != nil {
		return err
	}
	return nil
}

const maxSharedControlSocketPath = 96

func (a *App) sharedControlDir(p *projectContext) (string, error) {
	key := workspace.Fingerprint("ssh-v1", p.WS.MachineID, p.WS.ID, p.Host.Destination)[:24]
	root := filepath.Join(a.Paths.Cache, "ssh")
	candidate := filepath.Join(root, key)
	if len(filepath.Join(candidate, "c")) > maxSharedControlSocketPath {
		root = filepath.Join(os.TempDir(), fmt.Sprintf("pwnbridge-%d", os.Getuid()), "ssh")
		candidate = filepath.Join(root, key)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", fmt.Errorf("create shared SSH cache root: %w", err)
	}
	if err := fsutil.ValidatePrivateDirectory(root); err != nil {
		return "", fmt.Errorf("validate shared SSH cache root: %w", err)
	}
	return candidate, nil
}

func (a *App) stopSharedControlMaster(ctx context.Context, p *projectContext) error {
	dir, err := a.sharedControlDir(p)
	if err != nil {
		return err
	}
	return transport.New(p.Host.Destination, "").StopSharedControlMaster(ctx, dir)
}

func (a *App) barrier(ctx context.Context, p *projectContext) error {
	lock, err := workspace.AcquireLock(p.WS.LockPath)
	if err != nil {
		return err
	}
	defer lock.Close()
	timeout, cancel := context.WithTimeout(ctx, p.Config.Global.Sync.BarrierTimeout)
	defer cancel()
	if err := p.Sync.Resume(timeout, p.State.MutagenIdentifier); err != nil {
		return err
	}
	_, err = p.Sync.Barrier(timeout, p.State.MutagenIdentifier)
	return err
}

const (
	implicitWorkspaceMaxBytes = int64(2 << 30)
	implicitWorkspaceMaxFiles = 10_000
)

func guardImplicitWorkspace(root, projectConfig string) error {
	if projectConfig != "" {
		return nil
	}
	ignoredDirectories := map[string]bool{
		".git": true, ".pwnbridge": true, ".venv": true, "venv": true,
		"__pycache__": true, ".idea": true, ".vscode": true,
	}
	var bytes, files int64
	errLimit := errors.New("implicit workspace safety limit exceeded")
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path != root && entry.IsDir() && ignoredDirectories[entry.Name()] {
			return fs.SkipDir
		}
		if entry.IsDir() || entry.Name() == ".DS_Store" || strings.HasSuffix(entry.Name(), ".pyc") {
			return nil
		}
		files++
		if entry.Type().IsRegular() {
			info, infoErr := entry.Info()
			if infoErr != nil {
				return infoErr
			}
			bytes += info.Size()
		}
		if bytes > implicitWorkspaceMaxBytes || files > implicitWorkspaceMaxFiles {
			return errLimit
		}
		return nil
	})
	if err == nil {
		return nil
	}
	if !errors.Is(err, errLimit) {
		return fmt.Errorf("inspect implicit workspace %s: %w", root, err)
	}
	return fmt.Errorf("refusing to synchronize implicit workspace %s: it exceeds the automatic safety limit (at least %.1f GiB or %d files); cd into the challenge directory, or run `pwnbridge init` here to explicitly confirm this project root", root, float64(bytes)/(1<<30), files)
}

func (a *App) startSession(ctx context.Context, p *projectContext, progress *launchProgress) (session *activeSession, resultErr error) {
	progress.Stage("Checking workspace")
	if err := guardImplicitWorkspace(p.Config.ProjectRoot, p.Config.ProjectPath); err != nil {
		return nil, err
	}
	hostLifecycle, err := workspace.AcquireLock(a.hostLifecycleLockPath(p.HostID))
	if err != nil {
		return nil, fmt.Errorf("acquire host lifecycle lease: %w", err)
	}
	defer func() {
		if hostLifecycle != nil {
			resultErr = errors.Join(resultErr, hostLifecycle.Close())
		}
	}()
	latest, err := config.LoadGlobal(a.Paths)
	if err != nil {
		return nil, err
	}
	if current, ok := latest.Global.Hosts[p.HostID]; !ok || current != p.Host {
		return nil, fmt.Errorf("host %q was removed or changed; retry with current configuration", p.HostID)
	}
	if _, err := a.liveSessions(p.WS.LocalRoot); err != nil {
		return nil, err
	}
	asset, err := transport.FindAgentAsset(p.Config.AgentPath)
	if err != nil {
		return nil, err
	}
	id, err := identity.Random(16)
	if err != nil {
		return nil, err
	}
	token, err := identity.Random(32)
	if err != nil {
		return nil, err
	}
	nonce, err := identity.Random(16)
	if err != nil {
		return nil, err
	}
	runtimeDir, err := os.MkdirTemp("", "pb-"+id[:8]+"-")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(runtimeDir, 0o700); err != nil {
		os.RemoveAll(runtimeDir)
		return nil, err
	}
	var b *broker.Broker
	var master *transport.Master
	var lease *workspace.Lock
	var recordPath, leasePath string
	defer func() {
		if resultErr == nil {
			return
		}
		if b != nil {
			_ = b.Close()
		}
		if master != nil {
			_ = master.Close()
		}
		if recordPath != "" {
			_ = os.Remove(recordPath)
		}
		if lease != nil {
			_ = lease.Close()
		}
		if leasePath != "" {
			_ = os.Remove(leasePath)
		}
		_ = os.RemoveAll(runtimeDir)
	}()

	progress.Stage("Connecting to " + p.HostID)
	client := transport.New(p.Host.Destination, "")
	controlDir, err := a.sharedControlDir(p)
	if err != nil {
		return nil, err
	}
	master, err = client.StartSharedControlMaster(ctx, controlDir)
	if err != nil {
		return nil, err
	}
	client = master.Client

	progress.Stage("Syncing workspace")
	type agentPreparation struct {
		path  string
		probe transport.HostProbe
		err   error
	}
	prepareCtx, cancelPrepare := context.WithCancel(ctx)
	prepared := make(chan agentPreparation, 1)
	go func() {
		path, probe, prepareErr := client.PrepareAgent(prepareCtx, asset)
		prepared <- agentPreparation{path: path, probe: probe, err: prepareErr}
	}()
	syncErr := a.ensureSync(prepareCtx, p, client)
	if syncErr != nil {
		cancelPrepare()
	}
	agentResult := <-prepared
	cancelPrepare()
	if syncErr != nil {
		return nil, syncErr
	}
	if agentResult.err != nil {
		return nil, agentResult.err
	}
	remoteAgent, probe := agentResult.path, agentResult.probe
	client.AgentPath = remoteAgent
	master.Client.AgentPath = remoteAgent
	remoteDir := filepath.Join(probe.Home, ".cache", "pwnbridge", "sessions", id)
	localSocket := filepath.Join(runtimeDir, "b.sock")
	remoteSocket := filepath.Join(remoteDir, "broker.sock")
	prepare := "umask 077; mkdir -p -- " + remoteShellPath(filepath.Join(remoteDir, "requests"))
	if _, prepareErr := client.Raw(ctx, prepare); prepareErr != nil {
		return nil, fmt.Errorf("create remote session directory: %w", prepareErr)
	}
	recordPath = filepath.Join(a.Paths.State, "sessions", id+".json")
	leasePath = recordPath + ".lease"
	executable, err := paneExecutable()
	if err != nil {
		return nil, err
	}
	terminalConfig := p.Config.Global.Terminal
	record := broker.SessionRecord{
		ID: id, OwnerPID: os.Getpid(), Token: token, LocalSocket: localSocket, RemoteSocket: remoteSocket,
		Destination: p.Host.Destination, AgentPath: remoteAgent, RemoteSessionDir: remoteDir,
		LocalWorkspace: p.WS.LocalRoot, Executable: executable, Provider: p.Config.Global.Terminal.Provider,
		RecordPath: recordPath, LeasePath: leasePath,
		Placement: terminalConfig.Placement, Size: terminalConfig.Size,
		Focus: p.Config.Global.Terminal.Focus, CloseOnSuccess: p.Config.Global.Terminal.CloseOnSuccess,
		HoldOnFailure:         p.Config.Global.Terminal.HoldOnFailure,
		ZellijNearCurrentPane: terminalConfig.Zellij.NearCurrentPane,
		ZellijDirection:       terminalConfig.Zellij.Direction, ZellijFloating: terminalConfig.Zellij.Floating,
		TmuxDirection: terminalConfig.Tmux.Direction, TmuxSize: terminalConfig.Tmux.Size,
		Runtime: protocol.RuntimeSpec{
			Kind: p.Config.Project.Runtime.Kind, Engine: p.Config.Project.Runtime.Container.Engine,
			Image: p.Config.Project.Runtime.Container.Image, Workdir: p.Config.Project.Runtime.Container.Workdir,
			Network: p.Config.Project.Runtime.Container.Network, ID: "pwnbridge-" + id,
			Workspace: p.WS.RemotePath, WorkspaceID: p.WS.ID, SessionDir: remoteDir,
		},
	}
	progress.Stage("Starting debugger bridge")
	if p.Config.Global.Terminal.Scope == "remote" {
		record.LocalSocket, record.RemoteSocket = "", ""
	} else {
		registry := provider.NewRegistry(runtimeDir)
		b = broker.New(record, registry)
		b.BeforeOpen = func(barrierCtx context.Context) error { return a.barrier(barrierCtx, p) }
		if err = b.Start(); err == nil {
			record.LocalTCP = b.Record.LocalTCP
			err = master.ConfigureBroker(ctx, localSocket, remoteSocket, record.LocalTCP)
			if err == nil && p.Config.Project.Runtime.Kind == "container" && strings.HasPrefix(master.BrokerAddress, "tcp:") {
				err = errors.New("container debugger panes require the remote socat relay for TCP forwarding fallback")
			}
		}
		if err != nil {
			_ = b.Close()
			b = nil
			forwardErr := err
			record.LocalSocket, record.LocalTCP, record.RemoteSocket = "", "", ""
			master.BrokerAddress, master.RemoteSocket, master.LocalSocket = "", "", ""
			fmt.Fprintf(a.Err, "warning: debugger host panes are unavailable (%v); shell/run remain usable, or set terminal.scope=remote\n", forwardErr)
			err = nil
		}
	}
	record.ControlPath = master.ControlPath
	record.RemoteSocket = master.BrokerAddress
	if b != nil {
		b.Record = record
	}
	lease, err = workspace.AcquireLock(leasePath)
	if err != nil {
		return nil, fmt.Errorf("acquire session lease: %w", err)
	}
	if b != nil {
		_, err = master.Run(ctx, "broker-ping", protocol.BrokerPing{SessionID: id, Address: record.RemoteSocket, Token: token})
	}
	if err != nil {
		return nil, fmt.Errorf("reverse broker verification failed: %w", err)
	}
	// Publish the session only after its control plane is usable. This makes
	// the atomic record a readiness boundary for `stop` and other processes,
	// rather than exposing a half-initialized broker verification window.
	if err := broker.SaveSession(recordPath, record); err != nil {
		return nil, err
	}
	closeErr := hostLifecycle.Close()
	hostLifecycle = nil
	if closeErr != nil {
		return nil, closeErr
	}
	return &activeSession{app: a, project: p, ID: id, Token: token, Nonce: nonce, RemoteDir: remoteDir, RuntimeDir: runtimeDir, RecordPath: recordPath, Record: record, Broker: b, Master: master, Probe: probe, Lease: lease}, nil
}

// paneExecutable returns the real client executable rather than the path used
// to invoke it. In particular, pb is normally a symlink to pwnbridge. Recording
// the symlink would make a debugger pane run `pb __pane ...`, which the client
// interprets as a one-shot remote command instead of its internal pane helper.
func paneExecutable() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	return resolvePaneExecutable(executable)
}

func resolvePaneExecutable(executable string) (string, error) {
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return "", fmt.Errorf("resolve pwnbridge executable %s: %w", executable, err)
	}
	return resolved, nil
}

func (s *activeSession) runtimeSpec() protocol.RuntimeSpec {
	return s.Record.Runtime
}

func (s *activeSession) environment() map[string]string {
	env := map[string]string{}
	for key, value := range s.project.Config.Project.Environment.Set {
		env[key] = value
	}
	termName := os.Getenv("TERM")
	if termName == "" || termName == "dumb" {
		termName = "xterm-256color"
	}
	env["TERM"] = termName
	for _, key := range []string{"COLORTERM"} {
		if value := os.Getenv(key); value != "" {
			env[key] = value
		}
	}
	if _, configured := env["LANG"]; !configured {
		env["LANG"] = "C.UTF-8"
	}
	if _, configured := env["LC_ALL"]; !configured {
		env["LC_ALL"] = "C.UTF-8"
	}
	return env
}

func (s *activeSession) terminalSpec() protocol.TerminalSpec {
	terminal := protocol.TerminalSpec{
		SessionID: s.ID,
		Scope:     s.project.Config.Global.Terminal.Scope,
		Provider:  s.project.Config.Global.Terminal.Provider,
		// Provider-specific host layout is resolved by the local broker after
		// auto-selection. Remote scope supports only the global right/down value.
		Placement: s.project.Config.Global.Terminal.Placement,
	}
	if s.Record.RemoteSocket != "" {
		terminal.Broker, terminal.Token = s.Record.RemoteSocket, s.Token
	}
	return terminal
}

func (s *activeSession) Close(ctx context.Context) error {
	if s == nil || s.closed {
		return nil
	}
	s.closed = true
	var errs []error
	if s.Broker != nil {
		if err := s.Broker.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.Master != nil {
		remoteCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, err := s.Master.Run(remoteCtx, "cleanup", protocol.CleanupRequest{SessionID: s.ID, SessionDir: s.RemoteDir, Runtime: s.runtimeSpec()})
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("remote cleanup: %w", err))
		}
	}
	finalSyncOK := true
	if err := s.app.barrier(ctx, s.project); err != nil {
		finalSyncOK = false
		errs = append(errs, fmt.Errorf("final sync: %w", err))
	}
	if finalSyncOK && s.project.Config.Global.Sync.PauseOnIdle && s.project.State.MutagenIdentifier != "" {
		if other, leaseErr := s.app.hasOtherLease(s.project.WS.LocalRoot, s.ID); leaseErr != nil {
			errs = append(errs, leaseErr)
		} else if !other {
			if err := s.project.Sync.Pause(ctx, s.project.State.MutagenIdentifier); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if s.Master != nil {
		_ = s.Master.Close()
	}
	_ = os.Remove(s.RecordPath)
	if s.Lease != nil {
		_ = s.Lease.Close()
		_ = os.Remove(s.Record.LeasePath)
	}
	_ = os.RemoveAll(s.RuntimeDir)
	return errors.Join(errs...)
}

func (a *App) shell(ctx context.Context) (result error) {
	p, err := a.loadProject(ctx, true)
	if err != nil {
		return err
	}
	progress := newLaunchProgress(a.Err)
	defer progress.Stop()
	session, err := a.startSession(ctx, p, progress)
	if err != nil {
		return err
	}
	defer func() {
		cleanupProgress := newLaunchProgress(a.Err)
		cleanupProgress.Stage("Saving workspace")
		if closeErr := session.Close(context.Background()); closeErr != nil {
			result = errors.Join(result, closeErr)
		}
		cleanupProgress.Stop()
	}()
	selectedTransport, err := shellTransport(p.Host, p.Config.Global.Terminal.Scope, session)
	if err != nil {
		return err
	}
	request := protocol.ShellRequest{Cwd: p.WS.RemotePath, Shell: p.Config.Project.Shell.Command, SourceUserRC: p.Config.Project.Shell.SourceUserRC, Nonce: session.Nonce, SessionID: session.ID, PromptHost: p.HostID, PromptPath: p.WS.Slug, Environment: session.environment(), Terminal: session.terminalSpec(), Runtime: session.runtimeSpec(), RemoteBarrier: selectedTransport == "mosh"}
	encoded, err := agent.EncodeRequest(request)
	if err != nil {
		return err
	}
	cmd := session.Master.Command(ctx, true, "shell", encoded)
	proxy := shell.Proxy{In: a.In, Out: a.Out, Err: a.Err, Nonce: session.Nonce, Barrier: func(barrierCtx context.Context) error { return a.barrier(barrierCtx, p) }}
	if selectedTransport == "inline" {
		proxy.PredictEcho = true
	} else if selectedTransport == "mosh" {
		progress.Stage("Opening Mosh shell")
		cmd = session.Master.MoshCommand(ctx, "shell", encoded, p.Host.MoshPort)
		proxy.Nonce, proxy.Barrier, proxy.ExitNotice = "", nil, "[mosh is exiting.]"
	}
	progress.Stop()
	if err := proxy.Run(ctx, cmd); ctx.Err() != nil {
		return ctx.Err()
	} else {
		return err
	}
}

func shellTransport(host config.Host, terminalScope string, session *activeSession) (string, error) {
	wanted := host.ShellTransport
	if wanted == "" {
		wanted = "auto"
	}
	if wanted == "auto" {
		return "inline", nil
	}
	if wanted == "ssh" {
		return "ssh", nil
	}
	var reason string
	switch {
	case terminalScope == "remote":
		reason = "terminal.scope=remote uses SSH because remote multiplexer control is not compatible with Mosh"
	case session.Broker == nil || session.Record.RemoteSocket == "":
		reason = "the authenticated synchronization bridge is unavailable (check reverse SSH forwarding)"
	case !transport.MoshAvailable(session.Master.Client, session.Probe):
		if !transport.LocalMoshAvailable(session.Master.Client) {
			reason = "the local mosh client is not installed"
		} else {
			reason = "mosh-server is not installed on the remote host"
		}
	default:
		return "mosh", nil
	}
	if wanted == "mosh" {
		return "", fmt.Errorf("mosh shell requested but %s", reason)
	}
	return "ssh", nil
}

func (a *App) runCommand() *cobra.Command {
	var ttyMode string
	cmd := &cobra.Command{Use: "run -- COMMAND [ARG...]", Short: "Run a command in the remote workspace", Args: cobra.MinimumNArgs(1), DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error { return a.run(cmd.Context(), args, ttyMode) },
	}
	cmd.Flags().StringVar(&ttyMode, "tty", "auto", "PTY mode: auto, always, or never")
	return cmd
}

func (a *App) run(ctx context.Context, args []string, ttyMode string) (result error) {
	if ttyMode != "auto" && ttyMode != "always" && ttyMode != "never" {
		return fmt.Errorf("--tty must be auto, always, or never (got %q)", ttyMode)
	}
	p, err := a.loadProject(ctx, true)
	if err != nil {
		return err
	}
	progress := newLaunchProgress(a.Err)
	defer progress.Stop()
	session, err := a.startSession(ctx, p, progress)
	if err != nil {
		return err
	}
	defer func() {
		cleanupProgress := newLaunchProgress(a.Err)
		cleanupProgress.Stage("Saving workspace")
		if closeErr := session.Close(context.Background()); closeErr != nil {
			result = errors.Join(result, closeErr)
		}
		cleanupProgress.Stop()
	}()
	request := protocol.ExecRequest{Args: args, Cwd: p.WS.RemotePath, Environment: session.environment(), Terminal: session.terminalSpec(), Runtime: session.runtimeSpec()}
	encoded, err := agent.EncodeRequest(request)
	if err != nil {
		return err
	}
	tty := ttyMode == "always" || ttyMode == "auto" && term.IsTerminal(int(a.In.Fd()))
	remote := session.Master.Command(ctx, tty, "exec", encoded)
	progress.Stop()
	if tty && term.IsTerminal(int(a.In.Fd())) {
		// Put SSH behind the same local PTY proxy as the managed shell. Merely
		// attaching its stdio directly gives some SSH/OpenSSH combinations a
		// stale or zero-sized remote PTY, which breaks carriage-return progress
		// renderers such as pwninit/indicatif. The proxy copies the real window
		// size before launch, forwards SIGWINCH, and restores terminal mode.
		proxy := shell.Proxy{In: a.In, Out: a.Out, Err: a.Err, Nonce: session.Nonce}
		if err := proxy.Run(ctx, remote); ctx.Err() != nil {
			return ctx.Err()
		} else {
			return err
		}
	}
	remote.Stdin, remote.Stdout, remote.Stderr = a.In, a.Out, a.Err
	if err := remote.Run(); ctx.Err() != nil {
		return ctx.Err()
	} else {
		return err
	}
}

func (a *App) initCommand() *cobra.Command {
	return &cobra.Command{Use: "init", Short: "Create optional portable project configuration", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		configPath := filepath.Join(cwd, ".pwnbridge.toml")
		if _, err := os.Stat(configPath); err == nil {
			return fmt.Errorf("%s already exists", configPath)
		}
		content := "schema = 1\ntarget = \"linux/amd64\"\n\n[workspace]\nroot = \".\"\nignore = []\n\n[environment]\nprofile = \"pwn\"\nset = {}\n\n[shell]\ncommand = \"bash\"\nsource_user_rc = true\n\n[runtime]\nkind = \"host\"\n"
		if err := fsutil.AtomicWrite(configPath, []byte(content), 0o600); err != nil {
			return err
		}
		ignorePath := filepath.Join(cwd, ".pwnbridgeignore")
		if _, err := os.Stat(ignorePath); errors.Is(err, os.ErrNotExist) {
			if err := fsutil.AtomicWrite(ignorePath, []byte("# Project-specific synchronization ignores\n"), 0o600); err != nil {
				return err
			}
		}
		fmt.Fprintln(a.Out, "created", configPath)
		return nil
	}}
}

func (a *App) statusCommand() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{Use: "status", Short: "Show project, host, sync, and runtime status", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		p, err := a.loadProject(cmd.Context(), false)
		if err != nil {
			return err
		}
		result := map[string]any{"project_root": p.Config.ProjectRoot, "host": p.HostID}
		if p.HostID != "" {
			result["workspace"] = p.WS
			result["state"] = p.State
			if sessions, sessionErr := a.liveSessions(p.WS.LocalRoot); sessionErr == nil {
				ids := make([]string, 0, len(sessions))
				for _, session := range sessions {
					ids = append(ids, session.ID)
				}
				result["active_sessions"] = ids
			} else {
				result["session_error"] = sessionErr.Error()
			}
			if p.State.MutagenIdentifier != "" {
				report, statusErr := p.Sync.Status(cmd.Context(), p.State.MutagenIdentifier)
				if statusErr != nil {
					result["sync_error"] = statusErr.Error()
				} else {
					result["sync"] = report
				}
			}
		}
		if asJSON {
			return writeJSON(a.Out, result)
		}
		fmt.Fprintf(a.Out, "project: %s\nhost: %s\n", p.Config.ProjectRoot, empty(p.HostID, "not selected"))
		if p.HostID != "" {
			fmt.Fprintf(a.Out, "remote: %s\nsync session: %s\n", p.WS.RemotePath, empty(p.State.MutagenIdentifier, "not created"))
		}
		return nil
	}}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

func (a *App) doctorCommand() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{Use: "doctor", Short: "Check local and selected-host prerequisites", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		p, err := a.loadProject(cmd.Context(), false)
		if err != nil {
			return err
		}
		checks, complete, cause := collectLocalDoctor(cmd.Context(), p.Sync, p.Host.ShellTransport, defaultDoctorTimeouts)
		if p.HostID != "" && cause == nil {
			recipe, explanations, recipeErr := resolveDoctorRecipe(p.Host.BootstrapProfile, p.Config.Global.BootstrapProfiles)
			client := transport.New(p.Host.Destination, "")
			remoteChecks, remoteComplete, remoteCause := collectRemoteDoctor(cmd.Context(), client, remoteDoctorOptions{
				Recipe: recipe, RecipeExplanations: explanations, RecipeError: recipeErr,
				ContainerEngine: configuredContainerEngine(p.Config), ShellTransport: p.Host.ShellTransport,
				RequireForwarding: p.Config.Global.Terminal.Scope != "remote", Timeouts: defaultDoctorTimeouts,
			})
			checks = append(checks, remoteChecks...)
			complete = complete && remoteComplete
			if remoteCause != nil {
				cause = remoteCause
			}
		}
		report := diagnostics.NewReport(checks, complete)
		if err := a.emitDoctor(report, asJSON); err != nil {
			return err
		}
		if cause != nil {
			return cause
		}
		if !report.OK {
			return errors.New("one or more doctor checks failed")
		}
		return nil
	}}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

func (a *App) stopCommand() *cobra.Command {
	return &cobra.Command{Use: "stop", Short: "Final-flush and pause this workspace", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		p, err := a.loadProject(cmd.Context(), true)
		if err != nil {
			return err
		}
		hostLifecycle, err := workspace.AcquireLock(a.hostLifecycleLockPath(p.HostID))
		if err != nil {
			return fmt.Errorf("acquire host lifecycle lease: %w", err)
		}
		defer hostLifecycle.Close()
		if err := a.stopActiveSessions(cmd.Context(), p.WS.LocalRoot, p.Config.Global.Sync.BarrierTimeout+30*time.Second); err != nil {
			return err
		}
		closeControl := func(operationErr error) error {
			return errors.Join(operationErr, a.stopSharedControlMaster(cmd.Context(), p))
		}
		if p.State.MutagenIdentifier == "" {
			return closeControl(errors.New("workspace has no synchronization session"))
		}
		if err := a.barrier(cmd.Context(), p); err != nil {
			return closeControl(err)
		}
		if err := p.Sync.Pause(cmd.Context(), p.State.MutagenIdentifier); err != nil {
			return closeControl(err)
		}
		return closeControl(nil)
	}}
}

func (a *App) cleanCommand() *cobra.Command {
	var remote, yes bool
	cmd := &cobra.Command{Use: "clean", Short: "Terminate workspace metadata; optionally delete the remote workspace", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		p, err := a.loadProject(cmd.Context(), true)
		if err != nil {
			return err
		}
		if remote && !yes {
			return errors.New("remote deletion requires --yes")
		}
		hostLifecycle, err := workspace.AcquireLock(a.hostLifecycleLockPath(p.HostID))
		if err != nil {
			return fmt.Errorf("acquire host lifecycle lease: %w", err)
		}
		defer hostLifecycle.Close()
		if err := a.stopActiveSessions(cmd.Context(), p.WS.LocalRoot, p.Config.Global.Sync.BarrierTimeout+30*time.Second); err != nil {
			return err
		}
		if p.State.MutagenIdentifier != "" {
			if err := p.Sync.Terminate(cmd.Context(), p.State.MutagenIdentifier); err != nil {
				return err
			}
		}
		if remote {
			remotePath := remoteShellPath(p.WS.RemotePath)
			_, err := transport.New(p.Host.Destination, "").Raw(cmd.Context(), "rm -rf -- "+remotePath)
			if err != nil {
				return fmt.Errorf("remove remote workspace: %w", err)
			}
		}
		if err := a.stopSharedControlMaster(cmd.Context(), p); err != nil {
			return err
		}
		if err := saveCleanedWorkspace(p, remote); err != nil {
			return fmt.Errorf("save cleaned workspace catalog: %w", err)
		}
		fmt.Fprintln(a.Out, "cleaned workspace metadata; local files were preserved")
		return nil
	}}
	cmd.Flags().BoolVar(&remote, "remote", false, "also delete the remote workspace")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm destructive remote deletion")
	return cmd
}

func saveCleanedWorkspace(p *projectContext, remoteRemoved bool) error {
	p.State.MutagenIdentifier, p.State.SyncFingerprint, p.State.RuntimeID = "", "", ""
	if remoteRemoved {
		p.State.RemoteRetained = false
	}
	err := p.Manager.SaveState(p.WS, p.State)
	if err == nil || !remoteRemoved {
		return err
	}
	// A durability error can occur after the atomic rename, making the visible
	// state uncertain. Restore the conservative retained marker before returning
	// so a later host removal cannot assume remote lifecycle is complete.
	p.State.RemoteRetained = true
	return errors.Join(err, p.Manager.SaveState(p.WS, p.State))
}

func (a *App) hostCommand() *cobra.Command {
	host := &cobra.Command{Use: "host", Short: "Manage remote hosts"}
	host.AddCommand(a.hostAdd(), a.hostList(), a.hostShow(), a.hostTransport(), a.hostDefault(), a.hostUse(), a.hostRemove(), a.hostDoctor(), a.hostBootstrap())
	return host
}

func (a *App) hostTransport() *cobra.Command {
	var moshPort string
	cmd := &cobra.Command{Use: "transport NAME auto|mosh|ssh", Short: "Set a host's interactive shell transport", Long: "Set a host's interactive shell transport. auto uses pwnbridge predictive echo over inline SSH, ssh disables prediction, and mosh explicitly selects a roaming full-screen Mosh session.", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		var host config.Host
		_, err := a.updateGlobal(cmd.Context(), func(effective *config.Effective) error {
			var ok bool
			host, ok = effective.Global.Hosts[args[0]]
			if !ok {
				return fmt.Errorf("unknown host %q", args[0])
			}
			host.ShellTransport = args[1]
			if cmd.Flags().Changed("mosh-port") {
				host.MoshPort = moshPort
			}
			effective.Global.Hosts[args[0]] = host
			return nil
		})
		if err != nil {
			return err
		}
		port := host.MoshPort
		if port == "" {
			port = "60000:61000"
		}
		switch host.ShellTransport {
		case "auto":
			fmt.Fprintf(a.Out, "host %s shell transport: auto (predictive inline SSH)\n", args[0])
		case "ssh":
			fmt.Fprintf(a.Out, "host %s shell transport: ssh (plain inline SSH)\n", args[0])
		default:
			fmt.Fprintf(a.Out, "host %s shell transport: mosh (roaming full-screen, UDP %s)\n", args[0], port)
		}
		return nil
	}}
	cmd.Flags().StringVar(&moshPort, "mosh-port", "", "remote UDP port or range for Mosh")
	return cmd
}

func (a *App) hostAdd() *cobra.Command {
	var options hostAddOptions
	cmd := &cobra.Command{Use: "add NAME DESTINATION", Short: "Register a remote host", Long: "Register a remote host. Use --check to verify read-only SSH and bootstrap readiness before saving, and --replace to explicitly replace an existing name.", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		return a.addHost(cmd.Context(), args[0], args[1], options)
	}}
	cmd.Flags().StringVar(&options.ShellTransport, "shell-transport", "auto", "interactive shell: auto (predictive SSH), ssh (plain), or mosh (roaming)")
	cmd.Flags().StringVar(&options.MoshPort, "mosh-port", "60000:61000", "remote UDP port or range for Mosh")
	cmd.Flags().BoolVar(&options.Check, "check", false, "verify read-only SSH and bootstrap readiness before saving")
	cmd.Flags().BoolVar(&options.Replace, "replace", false, "replace an existing host with the same name")
	cmd.Flags().BoolVar(&options.Default, "default", false, "make this the machine-wide default host")
	cmd.Flags().BoolVar(&options.JSON, "json", false, "emit JSON")
	return cmd
}

func (a *App) hostList() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List hosts (* machine default, > current project)",
		Long:  "List configured hosts. An asterisk (*) marks the machine-wide default; a greater-than sign (>) marks the current project's effective host.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := a.loadProject(cmd.Context(), false)
			if err != nil {
				return err
			}
			names := make([]string, 0, len(p.Config.Global.Hosts))
			for name := range p.Config.Global.Hosts {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				defaultMarker := " "
				if name == p.Config.Global.DefaultHost {
					defaultMarker = "*"
				}
				projectMarker := " "
				if name == p.Config.SelectedHost {
					projectMarker = ">"
				}
				fmt.Fprintf(a.Out, "%s%s %-16s %s\n", defaultMarker, projectMarker, name, p.Config.Global.Hosts[name].Destination)
			}
			return nil
		}}
}

func (a *App) hostShow() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{Use: "show NAME", Short: "Show a configured host", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		p, err := a.loadProject(cmd.Context(), false)
		if err != nil {
			return err
		}
		host, ok := p.Config.Global.Hosts[args[0]]
		if !ok {
			return fmt.Errorf("unknown host %q", args[0])
		}
		if asJSON {
			return writeJSON(a.Out, host)
		}
		transportName := host.ShellTransport
		if transportName == "" {
			transportName = "auto"
		}
		moshPort := host.MoshPort
		if moshPort == "" {
			moshPort = "60000:61000"
		}
		fmt.Fprintf(a.Out, "destination: %s\nplatform: %s\nworkspace root: %s\nshell transport: %s\nmosh UDP ports: %s\n", host.Destination, host.Platform, host.WorkspaceRoot, transportName, moshPort)
		return nil
	}}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

func (a *App) hostDefault() *cobra.Command {
	return &cobra.Command{Use: "default NAME", Short: "Set the machine-wide default host", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		_, err := a.updateGlobal(cmd.Context(), func(effective *config.Effective) error {
			if _, ok := effective.Global.Hosts[args[0]]; !ok {
				return fmt.Errorf("unknown host %q", args[0])
			}
			effective.Global.DefaultHost = args[0]
			return nil
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(a.Out, "default host is now %s\n", args[0])
		return nil
	}}
}

func (a *App) hostUse() *cobra.Command {
	var followDefault bool
	cmd := &cobra.Command{Use: "use NAME", Short: "Set the current project's host", Args: func(cmd *cobra.Command, args []string) error {
		if followDefault {
			if len(args) != 0 {
				return errors.New("use either a host name or --default, not both")
			}
			return nil
		}
		return cobra.ExactArgs(1)(cmd, args)
	}, RunE: func(cmd *cobra.Command, args []string) error {
		p, err := a.loadProject(cmd.Context(), false)
		if err != nil {
			return err
		}
		if err := guardImplicitWorkspace(p.Config.ProjectRoot, p.Config.ProjectPath); err != nil {
			return err
		}
		if followDefault {
			if err := p.Manager.SetBinding(p.Config.ProjectRoot, ""); err != nil {
				return err
			}
			fmt.Fprintf(a.Out, "project %s now follows default host %s\n", p.Config.ProjectRoot, empty(p.Config.Global.DefaultHost, "not selected"))
			return nil
		}
		if _, ok := p.Config.Global.Hosts[args[0]]; !ok {
			return fmt.Errorf("unknown host %q", args[0])
		}
		hostLock, err := workspace.AcquireLock(a.hostLifecycleLockPath(args[0]))
		if err != nil {
			return err
		}
		latest, loadErr := config.LoadGlobal(a.Paths)
		if loadErr != nil {
			return errors.Join(loadErr, hostLock.Close())
		}
		if _, ok := latest.Global.Hosts[args[0]]; !ok {
			return errors.Join(fmt.Errorf("host %q was removed; retry with current configuration", args[0]), hostLock.Close())
		}
		if err := p.Manager.SetBinding(p.Config.ProjectRoot, args[0]); err != nil {
			return errors.Join(err, hostLock.Close())
		}
		if err := hostLock.Close(); err != nil {
			return err
		}
		fmt.Fprintf(a.Out, "project %s now uses host %s\n", p.Config.ProjectRoot, args[0])
		return nil
	}}
	cmd.Flags().BoolVar(&followDefault, "default", false, "remove the project override and follow the machine default")
	return cmd
}

func (a *App) hostDoctor() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{Use: "doctor NAME", Short: "Check a remote host", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		effective, err := config.LoadGlobal(a.Paths)
		if err != nil {
			return err
		}
		host, ok := effective.Global.Hosts[args[0]]
		if !ok {
			return fmt.Errorf("unknown host %q", args[0])
		}
		client := transport.New(host.Destination, "")
		recipe, explanations, recipeErr := resolveDoctorRecipe(host.BootstrapProfile, effective.Global.BootstrapProfiles)
		checks, complete, cause := collectRemoteDoctor(cmd.Context(), client, remoteDoctorOptions{
			Recipe: recipe, RecipeExplanations: explanations, RecipeError: recipeErr,
			ContainerEngine: configuredContainerEngine(effective), ShellTransport: host.ShellTransport,
			RequireForwarding: effective.Global.Terminal.Scope != "remote", Timeouts: defaultDoctorTimeouts,
		})
		report := diagnostics.NewReport(checks, complete)
		if err := a.emitDoctor(report, asJSON); err != nil {
			return err
		}
		if cause != nil {
			return cause
		}
		if !report.OK {
			return errors.New("host doctor failed")
		}
		return nil
	}}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

func (a *App) hostBootstrap() *cobra.Command {
	var options bootstrap.Options
	var profile, recipeFile, saveProfile, interactive string
	var with, without, systemPackages, pipPackages []string
	var bindHostProfile bool
	cmd := &cobra.Command{Use: "bootstrap NAME", Short: "Prepare a remote host for pwn work", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if options.JSON {
			interactive = "never"
		}
		if interactive != "auto" && interactive != "always" && interactive != "never" {
			return errors.New("--interactive must be auto, always, or never")
		}
		if profile != "" && recipeFile != "" {
			return errors.New("--profile and --recipe-file are mutually exclusive")
		}
		effective, err := config.LoadGlobal(a.Paths)
		if err != nil {
			return err
		}
		host, ok := effective.Global.Hosts[args[0]]
		if !ok {
			return fmt.Errorf("unknown host %q", args[0])
		}
		client := transport.New(host.Destination, "")
		inventory, err := bootstrap.Inspect(cmd.Context(), client)
		if err != nil {
			return err
		}
		baseName := profile
		if baseName == "" {
			baseName = host.BootstrapProfile
		}
		if baseName == "" {
			baseName = "pwn"
		}
		var value bootstrap.Recipe
		if recipeFile != "" {
			value, err = bootstrap.LoadRecipe(recipeFile)
		} else {
			value, err = resolveBootstrapRecipe(baseName, effective.Global.BootstrapProfiles)
		}
		if err != nil {
			return err
		}
		withIDs, err := bootstrap.ParseComponentList(with)
		if err != nil {
			return err
		}
		withoutIDs, err := bootstrap.ParseComponentList(without)
		if err != nil {
			return err
		}
		if options.WithPwndbg {
			withIDs = append(withIDs, bootstrap.ComponentPwndbg)
		}
		value, explanations, err := bootstrap.ResolveRecipe(value, withIDs, withoutIDs, systemPackages, pipPackages)
		if err != nil {
			return err
		}
		useWizard := interactive == "always" || interactive == "auto" && usableWizardTTY(a)
		if interactive == "always" && !usableWizardTTY(a) {
			return errors.New("--interactive=always requires usable input and output TTYs and non-dumb TERM")
		}
		if useWizard {
			wizard, wizardErr := bootstrapui.Run(cmd.Context(), bootstrapui.Options{Input: a.In, Output: a.Out, Inventory: inventory, Profiles: effective.Global.BootstrapProfiles, InitialProfile: baseName, With: withIDs, Without: withoutIDs, SystemPackages: systemPackages, PipPackages: pipPackages, NoSudo: options.NoSudo, AcceptDockerRisk: options.AcceptDockerRootRisk, Accessible: options.Accessible})
			if wizardErr != nil {
				return wizardErr
			}
			value, explanations, options.Yes = wizard.Recipe, wizard.Plan.Explanations, true
			options.PlanPrinted = true
			options.AcceptDockerRootRisk = wizard.AcceptDockerRisk
			if wizard.SaveName != "" && saveProfile == "" {
				saveProfile = wizard.SaveName
			}
			if wizard.BindHost {
				bindHostProfile = true
			}
		} else if !options.Yes && !options.DryRun {
			preview, planErr := bootstrap.BuildPlan(inventory, value, explanations, bootstrap.PlanOptions{NoSudo: options.NoSudo, AcceptDockerRootRisk: options.AcceptDockerRootRisk})
			if planErr != nil {
				return planErr
			}
			confirmationErr := errors.New("non-interactive bootstrap requires --yes after reviewing the resolved plan")
			if options.JSON {
				if err := writeJSON(a.Out, bootstrap.Result{OK: false, Plan: preview, Error: confirmationErr.Error()}); err != nil {
					return err
				}
			} else {
				bootstrap.PrintPlan(a.Out, preview)
			}
			return confirmationErr
		}
		if saveProfile != "" {
			if options.DryRun {
				return errors.New("--dry-run cannot save bootstrap recipes")
			}
			if saveProfile == "pwn" || saveProfile == "minimal" {
				return errors.New("cannot replace a built-in bootstrap recipe")
			}
			value.Name = saveProfile
			if err := bootstrap.ValidateRecipe(value); err != nil {
				return err
			}
			_, err := a.updateGlobal(cmd.Context(), func(latest *config.Effective) error {
				if latest.Global.BootstrapProfiles == nil {
					latest.Global.BootstrapProfiles = map[string]bootstrap.Recipe{}
				}
				latest.Global.BootstrapProfiles[saveProfile] = value
				if bindHostProfile {
					latestHost, ok := latest.Global.Hosts[args[0]]
					if !ok {
						return fmt.Errorf("host %q was removed while bootstrap was running", args[0])
					}
					latestHost.BootstrapProfile = saveProfile
					latest.Global.Hosts[args[0]] = latestHost
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		if !options.DryRun {
			deployPlan, planErr := bootstrap.BuildPlan(inventory, value, explanations, bootstrap.PlanOptions{NoSudo: options.NoSudo, AcceptDockerRootRisk: options.AcceptDockerRootRisk})
			if planErr != nil {
				return planErr
			}
			if deployPlan.ValidateExecutable() == nil && len(deployPlan.Steps) > 0 {
				asset, assetErr := transport.FindAgentAsset(effective.AgentPath)
				if assetErr != nil {
					return assetErr
				}
				remoteAgent, deployErr := client.DeployAgent(cmd.Context(), asset)
				if deployErr != nil {
					return fmt.Errorf("deploy bootstrap agent: %w", deployErr)
				}
				client.AgentPath = remoteAgent
			}
		}
		options.Recipe, options.Explanations, options.Inventory = value, explanations, &inventory
		options.Input, options.Output, options.ErrorOutput = a.In, a.Out, a.Err
		options.LogPath = filepath.Join(a.Paths.State, "bootstrap", args[0]+"-"+time.Now().UTC().Format("20060102T150405Z")+".log")
		if options.JSON {
			options.Output = io.Discard
		}
		result, runErr := bootstrap.RunResult(cmd.Context(), client, options)
		for runErr != nil && useWizard {
			choice, choiceErr := bootstrapui.FailureChoice(cmd.Context(), a.In, a.Out, options.Accessible, result.LogPath)
			if choiceErr != nil {
				return errors.Join(runErr, choiceErr)
			}
			switch choice {
			case "log":
				if err := bootstrap.PrintSanitizedLog(a.Out, result.LogPath); err != nil {
					fmt.Fprintln(a.Err, "show bootstrap log:", err)
				}
				continue
			case "retry":
				options.Inventory = nil
				result, runErr = bootstrap.RunResult(cmd.Context(), client, options)
				continue
			default:
				return runErr
			}
		}
		if options.JSON {
			if jsonErr := writeJSON(a.Out, result); jsonErr != nil {
				return jsonErr
			}
		}
		if runErr != nil {
			return runErr
		}
		if !options.JSON && !options.DryRun {
			fmt.Fprintf(a.Out, "bootstrapped %s in %s; log: %s\n", args[0], result.Elapsed.Round(time.Second), result.LogPath)
		}
		return nil
	}}
	cmd.Flags().StringVar(&interactive, "interactive", "auto", "wizard mode: auto, always, or never")
	cmd.Flags().StringVar(&profile, "profile", "", "built-in or saved bootstrap profile")
	cmd.Flags().StringVar(&recipeFile, "recipe-file", "", "portable bootstrap recipe TOML")
	cmd.Flags().StringArrayVar(&with, "with", nil, "enable a component (repeatable)")
	cmd.Flags().StringArrayVar(&without, "without", nil, "disable an optional component (repeatable)")
	cmd.Flags().StringArrayVar(&systemPackages, "apt-package", nil, "extra validated system package (repeatable)")
	cmd.Flags().StringArrayVar(&pipPackages, "pip-package", nil, "extra validated pip requirement (repeatable)")
	cmd.Flags().StringVar(&saveProfile, "save-profile", "", "save the resolved portable recipe")
	cmd.Flags().BoolVar(&options.WithPwndbg, "with-pwndbg", false, "install pwndbg")
	cmd.Flags().BoolVar(&options.DryRun, "dry-run", false, "print commands without running them")
	cmd.Flags().BoolVar(&options.NoSudo, "no-sudo", false, "skip system packages")
	cmd.Flags().BoolVar(&options.Yes, "yes", false, "apply the resolved non-interactive plan")
	cmd.Flags().BoolVar(&options.AcceptDockerRootRisk, "accept-docker-root-risk", false, "accept that Docker group membership is root-equivalent")
	cmd.Flags().BoolVar(&options.Accessible, "accessible", false, "use accessible line-oriented form mode")
	cmd.Flags().BoolVar(&options.Verbose, "verbose", false, "stream sanitized command output")
	cmd.Flags().BoolVar(&options.JSON, "json", false, "emit one final JSON result")
	return cmd
}

func resolveBootstrapRecipe(name string, profiles map[string]bootstrap.Recipe) (bootstrap.Recipe, error) {
	if value, ok := bootstrap.BuiltinRecipe(name); ok {
		return value, nil
	}
	if value, ok := profiles[name]; ok {
		return value, nil
	}
	return bootstrap.Recipe{}, fmt.Errorf("unknown bootstrap profile %q", name)
}

func usableWizardTTY(a *App) bool {
	if strings.EqualFold(os.Getenv("TERM"), "dumb") || os.Getenv("TERM") == "" {
		return false
	}
	if a.In == nil || !term.IsTerminal(int(a.In.Fd())) {
		return false
	}
	out, ok := a.Out.(*os.File)
	return ok && term.IsTerminal(int(out.Fd()))
}

func configuredContainerEngine(e config.Effective) string {
	if e.Project.Runtime.Kind != "container" {
		return ""
	}
	return e.Project.Runtime.Container.Engine
}

func (a *App) syncCommand() *cobra.Command {
	syncCmd := &cobra.Command{Use: "sync", Short: "Inspect and control synchronization"}
	status := func(ctx context.Context) (*projectContext, syncer.HealthReport, error) {
		p, err := a.loadProject(ctx, true)
		if err != nil {
			return nil, syncer.HealthReport{}, err
		}
		if p.State.MutagenIdentifier == "" {
			return p, syncer.HealthReport{}, errors.New("workspace has no synchronization session")
		}
		report, err := p.Sync.Status(ctx, p.State.MutagenIdentifier)
		return p, report, err
	}
	var statusJSON bool
	statusCmd := &cobra.Command{Use: "status", Short: "Show synchronization status", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		_, report, err := status(cmd.Context())
		if err != nil {
			return err
		}
		if statusJSON {
			return writeJSON(a.Out, report)
		}
		fmt.Fprintf(a.Out, "healthy: %t\npaused: %t\nstatus: %s\n", report.Healthy, report.Paused, report.Status)
		for _, problem := range report.Problems {
			fmt.Fprintln(a.Out, "problem:", problem)
		}
		return nil
	}}
	statusCmd.Flags().BoolVar(&statusJSON, "json", false, "emit JSON")
	syncCmd.AddCommand(statusCmd,
		&cobra.Command{Use: "flush", Short: "Flush and validate synchronization", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := a.loadProject(cmd.Context(), true)
			if err != nil {
				return err
			}
			return a.barrier(cmd.Context(), p)
		}},
		&cobra.Command{Use: "pause", Short: "Pause synchronization", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			p, _, err := status(cmd.Context())
			if err != nil {
				return err
			}
			return p.Sync.Pause(cmd.Context(), p.State.MutagenIdentifier)
		}},
		&cobra.Command{Use: "resume", Short: "Resume synchronization", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			p, _, err := status(cmd.Context())
			if err != nil {
				return err
			}
			return p.Sync.Resume(cmd.Context(), p.State.MutagenIdentifier)
		}},
	)
	var conflictsJSON bool
	conflicts := &cobra.Command{Use: "conflicts", Short: "List synchronization conflicts", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		_, report, err := status(cmd.Context())
		if err != nil {
			return err
		}
		if conflictsJSON {
			return writeJSON(a.Out, map[string]any{"paths": syncer.ConflictPaths(report.Raw), "problems": report.Problems, "raw": report.Raw})
		}
		if len(report.Problems) == 0 {
			fmt.Fprintln(a.Out, "no conflicts or endpoint problems")
		} else {
			for _, problem := range report.Problems {
				fmt.Fprintln(a.Out, problem)
			}
		}
		return nil
	}}
	conflicts.Flags().BoolVar(&conflictsJSON, "json", false, "emit JSON")
	syncCmd.AddCommand(conflicts, a.conflictDiffCommand(), a.resolveCommand(), a.recoveryCommand())
	return syncCmd
}

func (a *App) resolveCommand() *cobra.Command {
	var prefer string
	cmd := &cobra.Command{Use: "resolve --prefer local|remote -- PATH...", Short: "Resolve synchronization conflicts", Args: cobra.MinimumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if prefer != "local" && prefer != "remote" {
			return errors.New("--prefer must be local or remote")
		}
		p, err := a.loadProject(cmd.Context(), true)
		if err != nil {
			return err
		}
		// Fail invalid or stale requests before paying the cost of establishing an
		// SSH control master. The status is read again under the mutation lock.
		preflight, err := p.Sync.Status(cmd.Context(), p.State.MutagenIdentifier)
		if err != nil {
			return err
		}
		if preflight.Healthy {
			return errors.New("sync session has no conflicts")
		}
		if _, err := validateConflictArguments(preflight.Raw, args); err != nil {
			return err
		}
		var remoteRecovery *transport.Master
		if prefer == "local" {
			var cleanup func()
			remoteRecovery, cleanup, err = a.startAgentControl(cmd.Context(), p, "recovery")
			if err != nil {
				return err
			}
			defer cleanup()
		}
		mutationErr := func() (result error) {
			lock, err := workspace.AcquireLock(p.WS.LockPath)
			if err != nil {
				return err
			}
			defer func() { result = errors.Join(result, lock.Close()) }()
			report, err := p.Sync.Status(cmd.Context(), p.State.MutagenIdentifier)
			if err != nil {
				return err
			}
			if report.Healthy {
				return errors.New("sync session has no conflicts")
			}
			paths, err := validateConflictArguments(report.Raw, args)
			if err != nil {
				return err
			}
			archive := recovery.ArchiveName(time.Now())
			for _, rel := range paths {
				if err := rejectSymlinkParents(p.WS.LocalRoot, rel); err != nil {
					return fmt.Errorf("unsafe local conflict path %q: %w", rel, err)
				}
				backupID, err := recovery.BackupID(archive, prefer, rel)
				if err != nil {
					return err
				}
				backup := filepath.Join(p.WS.RecoveryPath, backupID)
				if prefer == "remote" {
					if err := recovery.Copy(p.WS.LocalRoot, rel, p.WS.RecoveryPath, backupID); err != nil {
						return fmt.Errorf("back up local loser: %w", err)
					}
					if _, err := recovery.Record(p.WS.RecoveryPath, archive, prefer, rel); err != nil {
						return fmt.Errorf("record local recovery copy: %w", err)
					}
					if err := recovery.RemoveAll(p.WS.LocalRoot, rel); err != nil {
						return fmt.Errorf("remove local loser: %w", err)
					}
				} else {
					if _, err := backupRemoteLoser(cmd.Context(), remoteRecovery, p.WS.RemotePath, rel, p.WS.RecoveryPath, archive, backupID); err != nil {
						return fmt.Errorf("back up and remove remote loser: %w", err)
					}
				}
				fmt.Fprintf(a.Out, "backed up losing %s copy of %q to %q\n", opposite(prefer), rel, backup)
			}
			return nil
		}()
		if mutationErr != nil {
			return mutationErr
		}
		return a.barrier(cmd.Context(), p)
	}}
	cmd.Flags().StringVar(&prefer, "prefer", "", "winning endpoint: local or remote")
	_ = cmd.MarkFlagRequired("prefer")
	return cmd
}

func (a *App) terminalCommand() *cobra.Command {
	terminal := &cobra.Command{Use: "terminal", Short: "Inspect terminal providers"}
	var asJSON bool
	providers := &cobra.Command{Use: "providers", Short: "List terminal providers", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		registry := provider.NewRegistry(a.Paths.Cache)
		results := []provider.Capabilities{}
		for _, name := range registry.Names() {
			if strings.HasPrefix(name, "custom:") {
				continue
			}
			_, caps, err := registry.Select(cmd.Context(), name)
			if err != nil && caps.Name == "" {
				caps = provider.Capabilities{Name: name, Reason: err.Error()}
			}
			results = append(results, caps)
		}
		results = append(results,
			provider.Capabilities{Name: "remote-tmux", Available: true, Placements: []string{"right", "down"}, CanFocus: true, CanClose: true, Reason: "remote executable is checked when the managed shell starts"},
			provider.Capabilities{Name: "remote-zellij", Available: true, Placements: []string{"right", "down"}, CanFocus: true, CanClose: true, Reason: "remote executable is checked when the managed shell starts"},
		)
		if asJSON {
			return writeJSON(a.Out, results)
		}
		for _, caps := range results {
			fmt.Fprintf(a.Out, "%-14s available=%-5t placements=%s %s\n", caps.Name, caps.Available, strings.Join(caps.Placements, ","), caps.Reason)
		}
		return nil
	}}
	providers.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	var selected, placement, size string
	test := &cobra.Command{Use: "test", Short: "Test a terminal provider", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		registry := provider.NewRegistry(a.Paths.Cache)
		p, caps, err := registry.Select(cmd.Context(), selected)
		if err != nil {
			return err
		}
		if !containsString(caps.Placements, placement) {
			return fmt.Errorf("provider %s does not support placement %q", caps.Name, placement)
		}
		executable, _ := os.Executable()
		handle, err := p.Open(cmd.Context(), provider.Spec{Cwd: mustCwd(), Title: "pwnbridge terminal test", Placement: placement, Size: size, Focus: true, CloseOnSuccess: true, Command: []string{executable, "version"}})
		if err != nil {
			return err
		}
		fmt.Fprintf(a.Out, "opened %s pane %s\n", caps.Name, handle.ID)
		return nil
	}}
	test.Flags().StringVar(&selected, "provider", "auto", "provider name")
	test.Flags().StringVar(&placement, "placement", "right", "right, down, tab, floating, or window")
	test.Flags().StringVar(&size, "size", "50%", "pane size")
	terminal.AddCommand(providers, test)
	return terminal
}

func (a *App) runtimeCommand() *cobra.Command {
	runtimeCmd := &cobra.Command{Use: "runtime", Short: "Inspect or reset execution runtime"}
	var asJSON bool
	status := &cobra.Command{Use: "status", Short: "Show the execution runtime", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		p, err := a.loadProject(cmd.Context(), false)
		if err != nil {
			return err
		}
		value := p.Config.Project.Runtime
		if asJSON {
			return writeJSON(a.Out, value)
		}
		fmt.Fprintf(a.Out, "kind: %s\nengine: %s\nimage: %s\n", value.Kind, value.Container.Engine, value.Container.Image)
		return nil
	}}
	status.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	reset := &cobra.Command{Use: "reset", Short: "Reset the execution runtime", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		p, err := a.loadProject(cmd.Context(), true)
		if err != nil {
			return err
		}
		if p.Config.Project.Runtime.Kind != "container" {
			return errors.New("project uses the host runtime")
		}
		if err := a.stopActiveSessions(cmd.Context(), p.WS.LocalRoot, p.Config.Global.Sync.BarrierTimeout+30*time.Second); err != nil {
			return err
		}
		client := transport.New(p.Host.Destination, "")
		engine := p.Config.Project.Runtime.Container.Engine
		if engine == "" || engine == "auto" {
			probe := `if command -v podman >/dev/null 2>&1; then printf podman; elif command -v docker >/dev/null 2>&1; then printf docker; else exit 127; fi`
			out, probeErr := client.Raw(cmd.Context(), probe)
			if probeErr != nil {
				return fmt.Errorf("detect remote container engine: %w", probeErr)
			}
			engine = strings.TrimSpace(string(out))
		}
		if engine != "docker" && engine != "podman" {
			return fmt.Errorf("invalid remote container engine %q", engine)
		}
		label := "pwnbridge.workspace=" + p.WS.ID
		command := "ids=$(" + engine + " ps -aq --filter label=" + remoteShellPath(label) + "); " +
			"if [ -n \"$ids\" ]; then " + engine + " rm -f $ids; fi"
		_, runErr := client.Raw(cmd.Context(), command)
		if runErr != nil {
			return fmt.Errorf("reset runtime: %w", runErr)
		}
		fmt.Fprintln(a.Out, "removed pwnbridge containers; workspace preserved")
		return nil
	}}
	runtimeCmd.AddCommand(status, reset)
	return runtimeCmd
}

func (a *App) configCommand() *cobra.Command {
	configCmd := &cobra.Command{Use: "config", Short: "Inspect configuration"}
	configCmd.AddCommand(a.bootstrapConfigCommand())
	configCmd.AddCommand(&cobra.Command{Use: "path", Short: "Show configuration paths", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		p, err := a.loadProject(cmd.Context(), false)
		if err != nil {
			return err
		}
		fmt.Fprintln(a.Out, "global:", p.Config.GlobalPath)
		if p.Config.ProjectPath != "" {
			fmt.Fprintln(a.Out, "project:", p.Config.ProjectPath)
		} else {
			fmt.Fprintln(a.Out, "project: not present")
		}
		return nil
	}})
	configCmd.AddCommand(&cobra.Command{Use: "validate", Short: "Validate effective configuration", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if _, err := a.loadProject(cmd.Context(), false); err != nil {
			return err
		}
		fmt.Fprintln(a.Out, "configuration is valid")
		return nil
	}})
	var effective, asJSON bool
	show := &cobra.Command{Use: "show", Short: "Show configuration", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		p, err := a.loadProject(cmd.Context(), false)
		if err != nil {
			return err
		}
		var value any = p.Config.Global
		if effective {
			value = p.Config
		}
		if asJSON {
			return writeJSON(a.Out, value)
		}
		data, _ := json.MarshalIndent(value, "", "  ")
		fmt.Fprintln(a.Out, string(data))
		return nil
	}}
	show.Flags().BoolVar(&effective, "effective", false, "include merged project and environment settings")
	show.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	configCmd.AddCommand(show)
	return configCmd
}

func (a *App) bootstrapConfigCommand() *cobra.Command {
	root := &cobra.Command{Use: "bootstrap", Short: "Manage portable bootstrap recipes"}
	root.AddCommand(&cobra.Command{Use: "list", Short: "List bootstrap recipes", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		effective, err := config.LoadGlobal(a.Paths)
		if err != nil {
			return err
		}
		fmt.Fprintln(a.Out, "minimal\tbuilt-in")
		fmt.Fprintln(a.Out, "pwn\tbuilt-in")
		names := make([]string, 0, len(effective.Global.BootstrapProfiles))
		for name := range effective.Global.BootstrapProfiles {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintln(a.Out, name+"\tsaved")
		}
		return nil
	}})
	var showJSON bool
	show := &cobra.Command{Use: "show NAME", Short: "Show a bootstrap recipe", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		effective, err := config.LoadGlobal(a.Paths)
		if err != nil {
			return err
		}
		value, err := resolveBootstrapRecipe(args[0], effective.Global.BootstrapProfiles)
		if err != nil {
			return err
		}
		if showJSON {
			return writeJSON(a.Out, value)
		}
		data, err := bootstrap.MarshalRecipe(value)
		if err != nil {
			return err
		}
		_, err = a.Out.Write(data)
		return err
	}}
	show.Flags().BoolVar(&showJSON, "json", false, "emit JSON")
	root.AddCommand(show)
	var importName string
	var replace bool
	importCmd := &cobra.Command{Use: "import FILE", Short: "Import a portable recipe", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		value, err := bootstrap.LoadRecipe(args[0])
		if err != nil {
			return err
		}
		if importName != "" {
			value.Name = importName
		}
		if value.Name == "pwn" || value.Name == "minimal" {
			return errors.New("cannot replace a built-in bootstrap recipe")
		}
		if err := bootstrap.ValidateRecipe(value); err != nil {
			return err
		}
		_, err = a.updateGlobal(cmd.Context(), func(effective *config.Effective) error {
			if _, exists := effective.Global.BootstrapProfiles[value.Name]; exists && !replace {
				return fmt.Errorf("bootstrap recipe %q already exists; pass --replace", value.Name)
			}
			if effective.Global.BootstrapProfiles == nil {
				effective.Global.BootstrapProfiles = map[string]bootstrap.Recipe{}
			}
			effective.Global.BootstrapProfiles[value.Name] = value
			return nil
		})
		if err != nil {
			return err
		}
		fmt.Fprintln(a.Out, "imported bootstrap recipe "+value.Name)
		return nil
	}}
	importCmd.Flags().StringVar(&importName, "name", "", "override the imported recipe name")
	importCmd.Flags().BoolVar(&replace, "replace", false, "replace an existing saved recipe")
	root.AddCommand(importCmd)
	var exportOutput string
	exportCmd := &cobra.Command{Use: "export NAME", Short: "Export a portable recipe", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		effective, err := config.LoadGlobal(a.Paths)
		if err != nil {
			return err
		}
		value, err := resolveBootstrapRecipe(args[0], effective.Global.BootstrapProfiles)
		if err != nil {
			return err
		}
		data, err := bootstrap.MarshalRecipe(value)
		if err != nil {
			return err
		}
		if exportOutput == "" || exportOutput == "-" {
			_, err = a.Out.Write(data)
			return err
		}
		return fsutil.AtomicWrite(exportOutput, data, 0o600)
	}}
	exportCmd.Flags().StringVarP(&exportOutput, "output", "o", "-", "output file or - for stdout")
	root.AddCommand(exportCmd)
	root.AddCommand(&cobra.Command{Use: "remove NAME", Short: "Remove a saved bootstrap recipe", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if args[0] == "pwn" || args[0] == "minimal" {
			return errors.New("cannot remove a built-in bootstrap recipe")
		}
		_, err := a.updateGlobal(cmd.Context(), func(effective *config.Effective) error {
			if _, exists := effective.Global.BootstrapProfiles[args[0]]; !exists {
				return fmt.Errorf("unknown saved bootstrap recipe %q", args[0])
			}
			var bound []string
			for name, host := range effective.Global.Hosts {
				if host.BootstrapProfile == args[0] {
					bound = append(bound, name)
				}
			}
			sort.Strings(bound)
			if len(bound) > 0 {
				return fmt.Errorf("bootstrap recipe %q is bound to hosts %s; rebind them before removal", args[0], strings.Join(bound, ", "))
			}
			delete(effective.Global.BootstrapProfiles, args[0])
			return nil
		})
		if err != nil {
			return err
		}
		fmt.Fprintln(a.Out, "removed bootstrap recipe "+args[0])
		return nil
	}})
	return root
}

func (a *App) versionCommand() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{Use: "version", Short: "Show version information", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		value := map[string]any{"version": version.Version, "commit": version.Commit, "date": version.Date, "protocol": version.ProtocolVersion, "config_schema": version.ConfigSchema, "mutagen": version.MutagenVersion}
		if asJSON {
			return writeJSON(a.Out, value)
		}
		fmt.Fprintf(a.Out, "pwnbridge %s (%s, %s)\n", version.Version, version.Commit, version.Date)
		return nil
	}}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

func (a *App) paneCommand() *cobra.Command {
	var recordPath, sessionID, requestID string
	cmd := &cobra.Command{Use: "__pane", Hidden: true, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if recordPath == "" {
			recordPath = filepath.Join(a.Paths.State, "sessions", sessionID+".json")
		}
		record, err := broker.LoadSession(recordPath)
		if err != nil {
			return err
		}
		if record.ID != sessionID {
			return errors.New("pane session mismatch")
		}
		return broker.RunPane(cmd.Context(), record, requestID)
	}}
	cmd.Flags().StringVar(&sessionID, "session", "", "internal session id")
	cmd.Flags().StringVar(&recordPath, "record", "", "internal session record")
	cmd.Flags().StringVar(&requestID, "request", "", "internal request id")
	_ = cmd.MarkFlagRequired("session")
	_ = cmd.MarkFlagRequired("request")
	return cmd
}

func completionCommand(root *cobra.Command) *cobra.Command {
	return &cobra.Command{Use: "completion [bash|zsh|fish]", Short: "Generate a shell completion script", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return root.GenBashCompletion(cmd.OutOrStdout())
		case "zsh":
			return root.GenZshCompletion(cmd.OutOrStdout())
		case "fish":
			return root.GenFishCompletion(cmd.OutOrStdout(), true)
		default:
			return fmt.Errorf("unsupported shell %q", args[0])
		}
	}}
}

func (a *App) liveSessions(localWorkspace string) ([]broker.SessionRecord, error) {
	dir := filepath.Join(a.Paths.State, "sessions")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var sessions []broker.SessionRecord
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		record, loadErr := broker.LoadSession(path)
		if loadErr != nil {
			removed, cleanupErr := removeInvalidStaleSession(path)
			if cleanupErr != nil {
				return nil, cleanupErr
			}
			if removed {
				continue
			}
			return nil, fmt.Errorf("invalid session state %s: %w", path, loadErr)
		}
		if record.LocalWorkspace != localWorkspace {
			continue
		}
		leaseActive, leaseErr := sessionLeaseActive(record)
		if leaseErr != nil {
			return nil, leaseErr
		}
		if !leaseActive {
			removeStaleSession(record)
			continue
		}
		if !processAlive(record.OwnerPID) {
			return nil, fmt.Errorf("session %s lease is held but owner process %d is unavailable", record.ID, record.OwnerPID)
		}
		// Remote-multiplexer sessions, and sessions degraded to shell/run-only
		// because sshd forbids reverse forwarding, intentionally have no local
		// broker socket. Their owning process is the lease and stop target.
		if record.LocalSocket == "" {
			sessions = append(sessions, record)
			continue
		}
		if pingErr := broker.Ping(record); pingErr == nil {
			sessions = append(sessions, record)
			continue
		}
		return nil, fmt.Errorf("session %s owner process %d is alive but its broker is unreachable; wait or terminate that pwnbridge process", record.ID, record.OwnerPID)
	}
	return sessions, nil
}

func (a *App) hasOtherLease(localWorkspace, excludingID string) (bool, error) {
	dir := filepath.Join(a.Paths.State, "sessions")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		record, loadErr := broker.LoadSession(path)
		if loadErr != nil {
			// A recent unparseable record may be in the middle of an atomic
			// replacement on an unusual filesystem. Conservatively retain the
			// lease. Old owned records are eligible for cleanup only when their
			// kernel lease can also be acquired, which prevents PID reuse or a
			// damaged record from hiding a still-live session.
			removed, cleanupErr := removeInvalidStaleSession(path)
			if cleanupErr != nil {
				return false, cleanupErr
			}
			if removed {
				continue
			}
			return true, nil
		}
		if record.ID == excludingID || record.LocalWorkspace != localWorkspace {
			continue
		}
		leaseActive, leaseErr := sessionLeaseActive(record)
		if leaseErr != nil {
			return false, leaseErr
		}
		if leaseActive {
			return true, nil
		}
		removeStaleSession(record)
	}
	return false, nil
}

func (a *App) stopActiveSessions(ctx context.Context, localWorkspace string, timeout time.Duration) error {
	sessions, err := a.liveSessions(localWorkspace)
	if err != nil {
		return err
	}
	if len(sessions) == 0 {
		return nil
	}
	for _, session := range sessions {
		if session.OwnerPID == os.Getpid() {
			return errors.New("refuse to stop the current pwnbridge process from itself")
		}
		process, findErr := os.FindProcess(session.OwnerPID)
		if findErr != nil {
			return fmt.Errorf("find session %s owner: %w", session.ID, findErr)
		}
		if signalErr := process.Signal(syscall.SIGTERM); signalErr != nil && processAlive(session.OwnerPID) {
			return fmt.Errorf("stop session %s: %w", session.ID, signalErr)
		}
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		remaining := false
		for _, session := range sessions {
			if _, statErr := os.Stat(session.RecordPath); statErr == nil || !errors.Is(statErr, os.ErrNotExist) {
				remaining = true
				break
			}
		}
		if !remaining {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("timed out waiting for active pwnbridge sessions to stop safely")
		case <-ticker.C:
		}
	}
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func ownedRegularFile(info os.FileInfo) bool {
	if !info.Mode().IsRegular() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid()
}

func sessionLeaseActive(record broker.SessionRecord) (bool, error) {
	info, err := os.Lstat(record.LeasePath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !ownedRegularFile(info) || info.Mode().Perm()&0o077 != 0 {
		return false, fmt.Errorf("unsafe session lease %s", record.LeasePath)
	}
	lock, acquired, err := workspace.TryAcquireLock(record.LeasePath)
	if err != nil {
		return false, err
	}
	if !acquired {
		return true, nil
	}
	_ = lock.Close()
	return false, nil
}

func removeStaleSession(record broker.SessionRecord) {
	_ = os.Remove(record.RecordPath)
	_ = os.Remove(record.LeasePath)
}

func removeInvalidStaleSession(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return false, err
	}
	if time.Since(info.ModTime()) <= time.Hour || !ownedRegularFile(info) || info.Mode().Perm()&0o077 != 0 {
		return false, nil
	}
	leasePath := path + ".lease"
	leaseInfo, err := os.Lstat(leasePath)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if !ownedRegularFile(leaseInfo) || leaseInfo.Mode().Perm()&0o077 != 0 {
		return false, fmt.Errorf("unsafe session lease %s", leasePath)
	}
	lock, acquired, err := workspace.TryAcquireLock(leasePath)
	if err != nil {
		return false, err
	}
	if !acquired {
		return false, nil
	}
	defer lock.Close()
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := os.Remove(leasePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return true, nil
}

func projectIgnores(root string, configured []string) ([]string, error) {
	const maximumIgnoreBytes = 1 << 20
	data, err := fsutil.ReadFileLimit(filepath.Join(root, ".pwnbridgeignore"), maximumIgnoreBytes)
	if errors.Is(err, os.ErrNotExist) {
		return parseIgnores(nil, configured)
	}
	if err != nil {
		return nil, err
	}
	return parseIgnores(data, configured)
}

func parseIgnores(data []byte, configured []string) ([]string, error) {
	result := make([]string, 0, len(configured)+16)
	lines := append(append([]string(nil), configured...), strings.Split(string(data), "\n")...)
	if len(lines) > 4096 {
		return nil, errors.New("too many synchronization ignore patterns (maximum 4096)")
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > 4096 || strings.IndexByte(line, 0) >= 0 || strings.ContainsAny(line, "\r\n") {
			return nil, errors.New("invalid synchronization ignore pattern")
		}
		result = append(result, line)
	}
	return result, nil
}
func writeJSON(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{"schema": 1, "data": value})
}

// ExitCode preserves the exit status of a remote command, while reserving a
// distinct code for synchronization safety blocks.  Callers can therefore use
// pwnbridge in scripts without losing ordinary Unix command semantics.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	// Local cancellation owns the result even if teardown also reports an SSH
	// or remote-process error. This keeps Ctrl-C and `pwnbridge stop`
	// deterministic instead of leaking a timing-dependent cleanup exit code.
	if errors.Is(err, context.Canceled) {
		return 130
	}
	var remoteShell *shell.ExitError
	if errors.As(err, &remoteShell) && remoteShell.Code > 0 && remoteShell.Code <= 255 {
		return remoteShell.Code
	}
	var remoteProcess *exec.ExitError
	if errors.As(err, &remoteProcess) {
		if code := remoteProcess.ExitCode(); code > 0 && code <= 255 {
			return code
		}
	}
	var unhealthy *syncer.UnhealthyError
	if errors.As(err, &unhealthy) {
		return 4
	}
	return 1
}
func empty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
func opposite(value string) string {
	if value == "local" {
		return "remote"
	}
	return "local"
}
func mustCwd() string { cwd, _ := os.Getwd(); return cwd }
func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func remoteShellPath(value string) string {
	if strings.HasPrefix(value, "~/") {
		return `"$HOME"/` + shellQuote(value[2:])
	}
	return shellQuote(value)
}
func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

func rejectSymlinkParents(root, rel string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("workspace root is not a real directory")
	}
	parent := filepath.Dir(rel)
	if parent == "." {
		return nil
	}
	current := root
	for _, component := range strings.Split(parent, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err = os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("parent %s is a symbolic link", current)
		}
		if !info.IsDir() {
			return fmt.Errorf("parent %s is not a directory", current)
		}
	}
	return nil
}

func remoteSymlinkParentCheck(root, rel string) string {
	paths := []string{strings.TrimRight(root, "/")}
	parent := filepath.ToSlash(filepath.Dir(rel))
	if parent != "." {
		current := strings.TrimRight(root, "/")
		for _, component := range strings.Split(parent, "/") {
			current += "/" + component
			paths = append(paths, current)
		}
	}
	checks := make([]string, 0, len(paths))
	for _, path := range paths {
		quoted := remoteShellPath(path)
		checks = append(checks,
			"if test -L "+quoted+"; then printf 'symbolic-link parent\\n'; exit 40; fi; "+
				"if test -e "+quoted+" && test ! -d "+quoted+"; then printf 'non-directory parent\\n'; exit 41; fi")
	}
	return "set -eu; " + strings.Join(checks, "; ")
}

func EncodeRuntime(spec protocol.RuntimeSpec) string {
	data, _ := json.Marshal(spec)
	return base64.RawURLEncoding.EncodeToString(data)
}
