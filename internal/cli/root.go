package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/pwnbridge/pwnbridge/internal/agent"
	"github.com/pwnbridge/pwnbridge/internal/bootstrap"
	"github.com/pwnbridge/pwnbridge/internal/broker"
	"github.com/pwnbridge/pwnbridge/internal/config"
	"github.com/pwnbridge/pwnbridge/internal/diagnostics"
	"github.com/pwnbridge/pwnbridge/internal/fsutil"
	"github.com/pwnbridge/pwnbridge/internal/identity"
	"github.com/pwnbridge/pwnbridge/internal/paths"
	"github.com/pwnbridge/pwnbridge/internal/protocol"
	"github.com/pwnbridge/pwnbridge/internal/shell"
	"github.com/pwnbridge/pwnbridge/internal/syncer"
	"github.com/pwnbridge/pwnbridge/internal/terminal/provider"
	"github.com/pwnbridge/pwnbridge/internal/transport"
	"github.com/pwnbridge/pwnbridge/internal/version"
	"github.com/pwnbridge/pwnbridge/internal/workspace"
)

type App struct {
	Paths    paths.Paths
	In       *os.File
	Out      io.Writer
	Err      io.Writer
	HostFlag string
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
	closed     bool
}

func New() (*App, error) {
	p, err := paths.Resolve()
	if err != nil {
		return nil, err
	}
	return &App{Paths: p, In: os.Stdin, Out: os.Stdout, Err: os.Stderr}, nil
}

func (a *App) Root() *cobra.Command {
	root := &cobra.Command{
		Use: "pwnbridge", Short: "Make a remote Linux x86-64 pwn environment feel local",
		SilenceUsage: true, SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error { return a.shell(cmd.Context()) },
	}
	root.PersistentFlags().StringVar(&a.HostFlag, "host", "", "override the configured remote host")
	root.AddCommand(
		&cobra.Command{Use: "shell", Short: "Open the managed remote shell", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return a.shell(cmd.Context()) }},
		a.runCommand(), a.initCommand(), a.statusCommand(), a.doctorCommand(), a.stopCommand(), a.cleanCommand(),
		a.hostCommand(), a.syncCommand(), a.terminalCommand(), a.runtimeCommand(), a.configCommand(), a.versionCommand(),
		a.paneCommand(),
	)
	root.AddCommand(completionCommand(root))
	return root
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
	if hostID == "" {
		if requireHost {
			return nil, errors.New("no host selected; run `pwnbridge host add NAME DESTINATION` and `pwnbridge host use NAME`")
		}
		mutagen := syncer.Mutagen{Runner: syncer.DefaultRunner(effective.MutagenPath, a.Paths.State)}
		return &projectContext{Config: effective, Manager: manager, Sync: mutagen}, nil
	}
	host, ok := effective.Global.Hosts[hostID]
	if !ok {
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

func (a *App) ensureSync(ctx context.Context, p *projectContext) error {
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
	if output, remoteErr := exec.CommandContext(ctx, "ssh", "-T", p.Host.Destination, remoteOperation).CombinedOutput(); remoteErr != nil {
		if operation == "validate" {
			return fmt.Errorf("remote workspace root is missing or was replaced; execution is blocked to protect the local copy. Verify local files, then run `pwnbridge clean` to explicitly create new synchronization history: %w: %s", remoteErr, strings.TrimSpace(string(output)))
		}
		return fmt.Errorf("create remote workspace: %w: %s", remoteErr, strings.TrimSpace(string(output)))
	}
	ignores, err := projectIgnores(p.Config.ProjectRoot, p.Config.Project.Workspace.Ignore)
	if err != nil {
		return err
	}
	spec := syncer.Spec{Workspace: p.WS, Destination: p.Host.Destination, Config: p.Config.Global.Sync, Ignores: ignores}
	timeout, cancel := context.WithTimeout(ctx, p.Config.Global.Sync.BarrierTimeout)
	defer cancel()
	if err := p.Sync.Ensure(timeout, spec, &p.State); err != nil {
		return err
	}
	if err := p.Manager.SaveState(p.WS, p.State); err != nil {
		return err
	}
	if err := p.Sync.Resume(timeout, p.State.MutagenIdentifier); err != nil {
		return err
	}
	return nil
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

func (a *App) startSession(ctx context.Context, p *projectContext) (*activeSession, error) {
	if _, err := a.liveSessions(p.WS.LocalRoot); err != nil {
		return nil, err
	}
	if err := a.ensureSync(ctx, p); err != nil {
		return nil, err
	}
	if err := a.barrier(ctx, p); err != nil {
		return nil, err
	}
	asset, err := transport.FindAgentAsset(p.Config.AgentPath)
	if err != nil {
		return nil, err
	}
	client := transport.New(p.Host.Destination, "")
	remoteAgent, err := client.DeployAgent(ctx, asset)
	if err != nil {
		return nil, err
	}
	client.AgentPath = remoteAgent
	probe, err := client.ProbeAgent(ctx)
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
	remoteDir := filepath.Join(probe.Home, ".cache", "pwnbridge", "sessions", id)
	localSocket := filepath.Join(runtimeDir, "b.sock")
	remoteSocket := filepath.Join(remoteDir, "broker.sock")
	prepare := "umask 077; mkdir -p -- " + remoteShellPath(filepath.Join(remoteDir, "requests"))
	if output, prepareErr := exec.CommandContext(ctx, "ssh", "-T", p.Host.Destination, prepare).CombinedOutput(); prepareErr != nil {
		os.RemoveAll(runtimeDir)
		return nil, fmt.Errorf("create remote session directory: %w: %s", prepareErr, strings.TrimSpace(string(output)))
	}
	recordPath := filepath.Join(a.Paths.State, "sessions", id+".json")
	executable, err := os.Executable()
	if err != nil {
		os.RemoveAll(runtimeDir)
		return nil, err
	}
	placement, paneSize := terminalLayout(p.Config.Global.Terminal)
	record := broker.SessionRecord{
		ID: id, OwnerPID: os.Getpid(), Token: token, LocalSocket: localSocket, RemoteSocket: remoteSocket,
		Destination: p.Host.Destination, AgentPath: remoteAgent, RemoteSessionDir: remoteDir,
		LocalWorkspace: p.WS.LocalRoot, Executable: executable, Provider: p.Config.Global.Terminal.Provider,
		RecordPath: recordPath,
		Placement:  placement, Size: paneSize,
		Focus: p.Config.Global.Terminal.Focus, CloseOnSuccess: p.Config.Global.Terminal.CloseOnSuccess,
		HoldOnFailure: p.Config.Global.Terminal.HoldOnFailure,
		Runtime: protocol.RuntimeSpec{
			Kind: p.Config.Project.Runtime.Kind, Engine: p.Config.Project.Runtime.Container.Engine,
			Image: p.Config.Project.Runtime.Container.Image, Workdir: p.Config.Project.Runtime.Container.Workdir,
			Network: p.Config.Project.Runtime.Container.Network, ID: "pwnbridge-" + id,
			Workspace: p.WS.RemotePath, WorkspaceID: p.WS.ID, SessionDir: remoteDir,
		},
	}
	registry := provider.NewRegistry(runtimeDir)
	b := broker.New(record, registry)
	b.BeforeOpen = func(barrierCtx context.Context) error { return a.barrier(barrierCtx, p) }
	if err := b.Start(); err != nil {
		os.RemoveAll(runtimeDir)
		return nil, err
	}
	record.LocalTCP = b.Record.LocalTCP
	master, err := client.StartMaster(ctx, runtimeDir, localSocket, remoteSocket, record.LocalTCP)
	if err != nil {
		b.Close()
		os.RemoveAll(runtimeDir)
		return nil, err
	}
	record.ControlPath = master.ControlPath
	record.RemoteSocket = master.BrokerAddress
	b.Record = record
	if err := broker.SaveSession(recordPath, record); err != nil {
		master.Close()
		b.Close()
		os.RemoveAll(runtimeDir)
		return nil, err
	}
	if _, err := master.Run(ctx, "broker-ping", protocol.BrokerPing{SessionID: id, Address: record.RemoteSocket, Token: token}); err != nil {
		master.Close()
		b.Close()
		os.Remove(recordPath)
		os.RemoveAll(runtimeDir)
		return nil, fmt.Errorf("reverse broker verification failed: %w", err)
	}
	return &activeSession{app: a, project: p, ID: id, Token: token, Nonce: nonce, RemoteDir: remoteDir, RuntimeDir: runtimeDir, RecordPath: recordPath, Record: record, Broker: b, Master: master}, nil
}

func (s *activeSession) runtimeSpec() protocol.RuntimeSpec {
	return s.Record.Runtime
}

func (s *activeSession) environment() map[string]string {
	env := map[string]string{}
	for key, value := range s.project.Config.Project.Environment.Set {
		env[key] = value
	}
	env["PWNBRIDGE_SESSION_ID"], env["PWNBRIDGE_SESSION_DIR"] = s.ID, s.RemoteDir
	env["PWNBRIDGE_BROKER"], env["PWNBRIDGE_BROKER_TOKEN"] = s.Record.RemoteSocket, s.Token
	env["PWNBRIDGE_TERMINAL_SCOPE"] = s.project.Config.Global.Terminal.Scope
	env["PWNBRIDGE_TERMINAL_PROVIDER"] = s.project.Config.Global.Terminal.Provider
	env["PWNBRIDGE_TERMINAL_PLACEMENT"] = s.project.Config.Global.Terminal.Placement
	termName := os.Getenv("TERM")
	if termName == "" || termName == "dumb" {
		termName = "xterm-256color"
	}
	env["TERM"] = termName
	for _, key := range []string{"COLORTERM", "LANG", "LC_ALL"} {
		if value := os.Getenv(key); value != "" {
			env[key] = value
		}
	}
	return env
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
	if err := s.app.barrier(ctx, s.project); err != nil {
		errs = append(errs, fmt.Errorf("final sync: %w", err))
	}
	_ = os.Remove(s.RecordPath)
	if s.project.Config.Global.Sync.PauseOnIdle && s.project.State.MutagenIdentifier != "" {
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
	_ = os.RemoveAll(s.RuntimeDir)
	return errors.Join(errs...)
}

func (a *App) shell(ctx context.Context) (result error) {
	p, err := a.loadProject(ctx, true)
	if err != nil {
		return err
	}
	session, err := a.startSession(ctx, p)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := session.Close(context.Background()); closeErr != nil {
			result = errors.Join(result, closeErr)
		}
	}()
	request := protocol.ShellRequest{Cwd: p.WS.RemotePath, Shell: p.Config.Project.Shell.Command, SourceUserRC: p.Config.Project.Shell.SourceUserRC, Nonce: session.Nonce, SessionID: session.ID, BrokerSocket: session.Record.RemoteSocket, BrokerToken: session.Token, Environment: session.environment(), Runtime: session.runtimeSpec()}
	encoded, err := agent.EncodeRequest(request)
	if err != nil {
		return err
	}
	cmd := session.Master.Command(ctx, true, "shell", encoded)
	proxy := shell.Proxy{In: a.In, Out: a.Out, Err: a.Err, Nonce: session.Nonce, Barrier: func(barrierCtx context.Context) error { return a.barrier(barrierCtx, p) }}
	if err := proxy.Run(ctx, cmd); ctx.Err() != nil {
		return ctx.Err()
	} else {
		return err
	}
}

func (a *App) runCommand() *cobra.Command {
	var ttyMode string
	cmd := &cobra.Command{Use: "run -- COMMAND [ARG...]", Short: "Run a command in the remote workspace", Args: cobra.MinimumNArgs(1), DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) (result error) {
			if ttyMode != "auto" && ttyMode != "always" && ttyMode != "never" {
				return fmt.Errorf("--tty must be auto, always, or never (got %q)", ttyMode)
			}
			p, err := a.loadProject(cmd.Context(), true)
			if err != nil {
				return err
			}
			session, err := a.startSession(cmd.Context(), p)
			if err != nil {
				return err
			}
			defer func() {
				if closeErr := session.Close(context.Background()); closeErr != nil {
					result = errors.Join(result, closeErr)
				}
			}()
			request := protocol.ExecRequest{Args: args, Cwd: p.WS.RemotePath, Environment: session.environment(), Runtime: session.runtimeSpec()}
			encoded, err := agent.EncodeRequest(request)
			if err != nil {
				return err
			}
			tty := ttyMode == "always" || ttyMode == "auto" && term.IsTerminal(int(a.In.Fd()))
			remote := session.Master.Command(cmd.Context(), tty, "exec", encoded)
			remote.Stdin, remote.Stdout, remote.Stderr = a.In, a.Out, a.Err
			if tty && term.IsTerminal(int(a.In.Fd())) {
				old, rawErr := term.MakeRaw(int(a.In.Fd()))
				if rawErr != nil {
					return rawErr
				}
				defer term.Restore(int(a.In.Fd()), old)
			}
			if err := remote.Run(); cmd.Context().Err() != nil {
				return cmd.Context().Err()
			} else {
				return err
			}
		},
	}
	cmd.Flags().StringVar(&ttyMode, "tty", "auto", "PTY mode: auto, always, or never")
	return cmd
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
		checks := diagnostics.Local(cmd.Context(), p.Sync)
		if p.HostID != "" {
			client := transport.New(p.Host.Destination, "")
			var agentErr error
			if asset, assetErr := transport.FindAgentAsset(p.Config.AgentPath); assetErr == nil {
				if remote, deployErr := client.DeployAgent(cmd.Context(), asset); deployErr == nil {
					client.AgentPath = remote
				} else {
					agentErr = deployErr
				}
			} else {
				agentErr = assetErr
			}
			checks = append(checks, diagnostics.Remote(cmd.Context(), client)...)
			if agentErr != nil {
				checks = append(checks, diagnostics.Check{Name: "diagnostic-agent", OK: false, Detail: agentErr.Error(), Remediation: "run make build or reinstall pwnbridge"})
			}
		}
		if asJSON {
			if err := writeJSON(a.Out, map[string]any{"ok": diagnostics.Healthy(checks), "checks": checks}); err != nil {
				return err
			}
			if !diagnostics.Healthy(checks) {
				return errors.New("one or more doctor checks failed")
			}
			return nil
		}
		for _, check := range checks {
			mark := "ok"
			if !check.OK {
				mark = "FAIL"
			}
			fmt.Fprintf(a.Out, "%-5s %-20s %s\n", mark, check.Name, check.Detail)
			if !check.OK && check.Remediation != "" {
				fmt.Fprintln(a.Out, "      fix:", check.Remediation)
			}
		}
		if !diagnostics.Healthy(checks) {
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
		if p.State.MutagenIdentifier == "" {
			return errors.New("workspace has no synchronization session")
		}
		if err := a.stopActiveSessions(cmd.Context(), p.WS.LocalRoot, p.Config.Global.Sync.BarrierTimeout+30*time.Second); err != nil {
			return err
		}
		if err := a.barrier(cmd.Context(), p); err != nil {
			return err
		}
		return p.Sync.Pause(cmd.Context(), p.State.MutagenIdentifier)
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
			out, err := exec.CommandContext(cmd.Context(), "ssh", "-T", p.Host.Destination, "rm -rf -- "+remotePath).CombinedOutput()
			if err != nil {
				return fmt.Errorf("remove remote workspace: %w: %s", err, strings.TrimSpace(string(out)))
			}
		}
		_ = os.Remove(p.WS.StatePath)
		fmt.Fprintln(a.Out, "cleaned workspace metadata; local files were preserved")
		return nil
	}}
	cmd.Flags().BoolVar(&remote, "remote", false, "also delete the remote workspace")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm destructive remote deletion")
	return cmd
}

func (a *App) hostCommand() *cobra.Command {
	host := &cobra.Command{Use: "host", Short: "Manage remote hosts"}
	host.AddCommand(a.hostAdd(), a.hostList(), a.hostShow(), a.hostUse(), a.hostRemove(), a.hostDoctor(), a.hostBootstrap())
	return host
}

func (a *App) hostAdd() *cobra.Command {
	return &cobra.Command{Use: "add NAME DESTINATION", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		e, err := a.loadProject(cmd.Context(), false)
		if err != nil {
			return err
		}
		name := args[0]
		if strings.ContainsAny(name, " /\\") {
			return errors.New("host name may contain no whitespace or slashes")
		}
		e.Config.Global.Hosts[name] = config.Host{Destination: args[1], Platform: "linux/amd64", WorkspaceRoot: "~/.local/share/pwnbridge/workspaces", BootstrapProfile: "pwn"}
		if e.Config.Global.DefaultHost == "" {
			e.Config.Global.DefaultHost = name
		}
		if err := config.SaveGlobal(e.Config.GlobalPath, e.Config.Global); err != nil {
			return err
		}
		fmt.Fprintf(a.Out, "added host %s (%s)\n", name, args[1])
		return nil
	}}
}

func (a *App) hostList() *cobra.Command {
	return &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
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
			marker := " "
			if name == p.Config.Global.DefaultHost {
				marker = "*"
			}
			fmt.Fprintf(a.Out, "%s %-16s %s\n", marker, name, p.Config.Global.Hosts[name].Destination)
		}
		return nil
	}}
}

func (a *App) hostShow() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{Use: "show NAME", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
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
		fmt.Fprintf(a.Out, "destination: %s\nplatform: %s\nworkspace root: %s\n", host.Destination, host.Platform, host.WorkspaceRoot)
		return nil
	}}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

func (a *App) hostUse() *cobra.Command {
	return &cobra.Command{Use: "use NAME", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		p, err := a.loadProject(cmd.Context(), false)
		if err != nil {
			return err
		}
		if _, ok := p.Config.Global.Hosts[args[0]]; !ok {
			return fmt.Errorf("unknown host %q", args[0])
		}
		if err := p.Manager.SetBinding(p.Config.ProjectRoot, args[0]); err != nil {
			return err
		}
		fmt.Fprintf(a.Out, "project now uses host %s\n", args[0])
		return nil
	}}
}

func (a *App) hostRemove() *cobra.Command {
	return &cobra.Command{Use: "remove NAME", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		p, err := a.loadProject(cmd.Context(), false)
		if err != nil {
			return err
		}
		if _, ok := p.Config.Global.Hosts[args[0]]; !ok {
			return fmt.Errorf("unknown host %q", args[0])
		}
		delete(p.Config.Global.Hosts, args[0])
		if p.Config.Global.DefaultHost == args[0] {
			p.Config.Global.DefaultHost = ""
		}
		return config.SaveGlobal(p.Config.GlobalPath, p.Config.Global)
	}}
}

func (a *App) hostDoctor() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{Use: "doctor NAME", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		p, err := a.loadProject(cmd.Context(), false)
		if err != nil {
			return err
		}
		host, ok := p.Config.Global.Hosts[args[0]]
		if !ok {
			return fmt.Errorf("unknown host %q", args[0])
		}
		client := transport.New(host.Destination, "")
		asset, assetErr := transport.FindAgentAsset(p.Config.AgentPath)
		if assetErr != nil {
			return assetErr
		}
		remoteAgent, deployErr := client.DeployAgent(cmd.Context(), asset)
		if deployErr != nil {
			return fmt.Errorf("deploy diagnostic agent: %w", deployErr)
		}
		client.AgentPath = remoteAgent
		checks := diagnostics.Remote(cmd.Context(), client)
		if asJSON {
			if err := writeJSON(a.Out, map[string]any{"ok": diagnostics.Healthy(checks), "checks": checks}); err != nil {
				return err
			}
			if !diagnostics.Healthy(checks) {
				return errors.New("host doctor failed")
			}
			return nil
		}
		for _, check := range checks {
			fmt.Fprintf(a.Out, "%t %-20s %s\n", check.OK, check.Name, check.Detail)
			if !check.OK && check.Remediation != "" {
				fmt.Fprintln(a.Out, "      fix:", check.Remediation)
			}
		}
		if !diagnostics.Healthy(checks) {
			return errors.New("host doctor failed")
		}
		return nil
	}}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

func (a *App) hostBootstrap() *cobra.Command {
	var options bootstrap.Options
	var profile string
	cmd := &cobra.Command{Use: "bootstrap NAME", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if profile != "pwn" {
			return errors.New("only the pwn bootstrap profile is supported")
		}
		p, err := a.loadProject(cmd.Context(), false)
		if err != nil {
			return err
		}
		host, ok := p.Config.Global.Hosts[args[0]]
		if !ok {
			return fmt.Errorf("unknown host %q", args[0])
		}
		client := transport.New(host.Destination, "")
		if !options.DryRun {
			asset, assetErr := transport.FindAgentAsset(p.Config.AgentPath)
			if assetErr != nil {
				return assetErr
			}
			remoteAgent, deployErr := client.DeployAgent(cmd.Context(), asset)
			if deployErr != nil {
				return deployErr
			}
			client.AgentPath = remoteAgent
		}
		if err := bootstrap.Run(cmd.Context(), client, options); err != nil {
			return err
		}
		if options.DryRun {
			return nil
		}
		probe, err := client.ProbeAgent(cmd.Context())
		if err != nil {
			return err
		}
		fmt.Fprintf(a.Out, "bootstrapped %s (%s/%s)\n", args[0], probe.OS, probe.Architecture)
		return nil
	}}
	cmd.Flags().StringVar(&profile, "profile", "pwn", "bootstrap profile")
	cmd.Flags().BoolVar(&options.WithPwndbg, "with-pwndbg", false, "install pwndbg")
	cmd.Flags().BoolVar(&options.DryRun, "dry-run", false, "print commands without running them")
	cmd.Flags().BoolVar(&options.NoSudo, "no-sudo", false, "skip system packages")
	return cmd
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
	statusCmd := &cobra.Command{Use: "status", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
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
		&cobra.Command{Use: "flush", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := a.loadProject(cmd.Context(), true)
			if err != nil {
				return err
			}
			return a.barrier(cmd.Context(), p)
		}},
		&cobra.Command{Use: "pause", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			p, _, err := status(cmd.Context())
			if err != nil {
				return err
			}
			return p.Sync.Pause(cmd.Context(), p.State.MutagenIdentifier)
		}},
		&cobra.Command{Use: "resume", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			p, _, err := status(cmd.Context())
			if err != nil {
				return err
			}
			return p.Sync.Resume(cmd.Context(), p.State.MutagenIdentifier)
		}},
	)
	var conflictsJSON bool
	conflicts := &cobra.Command{Use: "conflicts", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
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
	syncCmd.AddCommand(conflicts, a.resolveCommand())
	return syncCmd
}

func (a *App) resolveCommand() *cobra.Command {
	var prefer string
	cmd := &cobra.Command{Use: "resolve --prefer local|remote -- PATH...", Args: cobra.MinimumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if prefer != "local" && prefer != "remote" {
			return errors.New("--prefer must be local or remote")
		}
		p, err := a.loadProject(cmd.Context(), true)
		if err != nil {
			return err
		}
		report, err := p.Sync.Status(cmd.Context(), p.State.MutagenIdentifier)
		if err != nil {
			return err
		}
		if report.Healthy {
			return errors.New("sync session has no conflicts")
		}
		conflicts := map[string]bool{}
		for _, path := range syncer.ConflictPaths(report.Raw) {
			conflicts[filepath.Clean(path)] = true
		}
		if len(conflicts) == 0 {
			return errors.New("session is unhealthy but contains no resolvable file conflict")
		}
		timestamp := time.Now().UTC().Format("20060102T150405Z")
		resolved := map[string]bool{}
		for _, value := range args {
			rel := filepath.Clean(value)
			if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return fmt.Errorf("path %q escapes workspace", value)
			}
			if !conflicts[rel] {
				return fmt.Errorf("path %q is not a current synchronization conflict", value)
			}
			if resolved[rel] {
				return fmt.Errorf("path %q was specified more than once", value)
			}
			resolved[rel] = true
			backup := filepath.Join(p.WS.RecoveryPath, timestamp, prefer+"-winner", rel)
			if err := os.MkdirAll(filepath.Dir(backup), 0o700); err != nil {
				return err
			}
			local := filepath.Join(p.WS.LocalRoot, rel)
			remote := strings.TrimRight(p.WS.RemotePath, "/") + "/" + filepath.ToSlash(rel)
			if prefer == "remote" {
				if err := copyPath(local, backup); err != nil {
					return fmt.Errorf("back up local loser: %w", err)
				}
				if err := os.RemoveAll(local); err != nil {
					return err
				}
			} else {
				out, copyErr := exec.CommandContext(cmd.Context(), "scp", "-q", "-r", "-p", "--", p.Host.Destination+":"+remote, backup).CombinedOutput()
				if copyErr != nil {
					return fmt.Errorf("back up remote loser: %w: %s", copyErr, strings.TrimSpace(string(out)))
				}
				out, removeErr := exec.CommandContext(cmd.Context(), "ssh", "-T", p.Host.Destination, "rm -rf -- "+remoteShellPath(remote)).CombinedOutput()
				if removeErr != nil {
					return fmt.Errorf("remove remote loser: %w: %s", removeErr, strings.TrimSpace(string(out)))
				}
			}
			fmt.Fprintf(a.Out, "backed up losing %s copy of %s to %s\n", opposite(prefer), rel, backup)
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
	providers := &cobra.Command{Use: "providers", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
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
	test := &cobra.Command{Use: "test", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
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
	status := &cobra.Command{Use: "status", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
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
	reset := &cobra.Command{Use: "reset", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
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
		engine := p.Config.Project.Runtime.Container.Engine
		if engine == "" || engine == "auto" {
			probe := `if command -v podman >/dev/null 2>&1; then printf podman; elif command -v docker >/dev/null 2>&1; then printf docker; else exit 127; fi`
			out, probeErr := exec.CommandContext(cmd.Context(), "ssh", "-T", p.Host.Destination, probe).CombinedOutput()
			if probeErr != nil {
				return fmt.Errorf("detect remote container engine: %w: %s", probeErr, strings.TrimSpace(string(out)))
			}
			engine = strings.TrimSpace(string(out))
		}
		if engine != "docker" && engine != "podman" {
			return fmt.Errorf("invalid remote container engine %q", engine)
		}
		label := "pwnbridge.workspace=" + p.WS.ID
		command := "ids=$(" + engine + " ps -aq --filter label=" + remoteShellPath(label) + "); " +
			"if [ -n \"$ids\" ]; then " + engine + " rm -f $ids; fi"
		out, runErr := exec.CommandContext(cmd.Context(), "ssh", "-T", p.Host.Destination, command).CombinedOutput()
		if runErr != nil {
			return fmt.Errorf("reset runtime: %w: %s", runErr, strings.TrimSpace(string(out)))
		}
		fmt.Fprintln(a.Out, "removed pwnbridge containers; workspace preserved")
		return nil
	}}
	runtimeCmd.AddCommand(status, reset)
	return runtimeCmd
}

func (a *App) configCommand() *cobra.Command {
	configCmd := &cobra.Command{Use: "config", Short: "Inspect configuration"}
	configCmd.AddCommand(&cobra.Command{Use: "path", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
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
	configCmd.AddCommand(&cobra.Command{Use: "validate", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if _, err := a.loadProject(cmd.Context(), false); err != nil {
			return err
		}
		fmt.Fprintln(a.Out, "configuration is valid")
		return nil
	}})
	var effective, asJSON bool
	show := &cobra.Command{Use: "show", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
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

func (a *App) versionCommand() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{Use: "version", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
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
	return &cobra.Command{Use: "completion [bash|zsh|fish]", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
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
			info, statErr := entry.Info()
			if statErr == nil && time.Since(info.ModTime()) > time.Hour && ownedRegularFile(info) {
				_ = os.Remove(path)
				continue
			}
			return nil, fmt.Errorf("invalid session state %s: %w", path, loadErr)
		}
		if record.LocalWorkspace != localWorkspace {
			continue
		}
		if pingErr := broker.Ping(record); pingErr == nil {
			sessions = append(sessions, record)
			continue
		}
		if processAlive(record.OwnerPID) {
			return nil, fmt.Errorf("session %s owner process %d is alive but its broker is unreachable; wait or terminate that pwnbridge process", record.ID, record.OwnerPID)
		}
		_ = os.Remove(path)
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
			// lease; old owned records are eligible for stale cleanup.
			info, statErr := entry.Info()
			if statErr == nil && time.Since(info.ModTime()) > time.Hour && ownedRegularFile(info) {
				_ = os.Remove(path)
				continue
			}
			return true, nil
		}
		if record.ID == excludingID || record.LocalWorkspace != localWorkspace {
			continue
		}
		if processAlive(record.OwnerPID) || broker.Ping(record) == nil {
			return true, nil
		}
		_ = os.Remove(path)
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

func projectIgnores(root string, configured []string) ([]string, error) {
	result := append([]string(nil), configured...)
	data, err := os.ReadFile(filepath.Join(root, ".pwnbridgeignore"))
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			result = append(result, line)
		}
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
	if errors.Is(err, context.Canceled) {
		return 130
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
func terminalLayout(terminal config.Terminal) (string, string) {
	placement, size := terminal.Placement, terminal.Size
	if terminal.Provider == "zellij" {
		if terminal.Zellij.Floating {
			placement = "floating"
		} else if placement == "right" || placement == "down" {
			placement = terminal.Zellij.Direction
		}
	}
	if terminal.Provider == "tmux" {
		if placement == "right" || placement == "down" {
			switch terminal.Tmux.Direction {
			case "vertical", "down":
				placement = "down"
			default:
				placement = "right"
			}
		}
		size = terminal.Tmux.Size
	}
	return placement, size
}
func remoteShellPath(value string) string {
	if strings.HasPrefix(value, "~/") {
		return `"$HOME"/` + shellQuote(value[2:])
	}
	return shellQuote(value)
}
func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

func copyPath(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return copySymlink(source, destination)
	}
	if info.IsDir() {
		return filepath.Walk(source, func(path string, entry os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			rel, _ := filepath.Rel(source, path)
			target := filepath.Join(destination, rel)
			if entry.IsDir() {
				return os.MkdirAll(target, entry.Mode().Perm())
			}
			if entry.Mode()&os.ModeSymlink != 0 {
				return copySymlink(path, target)
			}
			if !entry.Mode().IsRegular() {
				return fmt.Errorf("refuse to back up non-regular file %s", path)
			}
			return copyFile(path, target, entry.Mode().Perm())
		})
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refuse to back up non-regular file %s", source)
	}
	return copyFile(source, destination, info.Mode().Perm())
}

func copySymlink(source, destination string) error {
	target, err := os.Readlink(source)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	return os.Symlink(target, destination)
}
func copyFile(source, destination string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func EncodeRuntime(spec protocol.RuntimeSpec) string {
	data, _ := json.Marshal(spec)
	return base64.RawURLEncoding.EncodeToString(data)
}
