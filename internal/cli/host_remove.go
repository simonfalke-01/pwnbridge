package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/simonfalke-01/pwnbridge/internal/broker"
	"github.com/simonfalke-01/pwnbridge/internal/config"
	"github.com/simonfalke-01/pwnbridge/internal/fsutil"
	"github.com/simonfalke-01/pwnbridge/internal/workspace"
)

const maxHostRemovalSessionEntries = 8192

type hostRemovalOptions struct {
	DryRun bool
	Yes    bool
	Force  bool
	JSON   bool
}

type hostRemovalBinding struct {
	ProjectRoot string `json:"project_root,omitempty"`
	Legacy      bool   `json:"legacy,omitempty"`
}

type hostRemovalWorkspace struct {
	ID                     string    `json:"id"`
	ProjectRoot            string    `json:"project_root,omitempty"`
	RemotePath             string    `json:"remote_path,omitempty"`
	Legacy                 bool      `json:"legacy,omitempty"`
	RemoteRetained         bool      `json:"remote_retained"`
	SynchronizationPresent bool      `json:"synchronization_present"`
	RuntimePresent         bool      `json:"runtime_present"`
	RecoveryPresent        bool      `json:"recovery_present"`
	ActiveSessions         []string  `json:"active_sessions,omitempty"`
	UpdatedAt              time.Time `json:"updated_at,omitempty"`
}

type hostRemovalReport struct {
	Name                   string                 `json:"name"`
	DryRun                 bool                   `json:"dry_run"`
	Force                  bool                   `json:"force"`
	Default                bool                   `json:"default"`
	Safe                   bool                   `json:"safe"`
	Allowed                bool                   `json:"allowed"`
	Removed                bool                   `json:"removed"`
	Bindings               []hostRemovalBinding   `json:"bindings"`
	Workspaces             []hostRemovalWorkspace `json:"workspaces"`
	UnattributedRecovery   []string               `json:"unattributed_recovery"`
	UnattributedSessions   []string               `json:"unattributed_sessions"`
	NonOverridableBlockers []string               `json:"non_overridable_blockers"`
	Blockers               []string               `json:"blockers"`
}

func (a *App) hostRemove() *cobra.Command {
	var options hostRemovalOptions
	cmd := &cobra.Command{
		Use:   "remove NAME (--dry-run|--yes)",
		Short: "Safely remove a configured host",
		Long:  "Preview or confirm host removal after inspecting every local project binding, managed workspace, recovery root, and live session. --force preserves inactive dangling references but never overrides a live session.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.removeHost(cmd.Context(), args[0], options)
		},
	}
	cmd.Flags().BoolVar(&options.DryRun, "dry-run", false, "preview references without changing configuration")
	cmd.Flags().BoolVar(&options.Yes, "yes", false, "confirm removal after rechecking references")
	cmd.Flags().BoolVar(&options.Force, "force", false, "preserve and override inactive dangling references")
	cmd.Flags().BoolVar(&options.JSON, "json", false, "emit JSON")
	return cmd
}

func (a *App) removeHost(ctx context.Context, name string, options hostRemovalOptions) error {
	if options.DryRun == options.Yes {
		return errors.New("select exactly one of --dry-run to preview or --yes to remove")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := a.Paths.Ensure(); err != nil {
		return err
	}
	if options.DryRun {
		effective, err := config.LoadGlobal(a.Paths)
		if err != nil {
			return err
		}
		report, err := a.inspectHostRemoval(effective, name, options)
		if err != nil {
			return err
		}
		return renderHostRemoval(a.Out, report, options.JSON)
	}
	hostLock, err := workspace.AcquireLock(a.hostLifecycleLockPath(name))
	if err != nil {
		return fmt.Errorf("acquire host lifecycle lease: %w", err)
	}

	var report hostRemovalReport
	_, updateErr := a.updateGlobal(ctx, func(effective *config.Effective) error {
		var err error
		report, err = a.inspectHostRemoval(*effective, name, options)
		if err != nil {
			return err
		}
		if guardErr := hostRemovalGuard(report); guardErr != nil {
			return guardErr
		}
		delete(effective.Global.Hosts, name)
		if effective.Global.DefaultHost == name {
			effective.Global.DefaultHost = ""
		}
		return nil
	})
	if updateErr == nil {
		report.Removed = true
	}
	var outputErr error
	if report.Name != "" {
		outputErr = renderHostRemoval(a.Out, report, options.JSON)
	}
	return errors.Join(updateErr, outputErr, hostLock.Close())
}

func (a *App) hostLifecycleLockPath(name string) string {
	return filepath.Join(a.Paths.State, "host-lifecycle", workspace.Fingerprint(name)[:16]+".lock")
}

func (a *App) inspectHostRemoval(effective config.Effective, name string, options hostRemovalOptions) (hostRemovalReport, error) {
	if _, ok := effective.Global.Hosts[name]; !ok {
		return hostRemovalReport{}, fmt.Errorf("unknown host %q", name)
	}
	report := hostRemovalReport{
		Name: name, DryRun: options.DryRun, Force: options.Force,
		Default:  effective.Global.DefaultHost == name,
		Bindings: []hostRemovalBinding{}, Workspaces: []hostRemovalWorkspace{},
		UnattributedRecovery: []string{}, UnattributedSessions: []string{},
		NonOverridableBlockers: []string{}, Blockers: []string{},
	}
	manager := workspace.Manager{Paths: a.Paths}
	bindings, err := manager.ListBindings()
	if err != nil {
		return report, fmt.Errorf("inventory project bindings: %w", err)
	}
	for _, binding := range bindings {
		if binding.HostID == name {
			report.Bindings = append(report.Bindings, hostRemovalBinding{ProjectRoot: binding.LocalRoot, Legacy: binding.Legacy})
		}
	}

	states, err := manager.ListStates()
	if err != nil {
		return report, fmt.Errorf("inventory managed workspaces: %w", err)
	}
	recoveryRoots, err := manager.ListRecoveryRoots()
	if err != nil {
		return report, fmt.Errorf("inventory recovery roots: %w", err)
	}
	recoveryByWorkspace := make(map[string]bool, len(recoveryRoots))
	stateByWorkspace := make(map[string]workspace.StoredState, len(states))
	for _, state := range states {
		stateByWorkspace[state.WorkspaceID] = state
	}
	for _, recoveryRoot := range recoveryRoots {
		recoveryByWorkspace[recoveryRoot.WorkspaceID] = true
		if _, ok := stateByWorkspace[recoveryRoot.WorkspaceID]; !ok {
			report.UnattributedRecovery = append(report.UnattributedRecovery, recoveryRoot.WorkspaceID)
		}
	}

	activeSessions, err := a.readActiveSessionIDs()
	if err != nil {
		return report, fmt.Errorf("inventory active sessions: %w", err)
	}
	for workspaceID, sessionIDs := range activeSessions {
		if _, ok := stateByWorkspace[workspaceID]; !ok {
			report.UnattributedSessions = append(report.UnattributedSessions, sessionIDs...)
		}
	}
	sort.Strings(report.UnattributedSessions)
	for _, state := range states {
		if state.HostID != name {
			continue
		}
		workspaceReport := hostRemovalWorkspace{
			ID: state.WorkspaceID, ProjectRoot: state.LocalRoot, RemotePath: state.RemotePath,
			Legacy: state.Legacy, RemoteRetained: state.RemoteRetained,
			SynchronizationPresent: state.MutagenIdentifier != "", RuntimePresent: state.RuntimeID != "",
			RecoveryPresent: recoveryByWorkspace[state.WorkspaceID],
			ActiveSessions:  append([]string(nil), activeSessions[state.WorkspaceID]...), UpdatedAt: state.UpdatedAt,
		}
		if workspaceReport.RemoteRetained || workspaceReport.SynchronizationPresent || workspaceReport.RuntimePresent ||
			workspaceReport.RecoveryPresent || len(workspaceReport.ActiveSessions) > 0 {
			report.Workspaces = append(report.Workspaces, workspaceReport)
		}
	}

	if report.Default {
		report.Blockers = append(report.Blockers, "host is the machine-wide default")
	}
	if len(report.Bindings) > 0 {
		report.Blockers = append(report.Blockers, fmt.Sprintf("%d project binding(s) select this host", len(report.Bindings)))
	}
	if len(report.Workspaces) > 0 {
		report.Blockers = append(report.Blockers, fmt.Sprintf("%d managed workspace(s) retain resources", len(report.Workspaces)))
	}
	if len(report.UnattributedRecovery) > 0 {
		report.Blockers = append(report.Blockers, fmt.Sprintf("%d non-empty recovery root(s) cannot be attributed to a host", len(report.UnattributedRecovery)))
	}
	activeCount := len(report.UnattributedSessions)
	for _, candidate := range report.Workspaces {
		activeCount += len(candidate.ActiveSessions)
	}
	if activeCount > 0 {
		reason := fmt.Sprintf("%d active session(s) must stop before removal", activeCount)
		report.NonOverridableBlockers = append(report.NonOverridableBlockers, reason)
		report.Blockers = append(report.Blockers, reason)
	}
	report.Safe = len(report.Blockers) == 0
	report.Allowed = len(report.NonOverridableBlockers) == 0 && (report.Safe || options.Force)
	return report, nil
}

func (a *App) readActiveSessionIDs() (map[string][]string, error) {
	root := filepath.Join(a.Paths.State, "sessions")
	entries, err := fsutil.ReadPrivateDirectoryLimit(root, maxHostRemovalSessionEntries)
	if errors.Is(err, os.ErrNotExist) {
		return map[string][]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	result := make(map[string][]string)
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".pwnbridge-tmp-") || strings.HasSuffix(name, ".lease") {
			continue
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || filepath.Ext(name) != ".json" {
			return nil, fmt.Errorf("invalid session catalog entry %s", filepath.Join(root, name))
		}
		record, err := broker.LoadSession(filepath.Join(root, name))
		if err != nil {
			return nil, err
		}
		active, err := sessionLeaseActive(record)
		if err != nil {
			return nil, err
		}
		if !active {
			continue
		}
		if !processAlive(record.OwnerPID) {
			return nil, fmt.Errorf("session %s lease is held but owner process %d is unavailable", record.ID, record.OwnerPID)
		}
		if !isWorkspaceID(record.Runtime.WorkspaceID) {
			return nil, fmt.Errorf("session %s has an invalid workspace identity", record.ID)
		}
		result[record.Runtime.WorkspaceID] = append(result[record.Runtime.WorkspaceID], record.ID)
	}
	for workspaceID := range result {
		sort.Strings(result[workspaceID])
	}
	return result, nil
}

func isWorkspaceID(value string) bool {
	if len(value) != 16 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func hostRemovalGuard(report hostRemovalReport) error {
	if len(report.NonOverridableBlockers) > 0 {
		return fmt.Errorf("host %q has a live session; stop it before removal", report.Name)
	}
	if !report.Safe && !report.Force {
		return fmt.Errorf("host %q is still referenced; resolve the reported blockers or use --force --yes to preserve them as dangling state", report.Name)
	}
	if !report.Allowed {
		return fmt.Errorf("host %q cannot be removed safely", report.Name)
	}
	return nil
}

func renderHostRemoval(out io.Writer, report hostRemovalReport, asJSON bool) error {
	if asJSON {
		return writeJSON(out, report)
	}
	if _, err := fmt.Fprintf(out, "host: %s\nmode: %s\ndefault: %t\n", report.Name, map[bool]string{true: "preview", false: "confirmed"}[report.DryRun], report.Default); err != nil {
		return err
	}
	for _, binding := range report.Bindings {
		project := strconv.QuoteToASCII(binding.ProjectRoot)
		if binding.Legacy {
			project = "unknown (legacy binding)"
		}
		if _, err := fmt.Fprintf(out, "binding: project=%s\n", project); err != nil {
			return err
		}
	}
	for _, managed := range report.Workspaces {
		project := strconv.QuoteToASCII(managed.ProjectRoot)
		if managed.Legacy {
			project = "unknown (legacy state)"
		}
		if _, err := fmt.Fprintf(out, "workspace: id=%s project=%s remote_retained=%t sync=%t runtime=%t recovery=%t active_sessions=%d\n",
			managed.ID, project, managed.RemoteRetained, managed.SynchronizationPresent, managed.RuntimePresent,
			managed.RecoveryPresent, len(managed.ActiveSessions)); err != nil {
			return err
		}
	}
	for _, id := range report.UnattributedRecovery {
		if _, err := fmt.Fprintf(out, "recovery: workspace_id=%s host=unknown\n", id); err != nil {
			return err
		}
	}
	for _, reason := range report.Blockers {
		if _, err := fmt.Fprintf(out, "blocker: %s\n", reason); err != nil {
			return err
		}
	}
	switch {
	case report.Removed && !report.Safe:
		_, err := fmt.Fprintf(out, "result: removed host %s; referenced local state was preserved—re-add the same name to manage it again\n", report.Name)
		return err
	case report.Removed:
		_, err := fmt.Fprintf(out, "result: removed host %s\n", report.Name)
		return err
	case len(report.NonOverridableBlockers) > 0:
		_, err := fmt.Fprintln(out, "result: blocked; active sessions cannot be overridden")
		return err
	case report.DryRun && report.Safe:
		_, err := fmt.Fprintln(out, "result: ready; rerun with --yes to remove")
		return err
	case report.DryRun && report.Force:
		_, err := fmt.Fprintln(out, "result: force removal is allowed; referenced local state would be preserved")
		return err
	case !report.DryRun && report.Allowed:
		_, err := fmt.Fprintln(out, "result: not removed; the configuration update did not complete")
		return err
	default:
		_, err := fmt.Fprintln(out, "result: blocked; resolve references or use --force --yes to preserve dangling state")
		return err
	}
}
