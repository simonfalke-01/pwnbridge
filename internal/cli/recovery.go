package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/simonfalke-01/pwnbridge/internal/recovery"
	"github.com/simonfalke-01/pwnbridge/internal/workspace"
)

func (a *App) recoveryCommand() *cobra.Command {
	command := &cobra.Command{Use: "recovery", Short: "List, verify, restore, and prune conflict recovery copies"}
	var asJSON bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List conflict recovery copies",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			project, err := a.loadProject(cmd.Context(), true)
			if err != nil {
				return err
			}
			entries, err := recovery.List(project.WS.RecoveryPath)
			if err != nil {
				return err
			}
			if asJSON {
				return writeJSON(a.Out, map[string]any{"entries": entries})
			}
			if len(entries) == 0 {
				fmt.Fprintln(a.Out, "no recovery copies")
				return nil
			}
			for _, entry := range entries {
				legacy := ""
				if entry.Legacy {
					legacy = " legacy=true"
				}
				digest := entry.SHA256
				if digest == "" {
					digest = "unverified"
				}
				fmt.Fprintf(a.Out, "%s id=%s loser=%s kind=%s bytes=%d items=%d mode=%#o sha256=%s path=%s%s\n",
					entry.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000000Z"),
					strconv.QuoteToASCII(entry.ID), entry.Loser, entry.Kind, entry.Size,
					entry.Items, entry.Mode, digest, strconv.QuoteToASCII(entry.OriginalPath), legacy)
			}
			return nil
		},
	}
	list.Flags().BoolVar(&asJSON, "json", false, "emit JSON")

	var verifyJSON bool
	verify := &cobra.Command{
		Use:   "verify [ID...]",
		Short: "Verify conflict recovery copy integrity",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, ids []string) error {
			project, err := a.loadProject(cmd.Context(), true)
			if err != nil {
				return err
			}
			lock, err := workspace.AcquireLock(project.WS.LockPath)
			if err != nil {
				return err
			}
			entries, err := recovery.ListForVerification(project.WS.RecoveryPath)
			if err == nil {
				entries, err = selectRecoveryEntries(entries, ids)
			}
			if err != nil {
				return errors.Join(err, lock.Close())
			}
			var transient *launchProgress
			var onProgress func(recoveryVerificationProgress)
			if !verifyJSON {
				transient = newLaunchProgress(a.Err)
				display := &recoveryProgressDisplay{progress: transient}
				onProgress = display.Update
			}
			report, verifyErr := verifyRecoveryEntriesProgress(cmd.Context(), project.WS.RecoveryPath, entries, onProgress)
			if verifyErr == nil {
				if contextErr := cmd.Context().Err(); contextErr != nil {
					report.Complete = false
					verifyErr = contextErr
				}
			}
			if transient != nil {
				transient.Stop()
			}
			closeErr := lock.Close()
			var outputErr error
			if verifyJSON {
				outputErr = writeJSON(a.Out, report)
			} else {
				outputErr = renderRecoveryVerification(a.Out, report)
			}
			if verifyErr != nil {
				return errors.Join(outputErr, verifyErr, closeErr)
			}
			return errors.Join(outputErr, closeErr, recoveryVerificationError(report))
		},
	}
	verify.Flags().BoolVar(&verifyJSON, "json", false, "emit JSON")

	var destination string
	restore := &cobra.Command{
		Use:   "restore ID --to PATH",
		Short: "Restore a recovery copy to a new local path",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (result error) {
			if destination == "" {
				return errors.New("--to is required")
			}
			project, err := a.loadProject(cmd.Context(), true)
			if err != nil {
				return err
			}
			lock, err := workspace.AcquireLock(project.WS.LockPath)
			if err != nil {
				return err
			}
			defer func() { result = errors.Join(result, lock.Close()) }()
			entry, err := recovery.Restore(project.WS.RecoveryPath, args[0], project.WS.LocalRoot, destination)
			if err != nil {
				return err
			}
			fmt.Fprintf(a.Out, "restored %s to local path %s; synchronization state was not changed\n",
				strconv.QuoteToASCII(entry.ID), strconv.QuoteToASCII(destination))
			return nil
		},
	}
	restore.Flags().StringVar(&destination, "to", "", "new project-relative destination (must not exist)")
	_ = restore.MarkFlagRequired("to")

	var keepLast int
	var pruneDryRun, pruneYes, pruneJSON bool
	prune := &cobra.Command{
		Use:   "prune --keep-last N (--dry-run|--yes)",
		Short: "Prune old complete recovery archives",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if keepLast < 1 {
				return errors.New("--keep-last must be at least 1")
			}
			if pruneDryRun == pruneYes {
				return errors.New("select exactly one of --dry-run to preview or --yes to prune")
			}
			project, err := a.loadProject(cmd.Context(), true)
			if err != nil {
				return err
			}
			lock, err := workspace.AcquireLock(project.WS.LockPath)
			if err != nil {
				return err
			}
			archives, err := recovery.ListArchives(project.WS.RecoveryPath)
			if err != nil {
				return errors.Join(err, lock.Close())
			}
			selected := selectRecoveryArchivesForPrune(archives, keepLast)
			report, err := newRecoveryPruneReport(archives, selected, keepLast, pruneDryRun)
			if err != nil {
				return errors.Join(err, lock.Close())
			}
			var pruneErr error
			if pruneDryRun {
				report.Complete = true
			} else {
				var transient *launchProgress
				if !pruneJSON && len(selected) > 0 {
					transient = newLaunchProgress(a.Err)
					transient.Stage(fmt.Sprintf("Pruning %d recovery archive(s)", len(selected)))
				}
				results, operationErr := recovery.PruneArchives(cmd.Context(), project.WS.RecoveryPath, selected)
				if transient != nil {
					transient.Stop()
				}
				report.apply(results)
				pruneErr = operationErr
				if pruneErr == nil {
					if contextErr := cmd.Context().Err(); contextErr != nil {
						pruneErr = contextErr
					}
				}
				report.Complete = pruneErr == nil && report.Pruned == report.Selected && report.PendingCleanup == 0
			}
			closeErr := lock.Close()
			var outputErr error
			if pruneJSON {
				outputErr = writeJSON(a.Out, report)
			} else {
				outputErr = renderRecoveryPrune(a.Out, report)
			}
			return errors.Join(outputErr, pruneErr, closeErr)
		},
	}
	prune.Flags().IntVar(&keepLast, "keep-last", 0, "retain at least this many newest recovery archives")
	prune.Flags().BoolVar(&pruneDryRun, "dry-run", false, "preview complete archives without deleting them")
	prune.Flags().BoolVar(&pruneYes, "yes", false, "confirm irreversible archive deletion")
	prune.Flags().BoolVar(&pruneJSON, "json", false, "emit JSON")
	command.AddCommand(list, verify, restore, prune)
	return command
}

type recoveryPruneArchiveResult struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Entries   int       `json:"entries"`
	Size      int64     `json:"size"`
	Items     int64     `json:"items"`
	Legacy    bool      `json:"legacy,omitempty"`
	Status    string    `json:"status"`
}

type recoveryPruneReport struct {
	Archives       []recoveryPruneArchiveResult `json:"archives"`
	KeepLast       int                          `json:"keep_last"`
	Kept           int                          `json:"kept"`
	Selected       int                          `json:"selected"`
	Pruned         int                          `json:"pruned"`
	PendingCleanup int                          `json:"pending_cleanup"`
	NotRun         int                          `json:"not_run"`
	LogicalBytes   int64                        `json:"logical_bytes"`
	DryRun         bool                         `json:"dry_run"`
	Complete       bool                         `json:"complete"`
}

func selectRecoveryArchivesForPrune(archives []recovery.Archive, keepLast int) []recovery.Archive {
	if keepLast >= len(archives) {
		return []recovery.Archive{}
	}
	return append([]recovery.Archive(nil), archives[keepLast:]...)
}

func newRecoveryPruneReport(all, selected []recovery.Archive, keepLast int, dryRun bool) (recoveryPruneReport, error) {
	report := recoveryPruneReport{
		Archives: make([]recoveryPruneArchiveResult, 0, len(selected)), KeepLast: keepLast,
		Kept: len(all) - len(selected), Selected: len(selected), DryRun: dryRun,
	}
	status := "not-run"
	if dryRun {
		status = "would-prune"
	} else {
		report.NotRun = len(selected)
	}
	for _, archive := range selected {
		if archive.Size > math.MaxInt64-report.LogicalBytes {
			return recoveryPruneReport{}, errors.New("selected recovery archive byte total overflows")
		}
		report.LogicalBytes += archive.Size
		report.Archives = append(report.Archives, recoveryPruneArchiveResult{
			ID: archive.ID, CreatedAt: archive.CreatedAt, Entries: archive.Entries,
			Size: archive.Size, Items: archive.Items, Legacy: archive.Legacy, Status: status,
		})
	}
	return report, nil
}

func (r *recoveryPruneReport) apply(results []recovery.PruneResult) {
	byID := make(map[string]recovery.PruneResult, len(results))
	for _, result := range results {
		byID[result.Archive.ID] = result
	}
	for index := range r.Archives {
		result, ok := byID[r.Archives[index].ID]
		if !ok {
			continue
		}
		r.NotRun--
		if result.CleanupPending {
			r.Archives[index].Status = "pending-cleanup"
			r.PendingCleanup++
			continue
		}
		r.Archives[index].Status = "pruned"
		r.Pruned++
	}
}

func renderRecoveryPrune(output io.Writer, report recoveryPruneReport) error {
	if len(report.Archives) == 0 {
		if _, err := fmt.Fprintln(output, "no recovery archives selected for pruning"); err != nil {
			return err
		}
	}
	for _, archive := range report.Archives {
		legacy := ""
		if archive.Legacy {
			legacy = " legacy=true"
		}
		if _, err := fmt.Fprintf(output, "%s archive=%s entries=%d logical_bytes=%d items=%d%s\n",
			archive.Status, strconv.QuoteToASCII(archive.ID), archive.Entries, archive.Size, archive.Items, legacy); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(output, "summary kept=%d selected=%d pruned=%d pending_cleanup=%d not_run=%d logical_bytes=%d dry_run=%t complete=%t\n",
		report.Kept, report.Selected, report.Pruned, report.PendingCleanup, report.NotRun, report.LogicalBytes, report.DryRun, report.Complete)
	return err
}

type recoveryVerificationResult struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	SHA256 string `json:"sha256,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type recoveryVerificationReport struct {
	Entries    []recoveryVerificationResult `json:"entries"`
	Verified   int                          `json:"verified"`
	Failed     int                          `json:"failed"`
	Unverified int                          `json:"unverified"`
	Complete   bool                         `json:"complete"`
	Checked    int                          `json:"checked"`
	Total      int                          `json:"total"`
}

type recoveryVerificationProgress struct {
	Index, Total      int
	Bytes, TotalBytes int64
	Items, TotalItems int64
	Done              bool
}

func selectRecoveryEntries(entries []recovery.Entry, ids []string) ([]recovery.Entry, error) {
	if len(ids) == 0 {
		return append([]recovery.Entry(nil), entries...), nil
	}
	available := make(map[string]recovery.Entry, len(entries))
	for _, entry := range entries {
		available[entry.ID] = entry
	}
	selected := make([]recovery.Entry, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if err := recovery.ValidateRelative(id); err != nil {
			return nil, fmt.Errorf("invalid recovery ID %q: %w", id, err)
		}
		if seen[id] {
			return nil, fmt.Errorf("duplicate recovery ID %q", id)
		}
		seen[id] = true
		entry, ok := available[id]
		if !ok {
			return nil, fmt.Errorf("recovery ID %q was not found; run `pwnbridge sync recovery list`", id)
		}
		selected = append(selected, entry)
	}
	return selected, nil
}

func verifyRecoveryEntries(ctx context.Context, recoveryRoot string, entries []recovery.Entry) (recoveryVerificationReport, error) {
	return verifyRecoveryEntriesProgress(ctx, recoveryRoot, entries, nil)
}

func verifyRecoveryEntriesProgress(ctx context.Context, recoveryRoot string, entries []recovery.Entry, onProgress func(recoveryVerificationProgress)) (recoveryVerificationReport, error) {
	report := recoveryVerificationReport{Entries: make([]recoveryVerificationResult, 0, len(entries)), Total: len(entries)}
	for index, entry := range entries {
		result := recoveryVerificationResult{ID: entry.ID, SHA256: entry.SHA256}
		update := func(progress recovery.ArchiveProgress, done bool) {
			if onProgress != nil {
				onProgress(recoveryVerificationProgress{
					Index: index + 1, Total: len(entries), Bytes: progress.Bytes, TotalBytes: entry.Size,
					Items: progress.Items, TotalItems: entry.Items, Done: done,
				})
			}
		}
		update(recovery.ArchiveProgress{}, false)
		var observed recovery.ArchiveProgress
		err := recovery.VerifyProgress(ctx, recoveryRoot, entry, func(progress recovery.ArchiveProgress) {
			observed = progress
			update(progress, false)
		})
		if ctxErr := ctx.Err(); ctxErr != nil {
			return report, ctxErr
		}
		switch {
		case err == nil:
			result.Status = "verified"
			report.Verified++
		case errors.Is(err, recovery.ErrUnverified):
			result.Status, result.Reason = "unverified", "no-recorded-digest"
			report.Unverified++
		case errors.Is(err, recovery.ErrIntegrityMismatch):
			result.Status, result.Reason = "failed", "integrity-mismatch"
			report.Failed++
		default:
			result.Status, result.Reason = "failed", "read-error"
			report.Failed++
		}
		report.Entries = append(report.Entries, result)
		report.Checked++
		update(observed, true)
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return report, contextErr
	}
	report.Complete = report.Checked == report.Total && report.Failed == 0 && report.Unverified == 0
	return report, nil
}

const recoveryProgressRefresh = 100 * time.Millisecond

type recoveryProgressDisplay struct {
	progress *launchProgress
	last     time.Time
}

func (d *recoveryProgressDisplay) Update(update recoveryVerificationProgress) {
	if d == nil || d.progress == nil {
		return
	}
	now := time.Now()
	if !update.Done && !d.last.IsZero() && now.Sub(d.last) < recoveryProgressRefresh {
		return
	}
	d.last = now
	d.progress.Stage(formatRecoveryProgress(update))
}

func formatRecoveryProgress(update recoveryVerificationProgress) string {
	percent := progressPercent(update.Bytes, update.TotalBytes)
	if update.TotalBytes <= 0 {
		percent = progressPercent(update.Items, update.TotalItems)
	}
	if update.Done {
		percent = 100
	} else if percent >= 100 {
		percent = 99
	}
	return fmt.Sprintf("Verifying recovery %d/%d (%d%%)", update.Index, update.Total, percent)
}

func progressPercent(value, total int64) int {
	if value <= 0 || total <= 0 {
		return 0
	}
	if value >= total {
		return 100
	}
	return int(float64(value) / float64(total) * 100)
}

func renderRecoveryVerification(output io.Writer, report recoveryVerificationReport) error {
	var buffer bytes.Buffer
	if len(report.Entries) == 0 {
		fmt.Fprintln(&buffer, "no recovery copies")
	}
	for _, entry := range report.Entries {
		fmt.Fprintf(&buffer, "%s id=%s", entry.Status, strconv.QuoteToASCII(entry.ID))
		if entry.SHA256 != "" {
			fmt.Fprintf(&buffer, " sha256=%s", entry.SHA256)
		}
		if entry.Reason != "" {
			fmt.Fprintf(&buffer, " reason=%s", entry.Reason)
		}
		fmt.Fprintln(&buffer)
	}
	fmt.Fprintf(&buffer, "summary verified=%d failed=%d unverified=%d complete=%t checked=%d total=%d\n",
		report.Verified, report.Failed, report.Unverified, report.Complete, report.Checked, report.Total)
	_, err := output.Write(buffer.Bytes())
	return err
}

func recoveryVerificationError(report recoveryVerificationReport) error {
	if report.Complete {
		return nil
	}
	return fmt.Errorf("recovery verification incomplete: %d failed, %d without recorded digests", report.Failed, report.Unverified)
}
