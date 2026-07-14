package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/simonfalke-01/pwnbridge/internal/filesnapshot"
	"github.com/simonfalke-01/pwnbridge/internal/protocol"
	"github.com/simonfalke-01/pwnbridge/internal/subprocess"
	"github.com/simonfalke-01/pwnbridge/internal/syncer"
	"github.com/simonfalke-01/pwnbridge/internal/transport"
)

type conflictPreview struct {
	path   string
	local  protocol.FileSnapshot
	remote protocol.FileSnapshot
}

func (a *App) conflictDiffCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "diff -- PATH...",
		Short: "Preview local-to-remote conflict differences",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			progress := newLaunchProgress(a.Err)
			defer progress.Stop()
			progress.Stage("Checking current conflicts")
			p, err := a.loadProject(cmd.Context(), true)
			if err != nil {
				return err
			}
			if p.State.MutagenIdentifier == "" {
				return errors.New("workspace has no synchronization session")
			}
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

			previews := make([]conflictPreview, len(paths))
			for i, path := range paths {
				local, captureErr := filesnapshot.Capture(p.WS.LocalRoot, path, protocol.MaxConflictPreviewBytes)
				if captureErr != nil {
					return fmt.Errorf("inspect local conflict %q: %w", path, captureErr)
				}
				previews[i] = conflictPreview{path: path, local: local}
			}

			progress.Stage("Inspecting conflict endpoints")
			master, cleanup, err := a.startAgentControl(cmd.Context(), p, "diff")
			if err != nil {
				return err
			}
			defer cleanup()
			for i := range previews {
				output, snapshotErr := master.Run(cmd.Context(), "snapshot", protocol.SnapshotRequest{Root: p.WS.RemotePath, Path: previews[i].path})
				if snapshotErr != nil {
					return fmt.Errorf("inspect remote conflict %q: %w", previews[i].path, snapshotErr)
				}
				if err := decodeSnapshot(output, &previews[i].remote); err != nil {
					return fmt.Errorf("decode remote conflict %q: %w", previews[i].path, err)
				}
			}
			progress.Stop()
			for i, preview := range previews {
				if i > 0 {
					fmt.Fprintln(a.Out)
				}
				if err := writeConflictDiff(cmd.Context(), a.Out, preview.path, preview.local, preview.remote); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func validateConflictArguments(raw any, arguments []string) ([]string, error) {
	conflicts := make(map[string]bool)
	for _, path := range syncer.ConflictPaths(raw) {
		conflicts[filepath.Clean(path)] = true
	}
	if len(conflicts) == 0 {
		return nil, errors.New("session is unhealthy but contains no resolvable file conflict")
	}
	result := make([]string, 0, len(arguments))
	seen := make(map[string]bool, len(arguments))
	for _, value := range arguments {
		rel := filepath.Clean(value)
		if filepath.IsAbs(rel) || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("path %q escapes workspace", value)
		}
		if !conflicts[rel] {
			return nil, fmt.Errorf("path %q is not a current synchronization conflict", value)
		}
		if seen[rel] {
			return nil, fmt.Errorf("path %q was specified more than once", value)
		}
		seen[rel] = true
		result = append(result, rel)
	}
	return result, nil
}

func (a *App) startAgentControl(ctx context.Context, p *projectContext, purpose string) (*transport.Master, func(), error) {
	asset, err := transport.FindAgentAsset(p.Config.AgentPath)
	if err != nil {
		return nil, nil, err
	}
	runtimeDir, err := os.MkdirTemp("", "pwnbridge-"+purpose+"-")
	if err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(runtimeDir, 0o700); err != nil {
		_ = os.RemoveAll(runtimeDir)
		return nil, nil, err
	}
	client := transport.New(p.Host.Destination, "")
	master, err := client.StartControlMaster(ctx, runtimeDir)
	if err != nil {
		_ = os.RemoveAll(runtimeDir)
		return nil, nil, err
	}
	remoteAgent, err := master.Client.DeployAgent(ctx, asset)
	if err != nil {
		_ = master.Close()
		_ = os.RemoveAll(runtimeDir)
		return nil, nil, fmt.Errorf("deploy %s agent: %w", purpose, err)
	}
	master.Client.AgentPath = remoteAgent
	cleanup := func() {
		_ = master.Close()
		_ = os.RemoveAll(runtimeDir)
	}
	return master, cleanup, nil
}

func decodeSnapshot(data []byte, snapshot *protocol.FileSnapshot) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(snapshot); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("trailing snapshot data: %w", err)
		}
		return errors.New("trailing snapshot value")
	}
	switch snapshot.Kind {
	case "missing", "regular", "directory", "symlink", "special":
		return validateSnapshot(*snapshot)
	default:
		return fmt.Errorf("unknown snapshot kind %q", snapshot.Kind)
	}
}

func validateSnapshot(snapshot protocol.FileSnapshot) error {
	if snapshot.Size < 0 || snapshot.Mode&^0o777 != 0 || len(snapshot.Content) > protocol.MaxConflictPreviewBytes || len(snapshot.LinkTarget) > protocol.MaxConflictPreviewBytes {
		return errors.New("snapshot exceeds its structural limits")
	}
	switch snapshot.Kind {
	case "missing":
		if snapshot.Size != 0 || snapshot.Mode != 0 || snapshot.SHA256 != "" || len(snapshot.Content) != 0 || snapshot.Omitted || snapshot.LinkTarget != "" {
			return errors.New("missing snapshot contains file data")
		}
	case "regular":
		if snapshot.LinkTarget != "" {
			return errors.New("regular snapshot contains a link target")
		}
		if snapshot.Omitted {
			if snapshot.Size <= protocol.MaxConflictPreviewBytes || len(snapshot.Content) != 0 || snapshot.SHA256 != "" {
				return errors.New("invalid omitted regular snapshot")
			}
			return nil
		}
		if snapshot.Size > protocol.MaxConflictPreviewBytes || int64(len(snapshot.Content)) != snapshot.Size {
			return errors.New("regular snapshot content does not match its size")
		}
		digest := sha256.Sum256(snapshot.Content)
		if snapshot.SHA256 != fmt.Sprintf("%x", digest) {
			return errors.New("regular snapshot digest does not match its content")
		}
	case "directory", "special":
		if snapshot.SHA256 != "" || len(snapshot.Content) != 0 || snapshot.Omitted || snapshot.LinkTarget != "" {
			return fmt.Errorf("%s snapshot contains regular-file data", snapshot.Kind)
		}
	case "symlink":
		if snapshot.Size != 0 || snapshot.Mode != 0 || snapshot.SHA256 != "" || len(snapshot.Content) != 0 || snapshot.Omitted {
			return errors.New("symlink snapshot contains file data")
		}
	}
	return nil
}

func writeConflictDiff(ctx context.Context, output io.Writer, path string, local, remote protocol.FileSnapshot) error {
	fmt.Fprintf(output, "conflict %s (local -> remote)\n", strconv.QuoteToASCII(path))
	if comparableFileSnapshot(local) && comparableFileSnapshot(remote) {
		if local.Omitted || remote.Omitted {
			writeSnapshotSummary(output, "local", local)
			writeSnapshotSummary(output, "remote", remote)
			fmt.Fprintf(output, "unified preview omitted: content exceeds %d-byte limit\n", protocol.MaxConflictPreviewBytes)
			return nil
		}
		if !displaySafe(local.Content) || !displaySafe(remote.Content) {
			writeSnapshotSummary(output, "local", local)
			writeSnapshotSummary(output, "remote", remote)
			fmt.Fprintln(output, "unified preview omitted: content is binary or contains terminal control characters")
			return nil
		}
		different, err := runUnifiedDiff(ctx, output, path, local.Content, remote.Content)
		if err != nil {
			return err
		}
		if !different {
			fmt.Fprintln(output, "copies have identical content")
		}
		if local.Kind != remote.Kind || local.Mode != remote.Mode {
			fmt.Fprintf(output, "metadata: local=%s remote=%s\n", shortSnapshot(local), shortSnapshot(remote))
		}
		return nil
	}
	writeSnapshotSummary(output, "local", local)
	writeSnapshotSummary(output, "remote", remote)
	if local.Kind != remote.Kind {
		fmt.Fprintln(output, "unified preview unavailable: endpoint types differ")
	} else {
		fmt.Fprintf(output, "unified preview unavailable for %s conflicts\n", local.Kind)
	}
	return nil
}

func comparableFileSnapshot(snapshot protocol.FileSnapshot) bool {
	return snapshot.Kind == "regular" || snapshot.Kind == "missing"
}

func displaySafe(content []byte) bool {
	if !utf8.Valid(content) {
		return false
	}
	for _, character := range string(content) {
		if character != '\n' && character != '\t' && (unicode.IsControl(character) || unicode.In(character, unicode.Cf)) {
			return false
		}
	}
	return true
}

func runUnifiedDiff(ctx context.Context, output io.Writer, path string, local, remote []byte) (bool, error) {
	if _, err := exec.LookPath("diff"); err != nil {
		return false, errors.New("POSIX diff is required for conflict previews")
	}
	directory, err := os.MkdirTemp("", "pwnbridge-preview-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(directory)
	localPath := filepath.Join(directory, "local")
	remotePath := filepath.Join(directory, "remote")
	if err := os.WriteFile(localPath, local, 0o600); err != nil {
		return false, err
	}
	if err := os.WriteFile(remotePath, remote, 0o600); err != nil {
		return false, err
	}
	command := subprocess.CommandContext(ctx, "diff", "-u", "-L", "local/"+strconv.QuoteToASCII(path), "-L", "remote/"+strconv.QuoteToASCII(path), localPath, remotePath)
	stderr := subprocess.NewDiagnosticWriter()
	command.Stdout, command.Stderr = output, stderr
	err = command.Run()
	if err == nil {
		return false, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return true, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, ctxErr
	}
	if detail := stderr.Diagnostic(); detail != "" {
		return false, fmt.Errorf("run unified diff: %w: %s", err, detail)
	}
	return false, fmt.Errorf("run unified diff: %w", err)
}

func writeSnapshotSummary(output io.Writer, endpoint string, snapshot protocol.FileSnapshot) {
	fmt.Fprintf(output, "%s: %s\n", endpoint, shortSnapshot(snapshot))
}

func shortSnapshot(snapshot protocol.FileSnapshot) string {
	switch snapshot.Kind {
	case "missing":
		return "missing"
	case "symlink":
		return "symlink -> " + strconv.QuoteToASCII(snapshot.LinkTarget)
	case "regular":
		result := fmt.Sprintf("regular size=%d mode=%#o", snapshot.Size, snapshot.Mode)
		if snapshot.SHA256 != "" {
			result += " sha256=" + snapshot.SHA256
		}
		if snapshot.Omitted {
			result += " content=omitted"
		}
		return result
	default:
		return fmt.Sprintf("%s mode=%#o", snapshot.Kind, snapshot.Mode)
	}
}
