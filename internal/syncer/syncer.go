package syncer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/config"
	"github.com/simonfalke-01/pwnbridge/internal/fsutil"
	"github.com/simonfalke-01/pwnbridge/internal/subprocess"
	"github.com/simonfalke-01/pwnbridge/internal/version"
	"github.com/simonfalke-01/pwnbridge/internal/workspace"
)

var identifierPattern = regexp.MustCompile(`\bsync_[A-Za-z0-9]{32,123}\b`)

var BuiltinIgnores = []string{
	".git", ".DS_Store", ".pwnbridge", ".venv", "venv", "__pycache__", "*.pyc", ".idea", ".vscode",
}

type Spec struct {
	Workspace   workspace.Workspace
	Destination string
	Config      config.Sync
	Ignores     []string
}

type HealthReport struct {
	Identifier string   `json:"identifier"`
	Healthy    bool     `json:"healthy"`
	Paused     bool     `json:"paused"`
	Status     string   `json:"status,omitempty"`
	Problems   []string `json:"problems,omitempty"`
	Raw        any      `json:"raw,omitempty"`
}

type Engine interface {
	Ensure(context.Context, Spec, *workspace.State) error
	Prepare(context.Context, Spec, *workspace.State) (HealthReport, error)
	Resume(context.Context, string) error
	Barrier(context.Context, string) (HealthReport, error)
	Status(context.Context, string) (HealthReport, error)
	Pause(context.Context, string) error
	Terminate(context.Context, string) error
}

type Runner interface {
	Run(context.Context, ...string) ([]byte, error)
}

type daemonStarter interface{ StartDaemon(context.Context) error }

type CommandRunner struct {
	Path    string
	DataDir string
}

const (
	maxMutagenDaemonLogBytes     = 5 << 20
	maxMutagenVersionOutputBytes = 64 << 10
	maxMutagenCommandOutputBytes = 1 << 20
	maxMutagenStateOutputBytes   = 16 << 20
)

func (r CommandRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	dataDir, err := r.effectiveDataDir()
	if err != nil {
		return nil, err
	}
	cmd := subprocess.CommandContext(ctx, r.Path, args...)
	cmd.Env = commandEnvironment(dataDir)
	result, err := subprocess.Capture(ctx, cmd, mutagenOutputLimit(args), subprocess.DiagnosticLimit)
	if err != nil {
		if detail := result.Diagnostic(); detail != "" {
			return result.Stdout, fmt.Errorf("%s %s: %w: %s", r.Path, strings.Join(args, " "), err, detail)
		}
		return result.Stdout, fmt.Errorf("%s %s: %w", r.Path, strings.Join(args, " "), err)
	}
	return result.Stdout, nil
}

func mutagenOutputLimit(args []string) int {
	if len(args) == 1 && args[0] == "version" {
		return maxMutagenVersionOutputBytes
	}
	if len(args) >= 2 && args[0] == "sync" && args[1] == "list" {
		return maxMutagenStateOutputBytes
	}
	return maxMutagenCommandOutputBytes
}

func (r CommandRunner) StartDaemon(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(r.DataDir, 0o700); err != nil {
		return fmt.Errorf("create Mutagen data directory: %w", err)
	}
	if err := fsutil.ValidatePrivateDirectory(r.DataDir); err != nil {
		return fmt.Errorf("validate Mutagen data directory: %w", err)
	}
	if _, err := r.Run(ctx, "daemon", "start"); err == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	dataDir, err := r.effectiveDataDir()
	if err != nil {
		return err
	}
	logFile, _, err := fsutil.OpenPrivateRotatingAppendFile(r.DataDir, "daemon.log", maxMutagenDaemonLogBytes)
	if err != nil {
		return fmt.Errorf("open isolated Mutagen daemon log: %w", err)
	}
	cmd := exec.Command(r.Path, "daemon", "run")
	cmd.Env = commandEnvironment(dataDir)
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := ctx.Err(); err != nil {
		return errors.Join(err, logFile.Close())
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start isolated Mutagen daemon process: %w", errors.Join(err, logFile.Close()))
	}
	if err := logFile.Close(); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("close isolated Mutagen daemon log: %w", err)
	}
	if err := cmd.Process.Release(); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("release isolated Mutagen daemon process: %w", err)
	}
	return nil
}

func commandEnvironment(dataDir string) []string {
	environment := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if strings.HasPrefix(upper, "TMUX") || strings.HasPrefix(upper, "ZELLIJ") {
			continue
		}
		switch upper {
		case "MUTAGEN_DATA_DIRECTORY", "PWNBRIDGE_BROKER", "PWNBRIDGE_BROKER_TOKEN", "PWNBRIDGE_SESSION_ID", "PWNBRIDGE_SESSION_DIR", "PWNBRIDGE_RUNTIME":
			continue
		}
		environment = append(environment, entry)
	}
	return append(environment, "MUTAGEN_DATA_DIRECTORY="+dataDir)
}

func (r CommandRunner) effectiveDataDir() (string, error) {
	if len(filepath.Join(r.DataDir, "daemon", "daemon.sock")) < 100 {
		return r.DataDir, nil
	}
	if err := os.MkdirAll(r.DataDir, 0o700); err != nil {
		return "", err
	}
	hash := workspace.Fingerprint(r.DataDir)[:12]
	shortRoot := filepath.Join(os.TempDir(), fmt.Sprintf("pwnbridge-%d", os.Getuid()))
	if err := os.MkdirAll(shortRoot, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(shortRoot, 0o700); err != nil {
		return "", err
	}
	alias := filepath.Join(shortRoot, "m-"+hash)
	if target, err := os.Readlink(alias); err == nil {
		if target != r.DataDir {
			return "", fmt.Errorf("unsafe Mutagen data alias %s", alias)
		}
		return alias, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.Symlink(r.DataDir, alias); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", err
		}
		target, readErr := os.Readlink(alias)
		if readErr != nil || target != r.DataDir {
			return "", fmt.Errorf("unsafe concurrent Mutagen data alias %s", alias)
		}
	}
	return alias, nil
}

type Mutagen struct{ Runner Runner }

// Prepare establishes the execution barrier with the minimum safe hot path.
// A matching stored session goes directly through resume, flush, and complete
// health inspection. Only a definite missing-session response falls back to
// version-gated creation; unhealthy sessions remain blocking errors.
func (m Mutagen) Prepare(ctx context.Context, spec Spec, state *workspace.State) (HealthReport, error) {
	fingerprint := Fingerprint(spec)
	if state.MutagenIdentifier != "" && state.SyncFingerprint == fingerprint {
		identifier := state.MutagenIdentifier
		if err := m.Resume(ctx, identifier); err == nil {
			report, barrierErr := m.Barrier(ctx, identifier)
			if barrierErr == nil || !missingSessionError(barrierErr) {
				return report, barrierErr
			}
		} else if !missingSessionError(err) {
			return HealthReport{}, err
		}
		state.MutagenIdentifier, state.SyncFingerprint = "", ""
	}
	if err := m.Ensure(ctx, spec, state); err != nil {
		return HealthReport{}, err
	}
	if err := m.Resume(ctx, state.MutagenIdentifier); err != nil {
		return HealthReport{}, err
	}
	return m.Barrier(ctx, state.MutagenIdentifier)
}

func (m Mutagen) CheckVersion(ctx context.Context) error {
	out, err := m.Runner.Run(ctx, "version")
	if err != nil {
		return fmt.Errorf("Mutagen is required; install mutagen-io/mutagen/mutagen: %w", err)
	}
	got := strings.TrimSpace(string(out))
	got = strings.TrimPrefix(got, "mutagen version ")
	got = strings.TrimPrefix(got, "v")
	if got != version.MutagenVersion {
		return fmt.Errorf("unsupported Mutagen version %q; pwnbridge requires exactly %s", got, version.MutagenVersion)
	}
	return nil
}

func (m Mutagen) Ensure(ctx context.Context, spec Spec, state *workspace.State) error {
	if err := m.CheckVersion(ctx); err != nil {
		return err
	}
	if starter, ok := m.Runner.(daemonStarter); ok {
		if err := starter.StartDaemon(ctx); err != nil {
			return fmt.Errorf("start isolated Mutagen daemon: %w", err)
		}
	} else if _, err := m.Runner.Run(ctx, "daemon", "start"); err != nil {
		return fmt.Errorf("start isolated Mutagen daemon: %w", err)
	}
	if err := m.waitReady(ctx); err != nil {
		return err
	}
	fingerprint := Fingerprint(spec)
	if state.MutagenIdentifier != "" {
		if state.SyncFingerprint != fingerprint {
			if err := m.Resume(ctx, state.MutagenIdentifier); err == nil {
				if _, err := m.Barrier(ctx, state.MutagenIdentifier); err != nil {
					return fmt.Errorf("cannot safely replace changed sync configuration: %w", err)
				}
				if err := m.Terminate(ctx, state.MutagenIdentifier); err != nil {
					return err
				}
			} else {
				if !missingSessionError(err) {
					return err
				}
			}
			state.MutagenIdentifier, state.SyncFingerprint = "", ""
		}
		if state.MutagenIdentifier != "" {
			report, err := m.Status(ctx, state.MutagenIdentifier)
			if err == nil && report.Identifier == state.MutagenIdentifier {
				return nil
			}
			if err != nil {
				if !missingSessionError(err) {
					return err
				}
			}
			state.MutagenIdentifier, state.SyncFingerprint = "", ""
		}
	}
	args := []string{"sync", "create", "--no-global-configuration", "--name", "pwnbridge-" + spec.Workspace.ID,
		"--label", "pwnbridge.workspace=" + spec.Workspace.ID,
		"--label", "pwnbridge.host=" + spec.Workspace.HostID,
		"--label", "pwnbridge.version=" + version.Version,
		"--mode", spec.Config.Mode, "--watch-mode", spec.Config.WatchMode,
		"--symlink-mode", spec.Config.SymlinkMode, "--ignore-vcs",
	}
	ignores := append([]string{}, BuiltinIgnores...)
	ignores = append(ignores, spec.Ignores...)
	for _, ignore := range uniqueStrings(ignores) {
		args = append(args, "--ignore", ignore)
	}
	endpoint := spec.Destination + ":" + spec.Workspace.RemotePath
	args = append(args, spec.Workspace.LocalRoot, endpoint)
	out, err := m.Runner.Run(ctx, args...)
	if err != nil {
		return err
	}
	identifier := identifierPattern.FindString(string(out))
	if identifier == "" {
		lookup, lookupErr := m.Runner.Run(ctx, "sync", "list", "--template", `{{ range . }}{{ .Identifier }}{{ "\n" }}{{ end }}`, "pwnbridge-"+spec.Workspace.ID)
		if lookupErr != nil {
			return fmt.Errorf("created session but could not discover identifier: %w", lookupErr)
		}
		identifier = identifierPattern.FindString(string(lookup))
	}
	if identifier == "" {
		return fmt.Errorf("Mutagen did not return a session identifier: %s", strings.TrimSpace(string(out)))
	}
	state.MutagenIdentifier, state.SyncFingerprint = identifier, fingerprint
	return nil
}

func missingSessionError(err error) bool {
	if err == nil {
		return false
	}
	var unhealthy *UnhealthyError
	if errors.As(err, &unhealthy) {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "not found") || strings.Contains(message, "did not match")
}

func (m Mutagen) waitReady(ctx context.Context) error {
	var last error
	for attempt := 0; attempt < 50; attempt++ {
		if _, err := m.Runner.Run(ctx, "sync", "list", "--template", "{{ json . }}", "pwnbridge-readiness-probe-that-does-not-exist"); err == nil || strings.Contains(err.Error(), "did not match any sessions") {
			return nil
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return fmt.Errorf("Mutagen daemon did not become ready: %w", last)
}

func (m Mutagen) Resume(ctx context.Context, identifier string) error {
	_, err := m.Runner.Run(ctx, "sync", "resume", identifier)
	return err
}

func (m Mutagen) Pause(ctx context.Context, identifier string) error {
	_, err := m.Runner.Run(ctx, "sync", "pause", identifier)
	return err
}

func (m Mutagen) Terminate(ctx context.Context, identifier string) error {
	_, err := m.Runner.Run(ctx, "sync", "terminate", identifier)
	return err
}

func (m Mutagen) Barrier(ctx context.Context, identifier string) (HealthReport, error) {
	if _, err := m.Runner.Run(ctx, "sync", "flush", identifier); err != nil {
		return HealthReport{}, err
	}
	report, err := m.Status(ctx, identifier)
	if err != nil {
		return report, err
	}
	if !report.Healthy {
		return report, &UnhealthyError{Report: report}
	}
	return report, nil
}

func (m Mutagen) Status(ctx context.Context, identifier string) (HealthReport, error) {
	out, err := m.Runner.Run(ctx, "sync", "list", "--template", "{{ json . }}", identifier)
	if err != nil {
		return HealthReport{}, err
	}
	values, err := decodeJSONValues(out)
	if err != nil {
		return HealthReport{}, fmt.Errorf("decode Mutagen session state: %w", err)
	}
	if len(values) != 1 {
		return HealthReport{}, fmt.Errorf("expected exactly one Mutagen session, got %d", len(values))
	}
	report := inspectHealth(values[0])
	report.Identifier = identifier
	report.Raw = values[0]
	return report, nil
}

type UnhealthyError struct{ Report HealthReport }

func (e *UnhealthyError) Error() string {
	return "synchronization is unhealthy: " + strings.Join(e.Report.Problems, "; ")
}

func Fingerprint(spec Spec) string {
	parts := []string{spec.Workspace.LocalRoot, spec.Workspace.RemotePath, spec.Destination, spec.Config.Mode, spec.Config.WatchMode, spec.Config.SymlinkMode}
	parts = append(parts, uniqueStrings(append(append([]string{}, BuiltinIgnores...), spec.Ignores...))...)
	return workspace.Fingerprint(parts...)
}

func decodeJSONValues(data []byte) ([]any, error) {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	var result []any
	for {
		var value any
		if err := decoder.Decode(&value); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		if array, ok := value.([]any); ok {
			result = append(result, array...)
		} else {
			result = append(result, value)
		}
	}
	return result, nil
}

func inspectHealth(raw any) HealthReport {
	report := HealthReport{Healthy: true}
	walkHealth("", raw, &report)
	report.Problems = uniqueStrings(report.Problems)
	sort.Strings(report.Problems)
	report.Healthy = len(report.Problems) == 0 && !report.Paused
	if report.Paused {
		report.Problems = append(report.Problems, "session is paused")
	}
	return report
}

func walkHealth(path string, value any, report *HealthReport) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normal := normalizeKey(key)
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			switch {
			case normal == "paused":
				if b, ok := child.(bool); ok && b {
					report.Paused = true
				}
			case normal == "status":
				if s, ok := child.(string); ok {
					report.Status = s
					low := strings.ToLower(s)
					if strings.Contains(low, "disconnected") || strings.Contains(low, "halted") || strings.Contains(low, "error") {
						report.Problems = append(report.Problems, childPath+"="+s)
					}
				}
			case normal == "connected":
				if connected, ok := child.(bool); ok && !connected {
					report.Problems = append(report.Problems, childPath+" is disconnected")
				}
			case strings.Contains(normal, "conflict") || strings.Contains(normal, "problem") || strings.Contains(normal, "error"):
				if hasProblem(child) {
					report.Problems = append(report.Problems, describe(childPath, child))
				}
			}
			walkHealth(childPath, child, report)
		}
	case []any:
		for i, child := range typed {
			walkHealth(path+"["+strconv.Itoa(i)+"]", child, report)
		}
	}
}

func hasProblem(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return strings.TrimSpace(v) != ""
	case float64:
		return v != 0
	case []any:
		return len(v) != 0
	case map[string]any:
		return len(v) != 0
	default:
		return true
	}
}

func describe(path string, value any) string {
	switch v := value.(type) {
	case string:
		return path + ": " + v
	case float64:
		return path + ": " + strconv.FormatFloat(v, 'f', -1, 64)
	case []any:
		return fmt.Sprintf("%s: %d item(s)", path, len(v))
	case map[string]any:
		return fmt.Sprintf("%s: %d item(s)", path, len(v))
	default:
		return path
	}
}

func normalizeKey(value string) string {
	value = strings.ToLower(value)
	return strings.NewReplacer("_", "", "-", "", " ", "").Replace(value)
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func DefaultRunner(path, stateRoot string) CommandRunner {
	return CommandRunner{Path: path, DataDir: filepath.Join(stateRoot, "mutagen", "v0.18")}
}

func ConflictPaths(raw any) []string {
	seen := map[string]bool{}
	var walk func(any, bool)
	walk = func(value any, inConflict bool) {
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				normal := normalizeKey(key)
				inside := inConflict || strings.Contains(normal, "conflict")
				if inside && normal == "path" {
					if path, ok := child.(string); ok && path != "" {
						seen[filepath.Clean(path)] = true
					}
				}
				walk(child, inside)
			}
		case []any:
			for _, child := range typed {
				walk(child, inConflict)
			}
		}
	}
	walk(raw, false)
	result := make([]string, 0, len(seen))
	for path := range seen {
		result = append(result, path)
	}
	sort.Strings(result)
	return result
}
