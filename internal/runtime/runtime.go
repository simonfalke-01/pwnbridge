package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"

	"github.com/simonfalke-01/pwnbridge/internal/protocol"
	"github.com/simonfalke-01/pwnbridge/internal/subprocess"
)

const maxRuntimeCommandOutputBytes = 64 << 10

type State struct {
	Kind    string `json:"kind"`
	Engine  string `json:"engine,omitempty"`
	ID      string `json:"id,omitempty"`
	Running bool   `json:"running"`
}

func Ensure(ctx context.Context, spec *protocol.RuntimeSpec, sessionID string) (State, error) {
	return EnsureProgress(ctx, spec, sessionID, nil)
}

// EnsureProgress is Ensure with optional direct image-pull progress. Progress
// is an opaque stream and is never used for command responses or diagnostics.
func EnsureProgress(ctx context.Context, spec *protocol.RuntimeSpec, sessionID string, progress io.Writer) (State, error) {
	if err := ctx.Err(); err != nil {
		return State{}, err
	}
	if spec.Kind == "" || spec.Kind == "host" {
		spec.Kind = "host"
		return State{Kind: "host", Running: true}, nil
	}
	if spec.Kind != "container" {
		return State{}, fmt.Errorf("unsupported runtime kind %q", spec.Kind)
	}
	engine, err := detectEngine(spec.Engine)
	if err != nil {
		return State{}, err
	}
	if spec.Image == "" {
		return State{}, errors.New("container image is required")
	}
	name := spec.ID
	if name == "" {
		name = "pwnbridge-" + sanitizeID(sessionID)
	}
	if !strings.HasPrefix(name, "pwnbridge-") {
		name = "pwnbridge-" + sanitizeID(name)
	}
	spec.Engine, spec.ID = engine, name
	inspect := subprocess.CommandContext(ctx, engine, "inspect", "-f", "{{.State.Running}}", name)
	inspectResult, inspectErr := subprocess.Capture(ctx, inspect, maxRuntimeCommandOutputBytes, subprocess.DiagnosticLimit)
	if inspectErr == nil && strings.TrimSpace(string(inspectResult.Stdout)) == "true" {
		return State{Kind: "container", Engine: engine, ID: name, Running: true}, nil
	}
	if err := ctx.Err(); err != nil {
		return State{}, err
	}
	var limitErr *subprocess.OutputLimitError
	if errors.As(inspectErr, &limitErr) {
		return State{}, runtimeCommandError("inspect existing container", inspectResult, inspectErr)
	}
	var exitErr *exec.ExitError
	if inspectErr != nil && !errors.As(inspectErr, &exitErr) {
		return State{}, runtimeCommandError("inspect existing container", inspectResult, inspectErr)
	}
	_ = subprocess.CommandContext(ctx, engine, "rm", "-f", name).Run()
	imageID, err := resolveImageProgress(ctx, engine, spec.Image, progress)
	if err != nil {
		return State{}, err
	}
	uid, gid := currentIDs()
	workdir := spec.Workdir
	if workdir == "" {
		workdir = "/work"
		spec.Workdir = workdir
	}
	network := spec.Network
	if network == "" {
		network = "bridge"
		spec.Network = network
	}
	args := []string{"run", "-d", "--name", name}
	if engine == "podman" {
		args = append(args, "--userns", "keep-id")
	}
	args = append(args, "--user", uid+":"+gid,
		"--label", "pwnbridge=true", "--label", "pwnbridge.session="+sanitizeID(sessionID),
		"--label", "pwnbridge.workspace="+sanitizeID(spec.WorkspaceID),
		"--cap-add", "SYS_PTRACE", "--security-opt", "seccomp=unconfined", "--network", network,
		"-v", spec.Workspace+":/work", "-v", spec.SessionDir+":/run/pwnbridge",
		"-v", filepath.Join(spec.SessionDir, "bin")+":/run/pwnbridge/bin:ro", "-w", workdir,
		"-e", "HOME=/tmp/pwnbridge-home", imageID, "sh", "-c", "mkdir -p /tmp/pwnbridge-home && exec sleep infinity")
	cmd := subprocess.CommandContext(ctx, engine, args...)
	result, err := subprocess.Capture(ctx, cmd, maxRuntimeCommandOutputBytes, subprocess.DiagnosticLimit)
	if err != nil {
		return State{}, runtimeCommandError("create container", result, err)
	}
	return State{Kind: "container", Engine: engine, ID: name, Running: true}, nil
}

// resolveImage converts even a convenient tag in local configuration into the
// immutable content ID actually passed to container run. Running session
// containers are reused before this is called, so later debugger panes do not
// depend on a tag still existing locally.
func resolveImage(ctx context.Context, engine, reference string) (string, error) {
	return resolveImageProgress(ctx, engine, reference, nil)
}

func resolveImageProgress(ctx context.Context, engine, reference string, progress io.Writer) (string, error) {
	inspect := func() (string, error) {
		cmd := subprocess.CommandContext(ctx, engine, "image", "inspect", "--format", "{{.Id}}", reference)
		result, err := subprocess.Capture(ctx, cmd, maxRuntimeCommandOutputBytes, subprocess.DiagnosticLimit)
		if err != nil {
			return "", runtimeCommandError(fmt.Sprintf("inspect container image %q", reference), result, err)
		}
		id := strings.TrimSpace(string(result.Stdout))
		hex := strings.TrimPrefix(id, "sha256:")
		if len(hex) != 64 {
			return "", fmt.Errorf("container engine returned a non-immutable image ID %q", id)
		}
		for _, r := range hex {
			if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
				return "", fmt.Errorf("container engine returned an invalid image ID %q", id)
			}
		}
		return "sha256:" + hex, nil
	}
	if id, err := inspect(); err == nil {
		return id, nil
	} else if ctx.Err() != nil {
		return "", ctx.Err()
	} else {
		var limitErr *subprocess.OutputLimitError
		if errors.As(err, &limitErr) {
			return "", err
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return "", err
		}
	}
	if progress != nil {
		pull := subprocess.CommandContext(ctx, engine, "pull", reference)
		writer := &lockedWriter{target: progress}
		pull.Stdout, pull.Stderr = writer, writer
		if err := pull.Run(); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return "", ctxErr
			}
			return "", fmt.Errorf("pull container image %q: %w", reference, err)
		}
	} else {
		pull := subprocess.CommandContext(ctx, engine, "pull", "--quiet", reference)
		result, err := subprocess.Capture(ctx, pull, maxRuntimeCommandOutputBytes, subprocess.DiagnosticLimit)
		if err != nil {
			return "", runtimeCommandError(fmt.Sprintf("pull container image %q", reference), result, err)
		}
	}
	return inspect()
}

func runtimeCommandError(operation string, result subprocess.CaptureResult, err error) error {
	if detail := result.Diagnostic(); detail != "" {
		return fmt.Errorf("%s: %w: %s", operation, err, detail)
	}
	return fmt.Errorf("%s: %w", operation, err)
}

type lockedWriter struct {
	mu     sync.Mutex
	target io.Writer
}

func (w *lockedWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.target.Write(data)
}

func Command(spec protocol.RuntimeSpec, tty bool, cwd string, environment map[string]string, argv []string) (*exec.Cmd, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty command")
	}
	if spec.Kind == "" || spec.Kind == "host" {
		executable := argv[0]
		if !strings.ContainsRune(executable, filepath.Separator) {
			search := environment["PATH"]
			if search == "" {
				search = os.Getenv("PATH")
			}
			resolved, err := lookPath(executable, search)
			if err != nil {
				return nil, err
			}
			executable = resolved
		}
		cmd := exec.Command(executable, argv[1:]...)
		cmd.Dir = cwd
		cmd.Env = mergeEnvironment(os.Environ(), environment)
		return cmd, nil
	}
	if spec.Kind != "container" || spec.Engine == "" || spec.ID == "" {
		return nil, errors.New("container runtime is not initialized")
	}
	args := []string{"exec", "-i"}
	if tty {
		args = append(args, "-t")
	}
	containerCwd := translateCwd(spec, cwd)
	args = append(args, "-w", containerCwd)
	for key, value := range environment {
		args = append(args, "-e", key+"="+value)
	}
	args = append(args, spec.ID)
	args = append(args, argv...)
	cmd := exec.Command(spec.Engine, args...)
	cmd.Env = os.Environ()
	return cmd, nil
}

func lookPath(name, search string) (string, error) {
	for _, directory := range filepath.SplitList(search) {
		if directory == "" {
			directory = "."
		}
		candidate := filepath.Join(directory, name)
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() && info.Mode().Perm()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("executable %q not found in PATH", name)
}

func Inspect(ctx context.Context, spec protocol.RuntimeSpec) (State, error) {
	if err := ctx.Err(); err != nil {
		return State{}, err
	}
	if spec.Kind == "" || spec.Kind == "host" {
		return State{Kind: "host", Running: true}, nil
	}
	if spec.Engine == "" || spec.ID == "" {
		return State{Kind: "container"}, nil
	}
	cmd := subprocess.CommandContext(ctx, spec.Engine, "inspect", "-f", "{{.State.Running}}", spec.ID)
	result, err := subprocess.Capture(ctx, cmd, maxRuntimeCommandOutputBytes, subprocess.DiagnosticLimit)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return State{}, ctxErr
		}
		var limitErr *subprocess.OutputLimitError
		if errors.As(err, &limitErr) {
			return State{}, runtimeCommandError("inspect container", result, err)
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return State{Kind: "container", Engine: spec.Engine, ID: spec.ID}, nil
		}
		return State{}, runtimeCommandError("inspect container", result, err)
	}
	return State{Kind: "container", Engine: spec.Engine, ID: spec.ID, Running: strings.TrimSpace(string(result.Stdout)) == "true"}, nil
}

func Stop(ctx context.Context, spec protocol.RuntimeSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if spec.Kind != "container" || spec.ID == "" {
		return nil
	}
	engine, detectErr := detectEngine(spec.Engine)
	if detectErr != nil {
		return detectErr
	}
	cmd := subprocess.CommandContext(ctx, engine, "rm", "-f", spec.ID)
	result, err := subprocess.Capture(ctx, cmd, maxRuntimeCommandOutputBytes, subprocess.DiagnosticLimit)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		// Podman can report a rootless network-namespace cleanup error after it
		// has successfully removed the container.  Re-inspect before treating
		// that diagnostic as a failed teardown.
		if inspectErr := subprocess.CommandContext(ctx, engine, "inspect", spec.ID).Run(); inspectErr != nil {
			return nil
		}
		return runtimeCommandError("remove container", result, err)
	}
	return nil
}

func translateCwd(spec protocol.RuntimeSpec, cwd string) string {
	if spec.Workdir != "" {
		if rel, err := filepath.Rel(spec.Workdir, cwd); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return filepath.ToSlash(cwd)
		}
	}
	if spec.Workspace != "" {
		if rel, err := filepath.Rel(spec.Workspace, cwd); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			if rel == "." {
				return spec.Workdir
			}
			return filepath.ToSlash(filepath.Join(spec.Workdir, rel))
		}
	}
	return spec.Workdir
}

func detectEngine(preferred string) (string, error) {
	if preferred != "" && preferred != "auto" {
		if _, err := exec.LookPath(preferred); err != nil {
			return "", fmt.Errorf("container engine %q not found", preferred)
		}
		return preferred, nil
	}
	for _, name := range []string{"podman", "docker"} {
		if _, err := exec.LookPath(name); err == nil {
			return name, nil
		}
	}
	return "", errors.New("neither podman nor docker is installed")
}

func currentIDs() (string, string) {
	if current, err := user.Current(); err == nil {
		return current.Uid, current.Gid
	}
	return fmt.Sprint(os.Getuid()), fmt.Sprint(os.Getgid())
}

func sanitizeID(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "session"
	}
	return b.String()
}

func mergeEnvironment(base []string, overlay map[string]string) []string {
	values := make(map[string]string, len(base)+len(overlay))
	for _, entry := range base {
		if index := strings.IndexByte(entry, '='); index > 0 {
			values[entry[:index]] = entry[index+1:]
		}
	}
	for key, value := range overlay {
		values[key] = value
	}
	result := make([]string, 0, len(values))
	for key, value := range values {
		result = append(result, key+"="+value)
	}
	return result
}
