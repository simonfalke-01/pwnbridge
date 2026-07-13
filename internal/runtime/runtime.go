package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/pwnbridge/pwnbridge/internal/protocol"
)

type State struct {
	Kind    string `json:"kind"`
	Engine  string `json:"engine,omitempty"`
	ID      string `json:"id,omitempty"`
	Running bool   `json:"running"`
}

func Ensure(ctx context.Context, spec *protocol.RuntimeSpec, sessionID string) (State, error) {
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
	inspect := exec.CommandContext(ctx, engine, "inspect", "-f", "{{.State.Running}}", name)
	if out, err := inspect.Output(); err == nil && strings.TrimSpace(string(out)) == "true" {
		return State{Kind: "container", Engine: engine, ID: name, Running: true}, nil
	}
	_ = exec.CommandContext(ctx, engine, "rm", "-f", name).Run()
	imageID, err := resolveImage(ctx, engine, spec.Image)
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
	cmd := exec.CommandContext(ctx, engine, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return State{}, fmt.Errorf("create container: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return State{Kind: "container", Engine: engine, ID: name, Running: true}, nil
}

// resolveImage converts even a convenient tag in local configuration into the
// immutable content ID actually passed to container run. Running session
// containers are reused before this is called, so later debugger panes do not
// depend on a tag still existing locally.
func resolveImage(ctx context.Context, engine, reference string) (string, error) {
	inspect := func() (string, error) {
		out, err := exec.CommandContext(ctx, engine, "image", "inspect", "--format", "{{.Id}}", reference).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("inspect container image %q: %w: %s", reference, err, strings.TrimSpace(string(out)))
		}
		id := strings.TrimSpace(string(out))
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
	}
	pull := exec.CommandContext(ctx, engine, "pull", reference)
	if out, err := pull.CombinedOutput(); err != nil {
		return "", fmt.Errorf("pull container image %q: %w: %s", reference, err, strings.TrimSpace(string(out)))
	}
	return inspect()
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
	if spec.Kind == "" || spec.Kind == "host" {
		return State{Kind: "host", Running: true}, nil
	}
	if spec.Engine == "" || spec.ID == "" {
		return State{Kind: "container"}, nil
	}
	out, err := exec.CommandContext(ctx, spec.Engine, "inspect", "-f", "{{.State.Running}}", spec.ID).Output()
	if err != nil {
		return State{Kind: "container", Engine: spec.Engine, ID: spec.ID}, nil
	}
	return State{Kind: "container", Engine: spec.Engine, ID: spec.ID, Running: strings.TrimSpace(string(out)) == "true"}, nil
}

func Stop(ctx context.Context, spec protocol.RuntimeSpec) error {
	if spec.Kind != "container" || spec.ID == "" {
		return nil
	}
	engine, detectErr := detectEngine(spec.Engine)
	if detectErr != nil {
		return detectErr
	}
	out, err := exec.CommandContext(ctx, engine, "rm", "-f", spec.ID).CombinedOutput()
	if err != nil {
		// Podman can report a rootless network-namespace cleanup error after it
		// has successfully removed the container.  Re-inspect before treating
		// that diagnostic as a failed teardown.
		if inspectErr := exec.CommandContext(ctx, engine, "inspect", spec.ID).Run(); inspectErr != nil {
			return nil
		}
		return fmt.Errorf("remove container: %w: %s", err, strings.TrimSpace(string(out)))
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
