package transport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/pwnbridge/pwnbridge/internal/agent"
	"github.com/pwnbridge/pwnbridge/internal/version"
)

type Client struct {
	SSH         string
	SCP         string
	Destination string
	AgentPath   string
}

type HostProbe struct {
	Home             string          `json:"home"`
	OS               string          `json:"os"`
	Architecture     string          `json:"architecture"`
	Version          string          `json:"version,omitempty"`
	Protocol         int             `json:"protocol,omitempty"`
	Tools            map[string]bool `json:"tools,omitempty"`
	Distro           string          `json:"distro,omitempty"`
	DistroVersion    string          `json:"distro_version,omitempty"`
	DiskAvailableKiB uint64          `json:"disk_available_kib,omitempty"`
	InodesAvailable  uint64          `json:"inodes_available,omitempty"`
	HomeWritable     bool            `json:"home_writable"`
	PtraceScope      string          `json:"ptrace_scope,omitempty"`
	PwntoolsVersion  string          `json:"pwntools_version,omitempty"`
}

type Master struct {
	Client        Client
	ControlPath   string
	RemoteSocket  string
	BrokerAddress string
	LocalSocket   string
	RelayPIDFile  string
	process       *exec.Cmd
	done          chan error
}

func New(destination, agentPath string) Client {
	return Client{SSH: "ssh", SCP: "scp", Destination: destination, AgentPath: agentPath}
}

func (c Client) BasicProbe(ctx context.Context) (HostProbe, error) {
	command := `printf '%s\n' "$HOME"; uname -s; uname -m`
	out, err := c.run(ctx, "-T", c.Destination, command)
	if err != nil {
		return HostProbe{}, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 3 {
		return HostProbe{}, fmt.Errorf("unexpected SSH probe output: %q", out)
	}
	probe := HostProbe{Home: lines[0], OS: strings.ToLower(lines[1]), Architecture: normalizeArchitecture(lines[2])}
	return probe, nil
}

func (c Client) ProbeAgent(ctx context.Context) (HostProbe, error) {
	out, err := c.run(ctx, "-T", c.Destination, remoteAgentCommand(c.AgentPath, "probe", ""))
	if err != nil {
		return HostProbe{}, err
	}
	var probe HostProbe
	if err := json.Unmarshal(out, &probe); err != nil {
		return HostProbe{}, fmt.Errorf("decode agent probe: %w", err)
	}
	if probe.Protocol != version.ProtocolVersion {
		return probe, fmt.Errorf("agent protocol %d is incompatible with client protocol %d", probe.Protocol, version.ProtocolVersion)
	}
	if probe.OS != "linux" || probe.Architecture != "amd64" {
		return probe, fmt.Errorf("unsupported remote platform %s/%s", probe.OS, probe.Architecture)
	}
	return probe, nil
}

func (c Client) DeployAgent(ctx context.Context, localPath string) (string, error) {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return "", fmt.Errorf("read agent asset: %w", err)
	}
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	probe, err := c.BasicProbe(ctx)
	if err != nil {
		return "", err
	}
	if probe.OS != "linux" || probe.Architecture != "amd64" {
		return "", fmt.Errorf("remote must be linux/amd64, got %s/%s", probe.OS, probe.Architecture)
	}
	dir := probe.Home + "/.local/share/pwnbridge/agents/" + strconv.Itoa(version.ProtocolVersion) + "/" + digest
	remote := dir + "/pwnbridge-agent"
	check := "test -x " + shellQuote(remote) + " && test \"$(sha256sum " + shellQuote(remote) + " | cut -d' ' -f1)\" = " + shellQuote(digest) + " && printf present"
	if out, _ := c.run(ctx, "-T", c.Destination, check); strings.TrimSpace(string(out)) == "present" {
		c.pruneAgents(ctx, filepath.Dir(dir), dir)
		return remote, nil
	}
	cache := probe.Home + "/.cache/pwnbridge"
	prepare := "umask 077; mkdir -p " + shellQuote(cache) + " " + shellQuote(dir) + "; mktemp " + shellQuote(cache+"/upload-"+digest+".XXXXXX")
	tmpOut, err := c.run(ctx, "-T", c.Destination, prepare)
	if err != nil {
		return "", err
	}
	tmp := strings.TrimSpace(string(tmpOut))
	if !strings.HasPrefix(tmp, cache+"/upload-"+digest+".") {
		return "", fmt.Errorf("remote mktemp returned unexpected path %q", tmp)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = c.run(cleanupCtx, "-T", c.Destination, "rm -f -- "+shellQuote(tmp))
	}()
	target := c.Destination + ":" + tmp
	cmd := exec.CommandContext(ctx, c.SCP, "-q", "--", localPath, target)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("upload agent: %w: %s", err, strings.TrimSpace(string(out)))
	}
	install := "set -eu; got=$(sha256sum " + shellQuote(tmp) + " | cut -d' ' -f1); " +
		"test \"$got\" = " + shellQuote(digest) + "; chmod 700 " + shellQuote(tmp) + "; mv " + shellQuote(tmp) + " " + shellQuote(remote)
	if _, err := c.run(ctx, "-T", c.Destination, install); err != nil {
		return "", err
	}
	c.pruneAgents(ctx, filepath.Dir(dir), dir)
	return remote, nil
}

func (c Client) pruneAgents(ctx context.Context, root, current string) {
	script := "root=" + shellQuote(root) + "; current=" + shellQuote(current) + `; count=0
find "$root" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' 2>/dev/null | sort -nr | while read -r stamp path; do
  base=${path##*/}
  case "$base" in ''|*[!0-9a-f]*) continue ;; esac
  [ "${#base}" -eq 64 ] || continue
  [ "$path" = "$current" ] && continue
  in_use=false
  for exe in /proc/[0-9]*/exe; do
    target=$(readlink "$exe" 2>/dev/null || true)
    case "$target" in "$path"/*) in_use=true; break ;; esac
  done
  [ "$in_use" = true ] && continue
  count=$((count+1))
  [ "$count" -le 2 ] || rm -rf -- "$path"
done`
	_, _ = c.run(ctx, "-T", c.Destination, script)
}

func (c Client) StartMaster(ctx context.Context, runtimeDir, localBroker, remoteBroker, localTCP string) (*Master, error) {
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return nil, err
	}
	control := filepath.Join(runtimeDir, "c")
	args := []string{"-M", "-N", "-S", control,
		"-o", "ControlMaster=yes", "-o", "ControlPersist=no", "-o", "ClearAllForwardings=yes",
		"-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3", "-o", "ForwardAgent=no",
		"-o", "ForwardX11=no", "-o", "ExitOnForwardFailure=yes", "-o", "StreamLocalBindMask=0177",
	}
	args = append(args, c.Destination)
	// The master must outlive cancellation of the foreground command long
	// enough for the session defer to stop containers, flush artifacts, and
	// cancel forwards. It is terminated explicitly by Master.Close.
	cmd := exec.Command(c.SSH, args...)
	cmd.Stdin = nil
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	master := &Master{Client: c, ControlPath: control, RemoteSocket: remoteBroker, LocalSocket: localBroker, process: cmd, done: make(chan error, 1)}
	go func() { master.done <- cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case processErr := <-master.done:
			return nil, fmt.Errorf("SSH control master exited during startup: %w", processErr)
		default:
		}
		check := exec.CommandContext(ctx, c.SSH, "-S", control, "-O", "check", c.Destination)
		if err := check.Run(); err == nil {
			if localBroker != "" && remoteBroker != "" {
				forward := exec.CommandContext(ctx, c.SSH, "-S", control, "-O", "forward", "-R", remoteBroker+":"+localBroker, c.Destination)
				if output, forwardErr := forward.CombinedOutput(); forwardErr != nil {
					if localTCP == "" {
						_ = master.Close()
						return nil, fmt.Errorf("create reverse stream-local forward: %w: %s", forwardErr, strings.TrimSpace(string(output)))
					}
					host, port, splitErr := net.SplitHostPort(localTCP)
					if splitErr != nil {
						_ = master.Close()
						return nil, splitErr
					}
					fallback := exec.CommandContext(ctx, c.SSH, "-S", control, "-O", "forward", "-R", "127.0.0.1:0:"+host+":"+port, c.Destination)
					fallbackOut, fallbackErr := fallback.CombinedOutput()
					if fallbackErr != nil {
						_ = master.Close()
						return nil, fmt.Errorf("reverse forwarding unavailable (stream-local: %v; TCP: %w: %s)", forwardErr, fallbackErr, strings.TrimSpace(string(fallbackOut)))
					}
					allocated := strings.TrimSpace(string(fallbackOut))
					if _, parseErr := strconv.Atoi(allocated); parseErr != nil {
						_ = master.Close()
						return nil, fmt.Errorf("SSH did not report allocated reverse port: %q", allocated)
					}
					master.BrokerAddress = "tcp:127.0.0.1:" + allocated
					// A container with bridge networking cannot reach a listener bound
					// to the host's loopback.  When socat is available (it is part of
					// the pwn bootstrap), expose the TCP fallback as the same private
					// Unix socket used by the normal stream-local path.  Direct-host
					// execution still retains the loopback TCP fallback if socat is
					// absent.
					relayPID := remoteBroker + ".relay.pid"
					relayScript := "umask 077; command -v socat >/dev/null 2>&1 || exit 0; " +
						"rm -f -- " + shellQuote(remoteBroker) + " " + shellQuote(relayPID) + "; " +
						"nohup socat UNIX-LISTEN:" + shellQuote(remoteBroker) + ",fork,mode=600 TCP:127.0.0.1:" + allocated +
						" </dev/null >/dev/null 2>&1 & pid=$!; printf '%s' \"$pid\" > " + shellQuote(relayPID) + "; " +
						"i=0; while [ \"$i\" -lt 100 ]; do test -S " + shellQuote(remoteBroker) + " && { printf relay; exit 0; }; " +
						"kill -0 \"$pid\" 2>/dev/null || exit 1; i=$((i+1)); sleep 0.02; done; exit 1"
					relay := exec.CommandContext(ctx, c.SSH, "-S", control, "-T", c.Destination, relayScript)
					if relayOut, relayErr := relay.CombinedOutput(); relayErr == nil && strings.TrimSpace(string(relayOut)) == "relay" {
						master.BrokerAddress = "unix:" + remoteBroker
						master.RelayPIDFile = relayPID
					}
				} else {
					master.BrokerAddress = "unix:" + remoteBroker
				}
			}
			return master, nil
		}
		select {
		case <-ctx.Done():
			_ = master.Close()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	_ = master.Close()
	return nil, errors.New("SSH control master did not become ready")
}

func (m *Master) Command(ctx context.Context, tty bool, operation, encoded string) *exec.Cmd {
	args := []string{"-S", m.ControlPath}
	if tty {
		args = append(args, "-tt", "-e", "none")
	} else {
		args = append(args, "-T")
	}
	args = append(args, m.Client.Destination, remoteAgentCommand(m.Client.AgentPath, operation, encoded))
	return exec.CommandContext(ctx, m.Client.SSH, args...)
}

func (m *Master) Run(ctx context.Context, operation string, request any) ([]byte, error) {
	encoded, err := agent.EncodeRequest(request)
	if err != nil {
		return nil, err
	}
	cmd := m.Command(ctx, false, operation, encoded)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("remote %s: %w: %s", operation, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func (m *Master) Close() error {
	if m == nil {
		return nil
	}
	if m.ControlPath != "" {
		if m.RelayPIDFile != "" {
			script := "pid=''; test ! -f " + shellQuote(m.RelayPIDFile) + " || pid=$(cat " + shellQuote(m.RelayPIDFile) + "); " +
				"case \"$pid\" in ''|*[!0-9]*) ;; *) kill \"$pid\" 2>/dev/null || true ;; esac; " +
				"rm -f -- " + shellQuote(m.RelayPIDFile) + " " + shellQuote(m.RemoteSocket)
			_ = exec.Command(m.Client.SSH, "-S", m.ControlPath, "-T", m.Client.Destination, script).Run()
		}
		_ = exec.Command(m.Client.SSH, "-S", m.ControlPath, "-O", "exit", m.Client.Destination).Run()
	}
	if m.process != nil {
		if m.process.Process != nil {
			_ = m.process.Process.Signal(os.Interrupt)
		}
		if m.done != nil {
			select {
			case <-m.done:
			case <-time.After(time.Second):
				if m.process.Process != nil {
					_ = m.process.Process.Kill()
				}
			}
		}
	}
	return nil
}

func (c Client) run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, c.SSH, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("ssh: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func remoteAgentCommand(path, operation, encoded string) string {
	resolved := shellQuote(path)
	if strings.HasPrefix(path, "~/") {
		resolved = `"$HOME"/` + shellQuote(strings.TrimPrefix(path, "~/"))
	}
	command := "exec " + resolved + " " + shellQuote(operation)
	if encoded != "" {
		command += " " + shellQuote(encoded)
	}
	return command
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

func normalizeArchitecture(value string) string {
	switch strings.TrimSpace(value) {
	case "x86_64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	default:
		return strings.TrimSpace(value)
	}
}

func FindAgentAsset(explicit string) (string, error) {
	if explicit != "" {
		if info, err := os.Stat(explicit); err == nil && !info.IsDir() {
			return explicit, nil
		}
		return "", fmt.Errorf("agent asset %s does not exist", explicit)
	}
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	candidates := []string{
		filepath.Join(filepath.Dir(executable), "pwnbridge-agent-linux-amd64"),
		filepath.Join(filepath.Dir(filepath.Dir(executable)), "libexec", "pwnbridge", "pwnbridge-agent-linux-amd64"),
		filepath.Join(filepath.Dir(executable), "..", "libexec", "pwnbridge", "pwnbridge-agent-linux-amd64"),
	}
	if runtime.GOOS == "darwin" {
		for _, candidate := range candidates {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return filepath.Clean(candidate), nil
			}
		}
	}
	return "", errors.New("Linux agent asset not found; run `make build` or set PWNBRIDGE_AGENT_PATH")
}

func CopyOutput(dst io.Writer, out []byte) { _, _ = dst.Write(out) }
