package transport

import (
	"bytes"
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
	"sync"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/agent"
	"github.com/simonfalke-01/pwnbridge/internal/fsutil"
	"github.com/simonfalke-01/pwnbridge/internal/subprocess"
	"github.com/simonfalke-01/pwnbridge/internal/version"
)

const (
	maxAgentAssetBytes       = 16 << 20
	maxSSHProbeOutputBytes   = 64 << 10
	maxSSHCommandOutputBytes = 1 << 20
	maxAgentProbeOutputBytes = 1 << 20
	maxAgentResponseBytes    = 2 << 20
	masterCloseTimeout       = 5 * time.Second
	masterInterruptTimeout   = time.Second
	masterPostKillWaitLimit  = 2 * time.Second
)

type Client struct {
	SSH         string
	SCP         string
	Mosh        string
	Destination string
	AgentPath   string
	ControlPath string
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
	closeTimeout  time.Duration
	closeOnce     sync.Once
}

func New(destination, agentPath string) Client {
	return Client{SSH: "ssh", SCP: "scp", Mosh: "mosh", Destination: destination, AgentPath: agentPath}
}

func (c Client) BasicProbe(ctx context.Context) (HostProbe, error) {
	command := `printf '__PWNBRIDGE_HOME__%s\n' "$HOME"; printf '__PWNBRIDGE_OS__'; uname -s; printf '__PWNBRIDGE_ARCH__'; uname -m`
	out, err := c.runBounded(ctx, maxSSHProbeOutputBytes, "-T", c.Destination, command)
	if err != nil {
		return HostProbe{}, err
	}
	return parseBasicProbe(out)
}

// Raw runs a non-interactive management command on the destination and retains
// at most 1 MiB of combined output. When the client was obtained from a Master,
// it automatically reuses that private connection. Deliberate bulk streams use
// dedicated pipe-based paths instead.
func (c Client) Raw(ctx context.Context, command string) ([]byte, error) {
	return c.run(ctx, "-T", c.Destination, command)
}

// RawBounded runs a non-interactive command while retaining at most limit
// combined stdout/stderr bytes. Excess output is drained so the SSH process can
// finish normally, then reported as an error without returning discarded data.
func (c Client) RawBounded(ctx context.Context, command string, limit int) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("SSH output limit must be positive")
	}
	return c.runBounded(ctx, limit, "-T", c.Destination, command)
}

// RunPTY executes one script through one ordinary SSH PTY. Bootstrap uses this
// to keep sudo authentication visible and to share the sudo timestamp across
// every privileged step without ever handling credentials itself.
func (c Client) RunPTY(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, command string) error {
	args := []string{"-tt"}
	if c.ControlPath != "" {
		args = append(args, "-o", "ControlPath="+c.ControlPath)
	}
	args = append(args, "--", c.Destination, command)
	cmd := subprocess.CommandContext(ctx, c.SSH, args...)
	cmd.Env = SafeSSHEnvironment()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	return nil
}

func parseBasicProbe(out []byte) (HostProbe, error) {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var probe HostProbe
	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "__PWNBRIDGE_HOME__"):
			probe.Home = strings.TrimPrefix(line, "__PWNBRIDGE_HOME__")
		case strings.HasPrefix(line, "__PWNBRIDGE_OS__"):
			probe.OS = strings.ToLower(strings.TrimPrefix(line, "__PWNBRIDGE_OS__"))
		case strings.HasPrefix(line, "__PWNBRIDGE_ARCH__"):
			probe.Architecture = normalizeArchitecture(strings.TrimPrefix(line, "__PWNBRIDGE_ARCH__"))
		}
	}
	if probe.Home != "" && probe.OS != "" && probe.Architecture != "" {
		return probe, nil
	}
	// Compatibility with fake transports and older captured probe output.
	if len(lines) < 3 {
		return HostProbe{}, fmt.Errorf("unexpected SSH probe output: %q", out)
	}
	return HostProbe{Home: lines[0], OS: strings.ToLower(lines[1]), Architecture: normalizeArchitecture(lines[2])}, nil
}

// CheckRemoteForwarding verifies the least-capable reverse-forwarding path
// used by the debugger broker. It deliberately creates a private control
// master first: ClearAllForwardings on that master removes configured forwards,
// then the control operation below tests a newly added forward without reusing
// or mutating any user-owned multiplexed SSH connection.
func (c Client) CheckRemoteForwarding(ctx context.Context) error {
	runtimeDir, err := os.MkdirTemp("", "pb-forward-check-")
	if err != nil {
		return fmt.Errorf("create forwarding probe directory: %w", err)
	}
	defer os.RemoveAll(runtimeDir)
	master, err := c.StartControlMaster(ctx, runtimeDir)
	if err != nil {
		return fmt.Errorf("start forwarding probe: %w", err)
	}
	defer master.Close()
	if out, err := c.runBounded(ctx, maxSSHProbeOutputBytes, "-S", master.ControlPath, "-O", "forward", "-R", "127.0.0.1:0:127.0.0.1:9", c.Destination); err != nil {
		return fmt.Errorf("reverse SSH forwarding is unavailable: %w", err)
	} else if port, parseErr := strconv.Atoi(strings.TrimSpace(string(out))); parseErr != nil || port < 1 || port > 65535 {
		return fmt.Errorf("SSH did not report an allocated reverse port: %q", strings.TrimSpace(string(out)))
	}
	return nil
}

func (c Client) ProbeAgent(ctx context.Context) (HostProbe, error) {
	out, err := c.runBounded(ctx, maxAgentProbeOutputBytes, "-T", c.Destination, remoteAgentCommand(c.AgentPath, "probe", ""))
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
	data, err := fsutil.ReadFileLimit(localPath, maxAgentAssetBytes)
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
	args := []string{"-q"}
	if c.ControlPath != "" {
		args = append(args, "-o", "ControlPath="+c.ControlPath)
	}
	args = append(args, "--", localPath, target)
	cmd := subprocess.CommandContext(ctx, c.SCP, args...)
	cmd.Env = SafeSSHEnvironment()
	output := boundedOutput{limit: maxSSHProbeOutputBytes}
	cmd.Stdout, cmd.Stderr = &output, &output
	err = cmd.Run()
	out, exceeded := output.snapshot()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", ctxErr
	}
	if exceeded {
		return "", fmt.Errorf("SCP output exceeded %d-byte limit", maxSSHProbeOutputBytes)
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
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
running=$(find /proc/[0-9]*/exe -printf '%l\n' 2>/dev/null || true)
find "$root" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' 2>/dev/null | sort -nr | while read -r stamp path; do
  base=${path##*/}
  case "$base" in ''|*[!0-9a-f]*) continue ;; esac
  [ "${#base}" -eq 64 ] || continue
  [ "$path" = "$current" ] && continue
  case "$running" in *"$path/"*) continue ;; esac
  count=$((count+1))
  [ "$count" -le 2 ] || rm -rf -- "$path"
done`
	_, _ = c.run(ctx, "-T", c.Destination, script)
}

func (c Client) StartMaster(ctx context.Context, runtimeDir, localBroker, remoteBroker, localTCP string) (*Master, error) {
	master, err := c.StartControlMaster(ctx, runtimeDir)
	if err != nil {
		return nil, err
	}
	master.RemoteSocket, master.LocalSocket = remoteBroker, localBroker
	if localBroker == "" || remoteBroker == "" {
		return master, nil
	}
	if err := master.addBrokerForward(ctx, localTCP); err != nil {
		_ = master.Close()
		return nil, err
	}
	return master, nil
}

// StartControlMaster establishes only the private SSH control plane. It is
// intentionally useful without reverse forwarding so ordinary shell/run
// workflows keep working on sshd configurations that disallow forwarding.
func (c Client) StartControlMaster(ctx context.Context, runtimeDir string) (*Master, error) {
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return nil, err
	}
	control := filepath.Join(runtimeDir, "c")
	args := []string{"-q", "-M", "-N", "-S", control,
		"-o", "ControlMaster=yes", "-o", "ControlPersist=no", "-o", "ClearAllForwardings=yes",
		"-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3", "-o", "ForwardAgent=no",
		"-o", "ForwardX11=no", "-o", "ExitOnForwardFailure=yes", "-o", "StreamLocalBindMask=0177",
	}
	args = append(args, c.Destination)
	// The master must outlive cancellation of the foreground command long
	// enough for the session defer to stop containers, flush artifacts, and
	// cancel forwards. It is terminated explicitly by Master.Close.
	cmd := exec.Command(c.SSH, args...)
	cmd.WaitDelay = subprocess.WaitDelay
	cmd.Env = SafeSSHEnvironment()
	masterOutput := boundedOutput{limit: maxSSHProbeOutputBytes}
	cmd.Stdin = nil
	cmd.Stdout = &masterOutput
	cmd.Stderr = &masterOutput
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	masterClient := c
	masterClient.ControlPath = control
	master := &Master{Client: masterClient, ControlPath: control, process: cmd, done: make(chan error, 1)}
	go func() { master.done <- cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, exceeded := masterOutput.snapshot(); exceeded {
			_ = master.Close()
			return nil, fmt.Errorf("SSH control master output exceeded %d-byte limit", maxSSHProbeOutputBytes)
		}
		select {
		case processErr := <-master.done:
			output, exceeded := masterOutput.snapshot()
			if exceeded {
				return nil, fmt.Errorf("SSH control master output exceeded %d-byte limit", maxSSHProbeOutputBytes)
			}
			detail := strings.TrimSpace(string(output))
			if detail != "" {
				return nil, fmt.Errorf("SSH control master exited during startup: %w: %s", processErr, detail)
			}
			return nil, fmt.Errorf("SSH control master exited during startup: %w", processErr)
		default:
		}
		check := c.sshCommand(ctx, "-S", control, "-O", "check", c.Destination)
		if err := check.Run(); err == nil {
			if _, exceeded := masterOutput.snapshot(); exceeded {
				_ = master.Close()
				return nil, fmt.Errorf("SSH control master output exceeded %d-byte limit", maxSSHProbeOutputBytes)
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

// ConfigureBroker adds debugger-broker forwarding to an already connected
// master. Keeping this separate from StartControlMaster lets launch setup and
// agent probes reuse the same SSH connection.
func (m *Master) ConfigureBroker(ctx context.Context, localBroker, remoteBroker, localTCP string) error {
	m.RemoteSocket, m.LocalSocket = remoteBroker, localBroker
	if localBroker == "" || remoteBroker == "" {
		return nil
	}
	return m.addBrokerForward(ctx, localTCP)
}

func (m *Master) addBrokerForward(ctx context.Context, localTCP string) error {
	if _, forwardErr := m.Client.runBounded(ctx, maxSSHProbeOutputBytes, "-S", m.ControlPath, "-O", "forward", "-R", m.RemoteSocket+":"+m.LocalSocket, m.Client.Destination); forwardErr != nil {
		if localTCP == "" {
			return fmt.Errorf("create reverse stream-local forward: %w", forwardErr)
		}
		host, port, splitErr := net.SplitHostPort(localTCP)
		if splitErr != nil {
			return splitErr
		}
		fallbackOut, fallbackErr := m.Client.runBounded(ctx, maxSSHProbeOutputBytes, "-S", m.ControlPath, "-O", "forward", "-R", "127.0.0.1:0:"+host+":"+port, m.Client.Destination)
		if fallbackErr != nil {
			return fmt.Errorf("reverse forwarding unavailable (stream-local: %v; TCP: %w)", forwardErr, fallbackErr)
		}
		allocated := strings.TrimSpace(string(fallbackOut))
		portNumber, parseErr := strconv.Atoi(allocated)
		if parseErr != nil || portNumber < 1 || portNumber > 65535 {
			return fmt.Errorf("SSH did not report allocated reverse port: %q", allocated)
		}
		m.BrokerAddress = "tcp:127.0.0.1:" + allocated
		// A bridge-networked container cannot reach a host loopback listener.
		// When socat is available, restore the private Unix-socket endpoint.
		relayPID := m.RemoteSocket + ".relay.pid"
		relayScript := "umask 077; command -v socat >/dev/null 2>&1 || exit 0; " +
			"rm -f -- " + shellQuote(m.RemoteSocket) + " " + shellQuote(relayPID) + "; " +
			"nohup socat UNIX-LISTEN:" + shellQuote(m.RemoteSocket) + ",fork,mode=600 TCP:127.0.0.1:" + allocated +
			" </dev/null >/dev/null 2>&1 & pid=$!; printf '%s' \"$pid\" > " + shellQuote(relayPID) + "; " +
			"i=0; while [ \"$i\" -lt 100 ]; do test -S " + shellQuote(m.RemoteSocket) + " && { printf relay; exit 0; }; " +
			"kill -0 \"$pid\" 2>/dev/null || exit 1; i=$((i+1)); sleep 0.02; done; exit 1"
		if relayOut, relayErr := m.Client.runBounded(ctx, maxSSHProbeOutputBytes, "-S", m.ControlPath, "-T", m.Client.Destination, relayScript); relayErr == nil && strings.TrimSpace(string(relayOut)) == "relay" {
			m.BrokerAddress = "unix:" + m.RemoteSocket
			m.RelayPIDFile = relayPID
		}
	} else {
		m.BrokerAddress = "unix:" + m.RemoteSocket
	}
	return nil
}

func (m *Master) Command(ctx context.Context, tty bool, operation, encoded string) *exec.Cmd {
	// OpenSSH otherwise prints "Shared connection to … closed." whenever a
	// normal multiplexed PTY exits. The command's exit status still carries
	// real transport and remote-process failures back to Pwnbridge.
	args := []string{"-q", "-S", m.ControlPath}
	if tty {
		args = append(args, "-tt", "-e", "none")
	} else {
		args = append(args, "-T")
	}
	args = append(args, m.Client.Destination, remoteAgentCommand(m.Client.AgentPath, operation, encoded))
	return m.Client.sshCommand(ctx, args...)
}

// MoshCommand starts the managed agent through Mosh while reusing the private
// SSH control master for authentication. SSH remains alive beside Mosh for
// synchronization, cleanup, and debugger-broker forwarding.
func (m *Master) MoshCommand(ctx context.Context, operation, encoded, port string) *exec.Cmd {
	mosh := m.Client.Mosh
	if mosh == "" {
		mosh = "mosh"
	}
	ssh := m.Client.SSH
	if ssh == "" {
		ssh = "ssh"
	}
	sshCommand := shellQuote(ssh) + " -S " + shellQuote(m.ControlPath)
	args := []string{"--predict=always", "--ssh=" + sshCommand}
	if port != "" {
		args = append(args, "--port="+port)
	}
	args = append(args, "--", m.Client.Destination, m.Client.AgentPath, operation)
	if encoded != "" {
		args = append(args, encoded)
	}
	cmd := subprocess.CommandContext(ctx, mosh, args...)
	cmd.Env = SafeMoshEnvironment()
	return cmd
}

func MoshAvailable(client Client, probe HostProbe) bool {
	return LocalMoshAvailable(client) && probe.Tools["mosh-server"]
}

func LocalMoshAvailable(client Client) bool {
	mosh := client.Mosh
	if mosh == "" {
		mosh = "mosh"
	}
	_, err := exec.LookPath(mosh)
	return err == nil
}

func (m *Master) Run(ctx context.Context, operation string, request any) ([]byte, error) {
	encoded, err := agent.EncodeRequest(request)
	if err != nil {
		return nil, err
	}
	cmd := m.Command(ctx, false, operation, encoded)
	output := boundedOutput{limit: maxAgentResponseBytes}
	cmd.Stdout, cmd.Stderr = &output, &output
	err = cmd.Run()
	out, exceeded := output.snapshot()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return out, ctxErr
	}
	if exceeded {
		return out, fmt.Errorf("remote %s output exceeded %d-byte limit", operation, maxAgentResponseBytes)
	}
	if err != nil {
		return out, fmt.Errorf("remote %s: %w: %s", operation, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func (m *Master) Close() error {
	if m == nil {
		return nil
	}
	m.closeOnce.Do(m.close)
	return nil
}

func (m *Master) close() {
	timeout := m.closeTimeout
	if timeout <= 0 {
		timeout = masterCloseTimeout
	}
	cleanupContext, cancelCleanup := context.WithTimeout(context.Background(), timeout)
	defer cancelCleanup()
	if m.ControlPath != "" {
		if m.RelayPIDFile != "" {
			script := "pid=''; test ! -f " + shellQuote(m.RelayPIDFile) + " || pid=$(cat " + shellQuote(m.RelayPIDFile) + "); " +
				"case \"$pid\" in ''|*[!0-9]*) ;; *) kill \"$pid\" 2>/dev/null || true ;; esac; " +
				"rm -f -- " + shellQuote(m.RelayPIDFile) + " " + shellQuote(m.RemoteSocket)
			cmd := subprocess.CommandContext(cleanupContext, m.Client.SSH, "-S", m.ControlPath, "-T", m.Client.Destination, script)
			cmd.Env = SafeSSHEnvironment()
			_ = cmd.Run()
		}
		exit := subprocess.CommandContext(cleanupContext, m.Client.SSH, "-S", m.ControlPath, "-O", "exit", m.Client.Destination)
		exit.Env = SafeSSHEnvironment()
		_ = exit.Run()
	}
	if m.process != nil {
		if m.process.Process != nil {
			_ = m.process.Process.Signal(os.Interrupt)
		}
		if m.done != nil {
			interruptTimer := time.NewTimer(masterInterruptTimeout)
			select {
			case <-m.done:
				if !interruptTimer.Stop() {
					select {
					case <-interruptTimer.C:
					default:
					}
				}
			case <-interruptTimer.C:
				if m.process.Process != nil {
					_ = m.process.Process.Kill()
				}
				killTimer := time.NewTimer(masterPostKillWaitLimit)
				select {
				case <-m.done:
					if !killTimer.Stop() {
						select {
						case <-killTimer.C:
						default:
						}
					}
				case <-killTimer.C:
				}
			}
		}
	}
}

func (c Client) run(ctx context.Context, args ...string) ([]byte, error) {
	return c.runBounded(ctx, maxSSHCommandOutputBytes, args...)
}

func (c Client) runBounded(ctx context.Context, limit int, args ...string) ([]byte, error) {
	cmd := c.sshCommand(ctx, args...)
	output := boundedOutput{limit: limit}
	cmd.Stdout, cmd.Stderr = &output, &output
	err := cmd.Run()
	out, exceeded := output.snapshot()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return out, ctxErr
	}
	if exceeded {
		return out, fmt.Errorf("SSH output exceeded %d-byte limit", limit)
	}
	if err != nil {
		return out, fmt.Errorf("ssh: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

type boundedOutput struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (o *boundedOutput) Write(data []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	remaining := o.limit - o.buffer.Len()
	if len(data) > remaining {
		o.exceeded = true
	}
	if remaining > 0 {
		keep := len(data)
		if keep > remaining {
			keep = remaining
		}
		_, _ = o.buffer.Write(data[:keep])
	}
	return len(data), nil
}

func (o *boundedOutput) snapshot() ([]byte, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return bytes.Clone(o.buffer.Bytes()), o.exceeded
}

func (c Client) sshCommand(ctx context.Context, args ...string) *exec.Cmd {
	if c.ControlPath != "" && !hasControlPath(args) {
		args = append([]string{"-S", c.ControlPath}, args...)
	}
	cmd := subprocess.CommandContext(ctx, c.SSH, args...)
	cmd.Env = SafeSSHEnvironment()
	return cmd
}

func hasControlPath(args []string) bool {
	for index, arg := range args {
		if arg == "-S" || strings.HasPrefix(arg, "-S") && len(arg) > 2 {
			return true
		}
		if arg == "-o" && index+1 < len(args) && strings.HasPrefix(strings.ToLower(args[index+1]), "controlpath=") {
			return true
		}
	}
	return false
}

// SafeSSHEnvironment keeps authentication/configuration environment available
// to the system OpenSSH client while ensuring host multiplexer state and
// session broker capabilities cannot be sent by an unusually broad SendEnv.
// It also gives PTY channels a useful terminal type when launched from a
// non-interactive parent (for example, a custom terminal provider).
func SafeSSHEnvironment() []string {
	result := make([]string, 0, len(os.Environ())+1)
	hasTERM := false
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if key == "TMUX" || strings.HasPrefix(key, "TMUX_") || key == "ZELLIJ" || strings.HasPrefix(key, "ZELLIJ_") {
			continue
		}
		if key == "LANG" || key == "LANGUAGE" || strings.HasPrefix(key, "LC_") {
			continue
		}
		switch key {
		case "PWNBRIDGE_BROKER", "PWNBRIDGE_BROKER_TOKEN", "PWNBRIDGE_SESSION_ID", "PWNBRIDGE_SESSION_DIR", "PWNBRIDGE_RUNTIME", "PWNBRIDGE_TERMINAL_SCOPE", "PWNBRIDGE_TERMINAL_PROVIDER", "PWNBRIDGE_TERMINAL_PLACEMENT":
			continue
		case "TERM":
			hasTERM = true
			if value == "" || value == "dumb" {
				entry = "TERM=xterm-256color"
			}
		}
		result = append(result, entry)
	}
	if !hasTERM {
		result = append(result, "TERM=xterm-256color")
	}
	return result
}

// SafeMoshEnvironment applies the SSH environment boundary and restores only
// a UTF-8 locale, which the Mosh client requires to model terminal state.
func SafeMoshEnvironment() []string {
	result := SafeSSHEnvironment()
	locale := ""
	for _, key := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		value := os.Getenv(key)
		normalized := strings.ToLower(strings.ReplaceAll(value, "-", ""))
		if strings.Contains(normalized, "utf8") {
			locale = value
			break
		}
	}
	if locale == "" {
		locale = "en_US.UTF-8"
	}
	return append(result, "LANG="+locale, "LC_CTYPE="+locale)
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
		if info, err := os.Stat(explicit); err == nil && info.Mode().IsRegular() {
			return explicit, nil
		}
		return "", fmt.Errorf("agent asset %s does not exist", explicit)
	}
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	if runtime.GOOS == "darwin" {
		if asset, ok := findAgentAssetFromExecutable(executable); ok {
			return asset, nil
		}
	}
	return "", errors.New("linux agent asset not found; run `make build` or set PWNBRIDGE_AGENT_PATH")
}

func findAgentAssetFromExecutable(executable string) (string, bool) {
	executables := []string{executable}
	if resolved, err := filepath.EvalSymlinks(executable); err == nil && resolved != executable {
		executables = append(executables, resolved)
	}
	for _, path := range executables {
		candidates := []string{
			filepath.Join(filepath.Dir(path), "pwnbridge-agent-linux-amd64"),
			filepath.Join(filepath.Dir(filepath.Dir(path)), "libexec", "pwnbridge", "pwnbridge-agent-linux-amd64"),
		}
		for _, candidate := range candidates {
			if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
				return filepath.Clean(candidate), true
			}
		}
	}
	return "", false
}

func CopyOutput(dst io.Writer, out []byte) { _, _ = dst.Write(out) }
