package agent

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/fsutil"
	"github.com/simonfalke-01/pwnbridge/internal/identity"
	"github.com/simonfalke-01/pwnbridge/internal/protocol"
	pruntime "github.com/simonfalke-01/pwnbridge/internal/runtime"
	"github.com/simonfalke-01/pwnbridge/internal/version"
)

func Main(args []string) error {
	if filepath.Base(os.Args[0]) == "pwntools-terminal" {
		return terminalWrapper(args)
	}
	if len(args) == 0 {
		return errors.New("agent command is required")
	}
	switch args[0] {
	case "probe":
		return probe()
	case "exec":
		return execCommand(args[1:])
	case "shell":
		return shellCommand(args[1:])
	case "pane":
		return paneCommand(args[1:])
	case "broker-ping":
		return brokerPing(args[1:])
	case "cleanup":
		return cleanup(args[1:])
	default:
		return fmt.Errorf("unknown agent command %q", args[0])
	}
}

func cleanup(args []string) error {
	var request protocol.CleanupRequest
	if err := decodeRequest(args, &request); err != nil {
		return err
	}
	if !validID(request.SessionID) {
		return errors.New("invalid cleanup session")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	allowed := filepath.Join(home, ".cache", "pwnbridge", "sessions")
	dir := expandHome(request.SessionDir)
	if filepath.Dir(filepath.Clean(dir)) != allowed || filepath.Base(filepath.Clean(dir)) != request.SessionID {
		return errors.New("cleanup directory is outside pwnbridge session state")
	}
	if err := pruntime.Stop(context.Background(), request.Runtime); err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

func brokerPing(args []string) error {
	var request protocol.BrokerPing
	if err := decodeRequest(args, &request); err != nil {
		return err
	}
	if !validID(request.SessionID) || request.Address == "" || len(request.Token) < 32 {
		return errors.New("invalid broker ping request")
	}
	conn, err := dialBroker(request.Address)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := protocol.Encode(conn, protocol.Message{Protocol: version.ProtocolVersion, Type: "ping", SessionID: request.SessionID, Token: request.Token}); err != nil {
		return err
	}
	var response protocol.Message
	if err := protocol.Decode(conn, &response); err != nil {
		return err
	}
	if response.Type != "pong" {
		return errors.New("broker did not return pong")
	}
	return nil
}

func probe() error {
	home, _ := os.UserHomeDir()
	tools := make(map[string]bool)
	for _, tool := range []string{
		"bash", "cc", "cmake", "file", "readelf", "gdb", "gdbserver", "gdb-multiarch",
		"patchelf", "checksec", "python3", "tmux", "strace", "ltrace", "socat", "nc",
		"docker", "podman", "zellij",
	} {
		_, err := exec.LookPath(tool)
		tools[tool] = err == nil
	}
	distro, distroVersion := osRelease()
	disk, inodes := filesystemAvailability(home)
	homeWritable := false
	if dir := filepath.Join(home, ".cache", "pwnbridge"); os.MkdirAll(dir, 0o700) == nil {
		if file, err := os.CreateTemp(dir, ".probe-*"); err == nil {
			homeWritable = true
			name := file.Name()
			_ = file.Close()
			_ = os.Remove(name)
		}
	}
	ptraceBytes, _ := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	pwntoolsVersion := ""
	pwnPython := filepath.Join(home, ".local", "share", "pwnbridge", "envs", "pwn-v1", "bin", "python")
	if output, err := exec.Command(pwnPython, "-c", `import importlib.metadata as m; print(m.version("pwntools"))`).Output(); err == nil {
		pwntoolsVersion = strings.TrimSpace(string(output))
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"protocol": version.ProtocolVersion, "version": version.Version,
		"os": runtime.GOOS, "architecture": runtime.GOARCH, "home": home, "tools": tools,
		"distro": distro, "distro_version": distroVersion, "disk_available_kib": disk,
		"inodes_available": inodes, "home_writable": homeWritable,
		"ptrace_scope": strings.TrimSpace(string(ptraceBytes)), "pwntools_version": pwntoolsVersion,
	})
}

func osRelease() (string, string) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", ""
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}
	return values["ID"], values["VERSION_ID"]
}

func filesystemAvailability(home string) (uint64, uint64) {
	return dfAvailable("-Pk", home), dfAvailable("-Pi", home)
}

func dfAvailable(option, path string) uint64 {
	output, err := exec.Command("df", option, path).Output()
	if err != nil {
		return 0
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) < 2 {
		return 0
	}
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 4 {
		return 0
	}
	value, _ := strconv.ParseUint(fields[3], 10, 64)
	return value
}

func execCommand(args []string) error {
	var request protocol.ExecRequest
	if err := decodeRequest(args, &request); err != nil {
		return err
	}
	if request.Cwd == "" || len(request.Args) == 0 {
		return errors.New("exec request requires cwd and args")
	}
	request.Cwd = expandHome(request.Cwd)
	request.Runtime.Workspace = request.Cwd
	if request.Environment == nil {
		request.Environment = map[string]string{}
	}
	sessionDir := request.Runtime.SessionDir
	if sessionDir != "" {
		if err := os.MkdirAll(filepath.Join(sessionDir, "bin"), 0o700); err != nil {
			return err
		}
		if err := installWrapper(filepath.Join(sessionDir, "bin", "pwntools-terminal")); err != nil {
			return err
		}
		if request.Runtime.Kind == "container" {
			request.Environment["PATH"] = "/run/pwnbridge/bin:" + getenvDefault(request.Environment, "PATH", containerDefaultPATH)
		} else {
			pathParts := []string{filepath.Join(sessionDir, "bin")}
			if home, err := os.UserHomeDir(); err == nil {
				pwnBin := filepath.Join(home, ".local", "share", "pwnbridge", "envs", "pwn-v1", "bin")
				if info, statErr := os.Stat(pwnBin); statErr == nil && info.IsDir() {
					pathParts = append(pathParts, pwnBin)
					request.Environment["VIRTUAL_ENV"] = filepath.Dir(pwnBin)
				}
			}
			pathParts = append(pathParts, getenvDefault(request.Environment, "PATH", os.Getenv("PATH")))
			request.Environment["PATH"] = strings.Join(pathParts, ":")
		}
	}
	if _, err := pruntime.Ensure(context.Background(), &request.Runtime, sessionName(request.Runtime)); err != nil {
		return err
	}
	if request.Runtime.SessionDir != "" {
		_ = fsutil.WriteJSON(filepath.Join(request.Runtime.SessionDir, "runtime.json"), request.Runtime)
	}
	if err := writeTerminalConfig(sessionDir, request.Terminal, request.Runtime); err != nil {
		return err
	}
	cmd, err := pruntime.Command(request.Runtime, false, request.Cwd, request.Environment, request.Args)
	if err != nil {
		return err
	}
	return replaceProcess(cmd)
}

func shellCommand(args []string) error {
	var request protocol.ShellRequest
	if err := decodeRequest(args, &request); err != nil {
		return err
	}
	if request.Cwd == "" || request.SessionID == "" || request.Nonce == "" {
		return errors.New("shell request is incomplete")
	}
	if request.Terminal.SessionID != request.SessionID {
		return errors.New("shell terminal session does not match request")
	}
	request.Cwd = expandHome(request.Cwd)
	if request.Shell == "" {
		request.Shell = "bash"
	}
	if request.Shell != "bash" {
		return fmt.Errorf("managed shell %q is unsupported; use bash", request.Shell)
	}
	sessionDir := request.Runtime.SessionDir
	if sessionDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		sessionDir = filepath.Join(home, ".cache", "pwnbridge", "sessions", request.SessionID)
		request.Runtime.SessionDir = sessionDir
	}
	if err := os.MkdirAll(filepath.Join(sessionDir, "bin"), 0o700); err != nil {
		return err
	}
	if err := installWrapper(filepath.Join(sessionDir, "bin", "pwntools-terminal")); err != nil {
		return err
	}
	rcPath := filepath.Join(sessionDir, "bashrc")
	if err := writeBashRC(rcPath, request.Nonce, request.SourceUserRC); err != nil {
		return err
	}
	request.Runtime.Workspace = request.Cwd
	if _, err := pruntime.Ensure(context.Background(), &request.Runtime, request.SessionID); err != nil {
		return err
	}
	_ = fsutil.WriteJSON(filepath.Join(sessionDir, "runtime.json"), request.Runtime)
	env := cloneMap(request.Environment)
	if request.Runtime.Kind == "container" {
		env["PATH"] = "/run/pwnbridge/bin:" + getenvDefault(request.Environment, "PATH", containerDefaultPATH)
		rcPath = "/run/pwnbridge/bashrc"
	} else {
		pathParts := []string{filepath.Join(sessionDir, "bin")}
		if home, err := os.UserHomeDir(); err == nil {
			pwnBin := filepath.Join(home, ".local", "share", "pwnbridge", "envs", "pwn-v1", "bin")
			if info, statErr := os.Stat(pwnBin); statErr == nil && info.IsDir() {
				pathParts = append(pathParts, pwnBin)
				env["VIRTUAL_ENV"] = filepath.Dir(pwnBin)
			}
		}
		pathParts = append(pathParts, getenvDefault(request.Environment, "PATH", os.Getenv("PATH")))
		env["PATH"] = strings.Join(pathParts, ":")
	}
	if err := writeTerminalConfig(sessionDir, request.Terminal, request.Runtime); err != nil {
		return err
	}
	cmd, err := pruntime.Command(request.Runtime, true, request.Cwd, env, []string{"bash", "--noprofile", "--rcfile", rcPath, "-i"})
	if request.Terminal.Scope == "remote" {
		if request.Runtime.Kind == "container" {
			return errors.New("remote multiplexer scope is incompatible with container runtime; use a host terminal provider")
		}
		wrapper := filepath.Join(sessionDir, "managed-shell")
		wrapperRC := rcPath
		content := "#!/bin/sh\nexec bash --noprofile --rcfile " + shellSingleQuote(wrapperRC) + " -i\n"
		if err := fsutil.AtomicWrite(wrapper, []byte(content), 0o700); err != nil {
			return err
		}
		mux := request.Terminal.Provider
		if mux == "" || mux == "auto" {
			if _, err := exec.LookPath("tmux"); err == nil {
				mux = "tmux"
			} else {
				mux = "zellij"
			}
		}
		name := "pwnbridge-" + request.SessionID
		argv := remoteMuxArgs(mux, name, wrapper)
		cmd, err = pruntime.Command(request.Runtime, true, request.Cwd, env, argv)
	}
	if err != nil {
		return err
	}
	return replaceProcess(cmd)
}

func remoteMuxArgs(mux, name, wrapper string) []string {
	if strings.Contains(mux, "tmux") {
		// A tmux server retains the environment with which it was first started.
		// Give every managed session a private server so that an unrelated or
		// stale tmux server cannot discard this session's PATH/VIRTUAL_ENV.
		return []string{"tmux", "-L", name, "new-session", "-s", name, "-n", "shell", wrapper}
	}
	return []string{"zellij", "attach", "--create", name, "options", "--default-shell", wrapper}
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func paneCommand(args []string) error {
	var request protocol.PaneRequest
	if err := decodeRequest(args, &request); err != nil {
		return err
	}
	if !validID(request.SessionID) || !validID(request.RequestID) || request.SessionDir == "" || request.Runtime.SessionDir != request.SessionDir {
		return errors.New("invalid pane request")
	}
	manifestPath := filepath.Join(request.SessionDir, "requests", request.RequestID+".json")
	var manifest protocol.Manifest
	if err := fsutil.ReadJSONLimit(manifestPath, protocol.MaxFrame, &manifest); err != nil {
		return fmt.Errorf("read debugger manifest: %w", err)
	}
	if manifest.Protocol != version.ProtocolVersion || manifest.SessionID != request.SessionID || manifest.RequestID != request.RequestID {
		return errors.New("debugger manifest identity mismatch")
	}
	argv, err := decodeStrings(manifest.ArgvBase64)
	if err != nil {
		return fmt.Errorf("decode debugger argv: %w", err)
	}
	environEntries, err := decodeStrings(manifest.EnvBase64)
	if err != nil {
		return fmt.Errorf("decode debugger environment: %w", err)
	}
	cwdBytes, err := base64.StdEncoding.DecodeString(manifest.CwdBase64)
	if err != nil {
		return err
	}
	environment := filteredEnvironment(environEntries)
	request.Runtime.Workspace = expandHome(request.Runtime.Workspace)
	request.Runtime.SessionDir = expandHome(request.Runtime.SessionDir)
	if _, err := pruntime.Ensure(context.Background(), &request.Runtime, request.SessionID); err != nil {
		return err
	}
	cmd, err := pruntime.Command(request.Runtime, true, expandHome(string(cwdBytes)), environment, argv)
	if err != nil {
		return err
	}
	err = replaceProcess(cmd)
	_ = os.Remove(manifestPath)
	return err
}

func terminalWrapper(args []string) error {
	if len(args) == 0 {
		return errors.New("pwntools-terminal requires a command")
	}
	config, err := loadTerminalConfig()
	if err != nil {
		return err
	}
	if config.Terminal.Scope == "remote" {
		return remoteTerminalWrapper(args, config.Terminal)
	}
	sessionID, sessionDir := config.Terminal.SessionID, config.Terminal.SessionDir
	broker, token := config.Terminal.Broker, config.Terminal.Token
	if !validID(sessionID) || sessionDir == "" || broker == "" || token == "" {
		return errors.New("pwntools-terminal is outside a pwnbridge broker session")
	}
	requestID, err := identity.Random(16)
	if err != nil {
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	manifest := protocol.Manifest{
		Protocol: version.ProtocolVersion, SessionID: sessionID, RequestID: requestID,
		ArgvBase64: encodeStrings(args), EnvBase64: encodeStrings(os.Environ()),
		CwdBase64: base64.StdEncoding.EncodeToString([]byte(cwd)), Runtime: config.Runtime,
	}
	manifestPath := filepath.Join(sessionDir, "requests", requestID+".json")
	if err := fsutil.WriteJSON(manifestPath, manifest); err != nil {
		return err
	}
	defer os.Remove(manifestPath)
	conn, err := dialBroker(broker)
	if err != nil {
		return fmt.Errorf("connect to pwnbridge terminal broker: %w", err)
	}
	defer conn.Close()
	open := protocol.Message{Protocol: version.ProtocolVersion, Type: "open", SessionID: sessionID, RequestID: requestID, Token: token, Payload: protocol.Payload(protocol.OpenPayload{Title: "pwntools GDB"})}
	if err := protocol.Encode(conn, open); err != nil {
		return err
	}

	var writeMu sync.Mutex
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(signals)
	done := make(chan struct{})
	go func() {
		select {
		case <-signals:
			writeMu.Lock()
			_ = protocol.Encode(conn, protocol.Message{Protocol: version.ProtocolVersion, Type: "cancel", SessionID: sessionID, RequestID: requestID, Token: token})
			writeMu.Unlock()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
		case <-done:
		}
	}()
	defer close(done)
	reader := bufio.NewReader(conn)
	for {
		var message protocol.Message
		if err := protocol.Decode(reader, &message); err != nil {
			return err
		}
		if message.Protocol != version.ProtocolVersion || message.SessionID != sessionID || message.RequestID != requestID || message.Token != token {
			return errors.New("broker response identity mismatch")
		}
		switch message.Type {
		case "opened":
			continue
		case "exited":
			payload, _ := protocol.ParsePayload[protocol.ExitPayload](message)
			if payload.Code != 0 {
				return fmt.Errorf("debugger exited with status %d: %s", payload.Code, payload.Error)
			}
			return nil
		case "cancel":
			return errors.New("debugger pane was cancelled")
		case "error":
			payload, _ := protocol.ParsePayload[protocol.ExitPayload](message)
			return errors.New(payload.Error)
		}
	}
}

func remoteTerminalWrapper(args []string, terminal protocol.TerminalSpec) error {
	provider := terminal.Provider
	if provider == "" || provider == "auto" {
		if os.Getenv("TMUX") != "" {
			provider = "tmux"
		} else if os.Getenv("ZELLIJ") != "" {
			provider = "zellij"
		} else {
			return errors.New("remote terminal scope requires a managed remote tmux or Zellij session")
		}
	}
	cwd, _ := os.Getwd()
	var open *exec.Cmd
	switch provider {
	case "tmux", "remote-tmux":
		if os.Getenv("TMUX") == "" {
			return errors.New("remote tmux provider is not active")
		}
		arguments := []string{"split-window", "-P", "-F", "#{pane_id}", "-c", cwd}
		if terminal.Placement != "down" {
			arguments = append(arguments, "-h")
		}
		arguments = append(arguments, args...)
		open = exec.Command("tmux", arguments...)
	case "zellij", "remote-zellij":
		if os.Getenv("ZELLIJ") == "" {
			return errors.New("remote Zellij provider is not active")
		}
		arguments := []string{"action", "new-pane", "--near-current-pane", "--direction", "right", "--name", "pwntools GDB", "--close-on-exit", "--"}
		if terminal.Placement == "down" {
			arguments[4] = "down"
		}
		arguments = append(arguments, args...)
		open = exec.Command("zellij", arguments...)
	default:
		return fmt.Errorf("provider %q cannot be used with remote terminal scope", provider)
	}
	output, err := open.CombinedOutput()
	if err != nil {
		return fmt.Errorf("open remote %s pane: %w: %s", provider, err, strings.TrimSpace(string(output)))
	}
	paneID := strings.TrimSpace(string(output))
	if paneID == "" {
		return errors.New("remote multiplexer returned no pane id")
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(signals)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-signals:
			closeRemotePane(provider, paneID)
			return errors.New("remote debugger pane cancelled")
		case <-ticker.C:
			if !remotePaneExists(provider, paneID) {
				return nil
			}
		}
	}
}

func closeRemotePane(provider, id string) {
	if strings.Contains(provider, "tmux") {
		_ = exec.Command("tmux", "kill-pane", "-t", id).Run()
	} else {
		_ = exec.Command("zellij", "action", "close-pane", "--pane-id", id).Run()
	}
}

func remotePaneExists(provider, id string) bool {
	if strings.Contains(provider, "tmux") {
		return exec.Command("tmux", "display-message", "-p", "-t", id, "#{pane_id}").Run() == nil
	}
	out, err := exec.Command("zellij", "action", "list-panes", "--json").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), `"id":`+strings.TrimPrefix(id, "terminal_")) || strings.Contains(string(out), `"id": `+strings.TrimPrefix(id, "terminal_"))
}

func decodeRequest(args []string, target any) error {
	if len(args) != 1 {
		return errors.New("expected one encoded request")
	}
	data, err := base64.RawURLEncoding.DecodeString(args[0])
	if err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	if len(data) > protocol.MaxFrame {
		return errors.New("request exceeds size limit")
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("request contains trailing JSON value")
	}
	return nil
}

func EncodeRequest(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	if len(data) > protocol.MaxFrame {
		return "", errors.New("request exceeds size limit")
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func replaceProcess(cmd *exec.Cmd) error {
	path := cmd.Path
	if !strings.ContainsRune(path, filepath.Separator) {
		resolved, err := exec.LookPath(path)
		if err != nil {
			return err
		}
		path = resolved
	}
	if cmd.Dir != "" {
		if err := os.Chdir(cmd.Dir); err != nil {
			return err
		}
	}
	return syscall.Exec(path, cmd.Args, cmd.Env)
}

func writeBashRC(path, nonce string, sourceUser bool) error {
	if !validID(nonce) {
		return errors.New("invalid shell marker nonce")
	}
	var source string
	if sourceUser {
		source = "if [ -r \"$HOME/.bashrc\" ]; then . \"$HOME/.bashrc\"; fi\n"
	}
	content := source + `
__pwnbridge_nonce='` + nonce + `'
__pwnbridge_prompt_marker() {
    local __pwnbridge_status=$?
    printf '\033]777;pwnbridge;%s;prompt;%s\007' "$__pwnbridge_nonce" "$__pwnbridge_status"
    return "$__pwnbridge_status"
}
if [ -n "${PROMPT_COMMAND-}" ]; then
    PROMPT_COMMAND="__pwnbridge_prompt_marker;${PROMPT_COMMAND}"
else
    PROMPT_COMMAND="__pwnbridge_prompt_marker"
fi
`
	return fsutil.AtomicWrite(path, []byte(content), 0o600)
}

func installWrapper(target string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	_ = os.Remove(target)
	if err := os.Link(executable, target); err == nil {
		return nil
	}
	src, err := os.Open(executable)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	return dst.Close()
}

const terminalConfigSchema = 1

type terminalConfig struct {
	Schema   int                   `json:"schema"`
	Terminal protocol.TerminalSpec `json:"terminal"`
	Runtime  protocol.RuntimeSpec  `json:"runtime"`
}

func writeTerminalConfig(sessionDir string, terminal protocol.TerminalSpec, runtimeSpec protocol.RuntimeSpec) error {
	if sessionDir == "" {
		return errors.New("terminal session directory is missing")
	}
	if runtimeSpec.SessionDir != sessionDir {
		return errors.New("terminal session directory does not match runtime")
	}
	terminal.SessionDir = sessionDir
	if runtimeSpec.Kind == "container" {
		paths := map[string]string{
			"PWNBRIDGE_SESSION_DIR": sessionDir,
			"PWNBRIDGE_BROKER":      terminal.Broker,
		}
		prepareRuntimeEnvironment(runtimeSpec, paths)
		terminal.SessionDir = paths["PWNBRIDGE_SESSION_DIR"]
		terminal.Broker = paths["PWNBRIDGE_BROKER"]
	}
	config := terminalConfig{Schema: terminalConfigSchema, Terminal: terminal, Runtime: runtimeSpec}
	if err := validateTerminalConfig(config); err != nil {
		return err
	}
	return fsutil.WriteJSON(filepath.Join(sessionDir, "terminal.json"), config)
}

func loadTerminalConfig() (terminalConfig, error) {
	var config terminalConfig
	executable := os.Args[0]
	if !filepath.IsAbs(executable) {
		resolved, err := exec.LookPath(executable)
		if err != nil {
			return config, fmt.Errorf("locate pwntools-terminal: %w", err)
		}
		executable = resolved
	}
	executable, err := filepath.Abs(executable)
	if err != nil {
		return config, err
	}
	path := filepath.Join(filepath.Dir(filepath.Dir(executable)), "terminal.json")
	info, err := os.Lstat(path)
	if err != nil {
		return config, fmt.Errorf("read pwntools terminal session: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return config, errors.New("pwntools terminal session state is not a private regular file")
	}
	if err := fsutil.ReadJSONLimit(path, protocol.MaxFrame, &config); err != nil {
		return config, fmt.Errorf("read pwntools terminal session: %w", err)
	}
	if err := validateTerminalConfig(config); err != nil {
		return config, err
	}
	return config, nil
}

func validateTerminalConfig(config terminalConfig) error {
	terminal := config.Terminal
	if config.Schema != terminalConfigSchema || !validID(terminal.SessionID) || terminal.SessionDir == "" {
		return errors.New("invalid pwntools terminal session state")
	}
	if terminal.Scope != "host" && terminal.Scope != "remote" {
		return errors.New("invalid pwntools terminal scope")
	}
	if terminal.Provider == "" || len(terminal.Provider) > 80 || strings.IndexAny(terminal.Provider, "\x00\r\n") >= 0 {
		return errors.New("invalid pwntools terminal provider")
	}
	switch terminal.Placement {
	case "right", "down", "tab", "floating", "window":
	default:
		return errors.New("invalid pwntools terminal placement")
	}
	if terminal.Broker == "" {
		if terminal.Token != "" {
			return errors.New("pwntools terminal token has no broker")
		}
	} else {
		if len(terminal.Token) < 32 {
			return errors.New("pwntools terminal broker token is invalid")
		}
		if _, _, err := validateBrokerAddress(terminal.Broker); err != nil {
			return err
		}
	}
	if config.Runtime.SessionDir == "" {
		return errors.New("pwntools terminal runtime state is incomplete")
	}
	if config.Runtime.ID != "pwnbridge-"+terminal.SessionID {
		return errors.New("pwntools terminal runtime identity mismatch")
	}
	return nil
}

func dialBroker(address string) (net.Conn, error) {
	network, target, err := validateBrokerAddress(address)
	if err != nil {
		return nil, err
	}
	// The target is either an owned per-session socket or numeric loopback,
	// as enforced by validateBrokerAddress immediately above.
	return net.Dial(network, target) // #nosec G704
}

func validateBrokerAddress(address string) (network, target string, err error) {
	if strings.HasPrefix(address, "unix:") {
		path := filepath.Clean(strings.TrimPrefix(address, "unix:"))
		portable := filepath.ToSlash(path)
		if !filepath.IsAbs(path) || filepath.Base(path) != "broker.sock" ||
			(path != "/run/pwnbridge/broker.sock" && !strings.Contains(portable, "/.cache/pwnbridge/sessions/")) {
			return "", "", errors.New("broker Unix socket is outside a pwnbridge session")
		}
		return "unix", path, nil
	}
	if strings.HasPrefix(address, "tcp:") {
		host, portText, splitErr := net.SplitHostPort(strings.TrimPrefix(address, "tcp:"))
		if splitErr != nil {
			return "", "", fmt.Errorf("invalid broker TCP address: %w", splitErr)
		}
		ip := net.ParseIP(host)
		port, portErr := strconv.Atoi(portText)
		if ip == nil || !ip.IsLoopback() || portErr != nil || port < 1 || port > 65535 {
			return "", "", errors.New("broker TCP address must be numeric loopback with a valid port")
		}
		return "tcp", net.JoinHostPort(host, portText), nil
	}
	return "", "", errors.New("invalid broker address")
}

func filteredEnvironment(entries []string) map[string]string {
	result := map[string]string{}
	for _, entry := range entries {
		index := strings.IndexByte(entry, '=')
		if index <= 0 {
			continue
		}
		key, value := entry[:index], entry[index+1:]
		upper := strings.ToUpper(key)
		if strings.HasPrefix(upper, "SSH_") || strings.HasPrefix(upper, "TMUX") || strings.HasPrefix(upper, "ZELLIJ") || strings.HasPrefix(upper, "PWNBRIDGE_") {
			continue
		}
		switch upper {
		case "TERM", "COLORTERM", "PWD", "OLDPWD", "_":
			continue
		}
		result[key] = value
	}
	return result
}

func encodeStrings(values []string) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = base64.StdEncoding.EncodeToString([]byte(value))
	}
	return result
}

func decodeStrings(values []string) ([]string, error) {
	result := make([]string, len(values))
	for i, value := range values {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, err
		}
		if strings.IndexByte(string(decoded), 0) >= 0 {
			return nil, errors.New("NUL in encoded value")
		}
		result[i] = string(decoded)
	}
	return result, nil
}

func validID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func sessionName(spec protocol.RuntimeSpec) string {
	if spec.ID != "" {
		return spec.ID
	}
	return "exec"
}
func getenvDefault(values map[string]string, key, fallback string) string {
	if value := values[key]; value != "" {
		return value
	}
	return fallback
}

const containerDefaultPATH = "/opt/pwnbridge/pwn/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

func prepareRuntimeEnvironment(spec protocol.RuntimeSpec, environment map[string]string) {
	if spec.Kind != "container" || environment == nil {
		return
	}
	environment["PWNBRIDGE_SESSION_DIR"] = "/run/pwnbridge"
	address := environment["PWNBRIDGE_BROKER"]
	if strings.HasPrefix(address, "unix:") && spec.SessionDir != "" {
		hostPath := strings.TrimPrefix(address, "unix:")
		if relative, err := filepath.Rel(spec.SessionDir, hostPath); err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			environment["PWNBRIDGE_BROKER"] = "unix:" + filepath.ToSlash(filepath.Join("/run/pwnbridge", relative))
		}
	}
}
func cloneMap(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func expandHome(value string) string {
	if value == "~" || strings.HasPrefix(value, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if value == "~" {
				return home
			}
			return filepath.Join(home, strings.TrimPrefix(value, "~/"))
		}
	}
	return value
}

func SortedToolNames(tools map[string]bool) []string {
	result := make([]string, 0, len(tools))
	for k := range tools {
		result = append(result, k)
	}
	sort.Strings(result)
	return result
}
