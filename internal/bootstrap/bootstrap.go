package bootstrap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/protocol"
	"github.com/simonfalke-01/pwnbridge/internal/transport"
)

// Packages remains the exact apt package set installed by the historical pwn
// preset. The typed catalog is authoritative; this compatibility view keeps
// downstream integrations source-compatible.
var Packages = []string{
	"build-essential", "cmake", "file", "binutils", "gdb", "gdbserver", "gdb-multiarch", "patchelf", "checksec",
	"python3", "python3-dev", "python3-venv", "python3-pip", "libssl-dev", "libffi-dev", "tmux", "python3-pwntools",
	"strace", "ltrace", "socat", "netcat-openbsd", "libc6-dbg", "git", "curl", "ca-certificates", "xz-utils", "mosh",
}

const (
	PwntoolsVersion = "4.15.0"
	PwndbgVersion   = "2026.02.18"
	PwndbgURL       = "https://github.com/pwndbg/pwndbg/releases/download/" + PwndbgVersion + "/pwndbg_" + PwndbgVersion + "_x86_64-portable.tar.xz"
	PwndbgSHA256    = "eeb93972d7910bf8233abf296b00577efb7137d94655502985566a328e5cecce"
)

type Options struct {
	DryRun, NoSudo, WithPwndbg bool
	Yes                        bool
	AcceptDockerRootRisk       bool
	Verbose                    bool
	JSON                       bool
	Accessible                 bool
	Recipe                     Recipe
	Inventory                  *Inventory
	Explanations               []string
	Input                      io.Reader
	Output                     io.Writer
	ErrorOutput                io.Writer
	LogPath                    string
}

type Result struct {
	OK         bool          `json:"ok"`
	DryRun     bool          `json:"dry_run"`
	Plan       ResolvedPlan  `json:"plan"`
	Postflight *Inventory    `json:"postflight,omitempty"`
	Completed  []string      `json:"completed,omitempty"`
	Pending    []string      `json:"pending,omitempty"`
	Elapsed    time.Duration `json:"elapsed_ns"`
	LogPath    string        `json:"log_path,omitempty"`
	Error      string        `json:"error,omitempty"`
}

// Plan is a compatibility rendering of the built-in apt pwn plan. New code
// should use BuildPlan and inspect typed actions and argv steps.
func Plan(options Options) []string {
	value, _ := BuiltinRecipe("pwn")
	if options.WithPwndbg {
		value.Components = append(value.Components, ComponentPwndbg)
	}
	value, explanations, _ := ResolveRecipe(value, nil, nil, nil, nil)
	tools := map[string]bool{}
	resolved, _ := BuildPlan(Inventory{OS: "linux", Architecture: "amd64", PackageManager: ManagerAPT, HomeWritable: true, SudoAvailable: true, Tools: tools}, value, explanations, PlanOptions{NoSudo: options.NoSudo, AcceptDockerRootRisk: options.AcceptDockerRootRisk})
	result := make([]string, 0, len(resolved.Steps))
	for _, step := range resolved.Steps {
		result = append(result, renderCommand(step, false))
	}
	return result
}

// Run preserves the old entry point while using the inventory-driven planner.
func Run(ctx context.Context, client transport.Client, options Options) error {
	_, err := RunResult(ctx, client, options)
	return err
}

func RunResult(ctx context.Context, client transport.Client, options Options) (Result, error) {
	started := time.Now()
	if options.Input == nil {
		options.Input = os.Stdin
	}
	if options.Output == nil {
		options.Output = os.Stdout
	}
	if options.ErrorOutput == nil {
		options.ErrorOutput = os.Stderr
	}
	value := options.Recipe
	if value.Name == "" {
		value, _ = BuiltinRecipe("pwn")
		if options.WithPwndbg {
			value.Components = append(value.Components, ComponentPwndbg)
		}
		var err error
		value, options.Explanations, err = ResolveRecipe(value, nil, nil, nil, nil)
		if err != nil {
			return Result{}, err
		}
	}
	var inventory Inventory
	var err error
	if options.Inventory != nil {
		inventory = *options.Inventory
	} else {
		inventory, err = Inspect(ctx, client)
	}
	if err != nil {
		return Result{}, err
	}
	resolved, err := BuildPlan(inventory, value, options.Explanations, PlanOptions{NoSudo: options.NoSudo, AcceptDockerRootRisk: options.AcceptDockerRootRisk})
	if err != nil {
		return Result{}, err
	}
	result := Result{DryRun: options.DryRun, Plan: resolved, Elapsed: time.Since(started), LogPath: options.LogPath}
	if !options.JSON {
		PrintPlan(options.Output, resolved)
	}
	if options.DryRun {
		result.OK = len(resolved.Blockers) == 0
		return result, nil
	}
	if err := resolved.ValidateExecutable(); err != nil {
		result.Error = err.Error()
		return result, err
	}
	if len(resolved.Steps) == 0 {
		result.OK = true
		result.Elapsed = time.Since(started)
		return result, nil
	}
	if !options.Yes {
		err := errors.New("bootstrap is ready to apply; rerun with --yes or use an interactive terminal")
		result.Error = err.Error()
		return result, err
	}

	progressTarget := options.Output
	if options.JSON {
		progressTarget = options.ErrorOutput
	}
	tracker := newProgress(resolved.Steps, progressTarget, options.Verbose || options.JSON)
	var log io.WriteCloser = nopWriteCloser{io.Discard}
	if options.LogPath != "" {
		if err := os.MkdirAll(filepath.Dir(options.LogPath), 0o700); err != nil {
			return result, fmt.Errorf("create bootstrap log directory: %w", err)
		}
		file, openErr := os.OpenFile(options.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if openErr != nil {
			return result, fmt.Errorf("open bootstrap log: %w", openErr)
		}
		if chmodErr := file.Chmod(0o600); chmodErr != nil {
			_ = file.Close()
			return result, fmt.Errorf("secure bootstrap log: %w", chmodErr)
		}
		log = file
		_, _ = fmt.Fprintf(log, "\n=== bootstrap attempt %s recipe=%s ===\n", time.Now().UTC().Format(time.RFC3339), resolved.Recipe.Name)
	}
	defer log.Close()
	displays := []io.Writer{log, tracker}
	if options.Verbose && !options.JSON {
		displays = append(displays, &sanitizeWriter{target: options.Output})
	}
	stream := io.MultiWriter(displays...)
	command := "sh -c " + shellQuote(RenderScript(resolved, inventory.Root))
	if client.AgentPath != "" {
		request := protocol.BootstrapRequest{Recipe: resolved.Recipe.Name, AuthenticateSudo: !inventory.Root && hasSudoSteps(resolved.Steps)}
		for _, step := range resolved.Steps {
			request.Steps = append(request.Steps, protocol.BootstrapStep{ID: step.ID, Component: step.Component, Description: step.Description, Args: step.Argv, Environment: step.Environment, Sudo: step.Sudo && !inventory.Root})
		}
		data, marshalErr := json.Marshal(request)
		if marshalErr != nil {
			return result, marshalErr
		}
		if len(data) > protocol.MaxFrame {
			return result, fmt.Errorf("structured bootstrap request exceeds %d bytes", protocol.MaxFrame)
		}
		encoded := base64.RawURLEncoding.EncodeToString(data)
		command = shellQuote(client.AgentPath) + " bootstrap " + shellQuote(encoded)
	}
	err = client.RunPTY(ctx, options.Input, stream, stream, command)
	result.Completed, result.Pending = tracker.snapshot()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			err = fmt.Errorf("bootstrap interrupted: completed [%s]; pending [%s]; log %s: %w", strings.Join(result.Completed, ", "), strings.Join(result.Pending, ", "), result.LogPath, err)
		} else {
			err = fmt.Errorf("bootstrap failed after completed [%s]; pending [%s]; rerun the same recipe to resume; log %s: %w", strings.Join(result.Completed, ", "), strings.Join(result.Pending, ", "), result.LogPath, err)
		}
		result.Error, result.Elapsed = err.Error(), time.Since(started)
		return result, err
	}
	postflight, err := Inspect(ctx, client)
	if err != nil {
		err = fmt.Errorf("postflight inventory: %w", err)
		result.Error, result.Elapsed = err.Error(), time.Since(started)
		return result, err
	}
	result.Postflight = &postflight
	verification, _ := BuildPlan(postflight, value, nil, PlanOptions{NoSudo: options.NoSudo, AcceptDockerRootRisk: true})
	var unhealthy []string
	for _, action := range verification.Actions {
		if action.State != ActionSkip && action.State != ActionUnsupported {
			unhealthy = append(unhealthy, action.Component)
		}
	}
	if len(unhealthy) > 0 {
		err = fmt.Errorf("postflight verification failed for: %s", strings.Join(unhealthy, ", "))
		result.Error, result.Elapsed = err.Error(), time.Since(started)
		return result, err
	}
	result.OK, result.Elapsed = true, time.Since(started)
	return result, nil
}

func PrintPlan(out io.Writer, plan ResolvedPlan) {
	fmt.Fprintf(out, "Host: %s  Distro: %s %s  Package manager: %s  Arch: %s  libc: %s\n", plan.Inventory.Host, plan.Inventory.Distro, plan.Inventory.DistroVersion, plan.Inventory.PackageManager, plan.Inventory.Architecture, plan.Inventory.Libc)
	fmt.Fprintf(out, "Disk: %d KiB  Inodes: %d  Privilege: root=%t sudo=%t  Recipe: %s\n", plan.Inventory.DiskAvailableKiB, plan.Inventory.InodesAvailable, plan.Inventory.Root, plan.Inventory.SudoAvailable, plan.Recipe.Name)
	for _, action := range plan.Actions {
		fmt.Fprintf(out, "  %-11s %-14s %s", action.State, action.Component, action.Detail)
		if len(action.Packages) > 0 {
			fmt.Fprintf(out, " (%s)", strings.Join(action.Packages, ", "))
		}
		fmt.Fprintln(out)
	}
	for _, warning := range plan.Warnings {
		fmt.Fprintln(out, "  warning:     "+warning)
	}
	for _, blocker := range plan.Blockers {
		fmt.Fprintln(out, "  unsupported: "+blocker)
	}
	if len(plan.Steps) > 0 {
		fmt.Fprintln(out, "Exact steps:")
		for _, step := range plan.Steps {
			fmt.Fprintln(out, "  "+renderCommand(step, plan.Inventory.Root))
		}
	}
}

func RenderScript(plan ResolvedPlan, root bool) string {
	var script strings.Builder
	script.WriteString("set -u\numask 077\n")
	if !root && hasSudoSteps(plan.Steps) {
		script.WriteString("printf '__PWNBRIDGE_EVENT__auth\\tsudo\\tAuthenticate sudo in this terminal\\n'\n")
		script.WriteString("sudo -v || exit $?\n")
	}
	for _, step := range plan.Steps {
		description := strings.NewReplacer("\t", " ", "\n", " ", "\r", " ").Replace(step.Description)
		fmt.Fprintf(&script, "printf '__PWNBRIDGE_EVENT__start\\t%s\\t%s\\n'\n", step.ID, description)
		command := renderCommand(step, root)
		fmt.Fprintf(&script, "if %s; then printf '__PWNBRIDGE_EVENT__done\\t%s\\t%s\\n'; else rc=$?; printf '__PWNBRIDGE_EVENT__failed\\t%s\\t%s\\n'; exit \"$rc\"; fi\n", command, step.ID, description, step.ID, description)
	}
	return script.String()
}

func renderCommand(step Step, root bool) string {
	if len(step.Argv) > 0 && step.Argv[0] == "pwnbridge-internal-pwndbg-install" {
		return renderPwndbgInstall()
	}
	if step.ID == "pwntools-venv" {
		return `envroot="$HOME/.local/share/pwnbridge/envs/pwn-v1"; if test ! -x "$envroot/bin/python" || test ! -x "$envroot/bin/pip"; then rm -rf "$envroot"; python3 -m venv --system-site-packages "$envroot"; fi`
	}
	var words []string
	if step.Sudo && !root {
		words = append(words, "sudo", "-n")
	}
	if len(step.Environment) > 0 {
		words = append(words, "env")
		keys := make([]string, 0, len(step.Environment))
		for key := range step.Environment {
			keys = append(keys, key)
		}
		sortStrings(keys)
		for _, key := range keys {
			words = append(words, shellQuote(key+"="+step.Environment[key]))
		}
	}
	for _, arg := range step.Argv {
		words = append(words, renderArgument(arg))
	}
	return strings.Join(words, " ")
}

func renderArgument(value string) string {
	if strings.HasPrefix(value, "$HOME/") {
		return `"$HOME/` + strings.ReplaceAll(strings.TrimPrefix(value, "$HOME/"), `"`, ``) + `"`
	}
	if value == "$USER" {
		return `"$USER"`
	}
	return shellQuote(value)
}

func renderPwndbgInstall() string {
	return `root="$HOME/.local/share/pwnbridge/pwndbg"; dest="$root/` + PwndbgVersion + `"; ` +
		`if test -e "$dest" && test ! -x "$dest/bin/pwndbg"; then rm -rf "$dest"; fi; ` +
		`if test ! -x "$dest/bin/pwndbg"; then mkdir -p "$root"; tmp=$(mktemp -d "$root/.install-` + PwndbgVersion + `.XXXXXX") || exit; ` +
		`archive="$tmp/pwndbg.tar.xz"; curl --proto '=https' --tlsv1.2 -fL --retry 3 -o "$archive" '` + PwndbgURL + `' && ` +
		`printf '%s  %s\n' '` + PwndbgSHA256 + `' "$archive" | sha256sum -c - && tar -xJf "$archive" -C "$tmp" && ` +
		`test -x "$tmp/pwndbg/bin/pwndbg" && test ! -e "$dest" && mv "$tmp/pwndbg" "$dest"; rc=$?; rm -rf "$tmp"; test "$rc" = 0 || exit "$rc"; fi; ` +
		`ln -sfn '` + PwndbgVersion + `' "$root/current"; envbin="$HOME/.local/share/pwnbridge/envs/pwn-v1/bin"; tmp="$envbin/.pwndbg.$$"; ` +
		`printf '%s\n' '#!/bin/sh' 'exec "$HOME/.local/share/pwnbridge/pwndbg/current/bin/pwndbg" -nx "$@"' > "$tmp" && chmod 0755 "$tmp" && mv -f "$tmp" "$envbin/pwndbg"`
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

type progressWriter struct {
	mu        sync.Mutex
	target    io.Writer
	pending   []string
	completed []string
	buffer    bytes.Buffer
	quiet     bool
	auth      bool
}

func newProgress(steps []Step, target io.Writer, quiet bool) *progressWriter {
	ids := make([]string, len(steps))
	for i, step := range steps {
		ids[i] = step.ID
	}
	return &progressWriter{target: target, pending: ids, quiet: quiet}
}
func (p *progressWriter) Write(data []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, _ = p.buffer.Write(data)
	for {
		line, err := p.buffer.ReadString('\n')
		if err != nil {
			if p.auth && line != "" {
				_, _ = fmt.Fprint(p.target, sanitize(line))
			} else {
				p.buffer.WriteString(line)
			}
			break
		}
		clean := sanitize(line)
		if strings.HasPrefix(strings.TrimSpace(clean), "{") {
			var event protocol.BootstrapEvent
			if json.Unmarshal([]byte(strings.TrimSpace(clean)), &event) == nil {
				fields := []string{event.Type, event.StepID, event.Description}
				p.handleEvent(fields)
				continue
			}
		}
		if p.auth && !strings.HasPrefix(clean, "__PWNBRIDGE_EVENT__") {
			_, _ = fmt.Fprintln(p.target, clean)
			continue
		}
		if !strings.HasPrefix(clean, "__PWNBRIDGE_EVENT__") {
			continue
		}
		fields := strings.Split(strings.TrimSpace(strings.TrimPrefix(clean, "__PWNBRIDGE_EVENT__")), "\t")
		if len(fields) < 3 {
			continue
		}
		p.handleEvent(fields)
	}
	return len(data), nil
}
func (p *progressWriter) handleEvent(fields []string) {
	if len(fields) < 3 {
		return
	}
	description := sanitize(fields[2])
	switch fields[0] {
	case "auth":
		p.auth = true
		if !p.quiet {
			fmt.Fprintln(p.target, "  [auth] "+description)
		}
	case "start":
		p.auth = false
		if !p.quiet {
			fmt.Fprintln(p.target, "  [ ] "+description)
		}
	case "done":
		p.completed = append(p.completed, fields[1])
		p.removePending(fields[1])
		if !p.quiet {
			fmt.Fprintln(p.target, "  [✓] "+description)
		}
	case "failed":
		if !p.quiet {
			fmt.Fprintln(p.target, "  [!] "+description)
		}
	}
}
func (p *progressWriter) removePending(id string) {
	for i, value := range p.pending {
		if value == id {
			p.pending = append(p.pending[:i], p.pending[i+1:]...)
			return
		}
	}
}
func (p *progressWriter) snapshot() ([]string, []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.completed...), append([]string(nil), p.pending...)
}

type sanitizeWriter struct {
	target  io.Writer
	mu      sync.Mutex
	pending bytes.Buffer
}

func (w *sanitizeWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, _ = w.pending.Write(data)
	scanner := bufio.NewScanner(&w.pending)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(data) > 0 && data[len(data)-1] != '\n' && len(lines) > 0 {
		tail := lines[len(lines)-1]
		lines = lines[:len(lines)-1]
		w.pending.Reset()
		w.pending.WriteString(tail)
	}
	for _, line := range lines {
		display := sanitize(line)
		var event protocol.BootstrapEvent
		if json.Unmarshal([]byte(strings.TrimSpace(display)), &event) == nil {
			if event.Type != "output" {
				continue
			}
			display = sanitize(event.Output)
		}
		if _, err := fmt.Fprintln(w.target, display); err != nil {
			return 0, err
		}
	}
	return len(data), nil
}

// sanitize removes C0 controls (except tabs/newlines) and CSI/OSC terminal
// controls so hostile package output cannot rewrite the compact UI.
func sanitize(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); {
		if value[i] == 0x1b {
			i++
			if i < len(value) && value[i] == '[' {
				i++
				for i < len(value) {
					c := value[i]
					i++
					if c >= 0x40 && c <= 0x7e {
						break
					}
				}
				continue
			}
			if i < len(value) && value[i] == ']' {
				i++
				for i < len(value) {
					if value[i] == 0x07 {
						i++
						break
					}
					if value[i] == 0x1b && i+1 < len(value) && value[i+1] == '\\' {
						i += 2
						break
					}
					i++
				}
				continue
			}
			continue
		}
		c := value[i]
		i++
		if c == '\n' || c == '\t' || c >= 0x20 && c != 0x7f {
			out.WriteByte(c)
		}
	}
	return out.String()
}

func PrintSanitizedLog(out io.Writer, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 16<<20)
	for scanner.Scan() {
		if _, err := fmt.Fprintln(out, sanitize(scanner.Text())); err != nil {
			return err
		}
	}
	return scanner.Err()
}
