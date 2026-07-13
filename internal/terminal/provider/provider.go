package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/fsutil"
	"github.com/simonfalke-01/pwnbridge/internal/identity"
	"github.com/simonfalke-01/pwnbridge/internal/version"
)

type Capabilities struct {
	Name       string   `json:"name"`
	Available  bool     `json:"available"`
	Placements []string `json:"placements"`
	CanFocus   bool     `json:"can_focus"`
	CanClose   bool     `json:"can_close"`
	Reason     string   `json:"reason,omitempty"`
}

type Spec struct {
	SessionID       string   `json:"session_id"`
	RequestID       string   `json:"request_id"`
	Cwd             string   `json:"cwd"`
	Title           string   `json:"title"`
	Placement       string   `json:"placement"`
	Size            string   `json:"size"`
	Focus           bool     `json:"focus"`
	CloseOnSuccess  bool     `json:"close_on_success"`
	HoldOnFailure   bool     `json:"hold_on_failure"`
	NearCurrentPane bool     `json:"near_current_pane,omitempty"`
	RequireVisible  bool     `json:"require_visible,omitempty"`
	Command         []string `json:"command"`
}

type Handle struct {
	Provider string `json:"provider"`
	ID       string `json:"id"`
	Aux      string `json:"aux,omitempty"`
}

type State struct{ Exists, Running bool }

type Provider interface {
	Detect(context.Context) (Capabilities, int, error)
	Open(context.Context, Spec) (Handle, error)
	Inspect(context.Context, Handle) (State, error)
	Focus(context.Context, Handle) error
	Close(context.Context, Handle) error
}

type Registry struct{ providers map[string]Provider }

func NewRegistry(runtimeDir string) *Registry {
	r := &Registry{providers: map[string]Provider{}}
	r.providers["zellij"] = Zellij{}
	r.providers["tmux"] = Tmux{}
	r.providers["wezterm"] = WezTerm{}
	r.providers["kitty"] = Kitty{}
	r.providers["iterm2"] = AppWindow{Name: "iterm2", Application: "iTerm", RuntimeDir: runtimeDir}
	r.providers["terminal-app"] = AppWindow{Name: "terminal-app", Application: "Terminal", RuntimeDir: runtimeDir}
	return r
}

func (r *Registry) Names() []string {
	return []string{"zellij", "tmux", "wezterm", "kitty", "iterm2", "terminal-app", "custom:<name>"}
}

func (r *Registry) Select(ctx context.Context, configured string) (Provider, Capabilities, error) {
	if configured != "" && configured != "auto" {
		if strings.HasPrefix(configured, "custom:") {
			name := strings.TrimPrefix(configured, "custom:")
			p := Custom{Name: name}
			caps, _, err := p.Detect(ctx)
			return p, caps, err
		}
		p, ok := r.providers[configured]
		if !ok {
			return nil, Capabilities{}, fmt.Errorf("unknown terminal provider %q", configured)
		}
		caps, _, err := p.Detect(ctx)
		if err != nil {
			return nil, caps, err
		}
		if !caps.Available {
			return nil, caps, fmt.Errorf("terminal provider %s is unavailable: %s", configured, caps.Reason)
		}
		return p, caps, nil
	}
	order := []string{"zellij", "tmux"}
	switch os.Getenv("TERM_PROGRAM") {
	case "WezTerm":
		order = append(order, "wezterm")
	case "iTerm.app":
		order = append(order, "iterm2")
	}
	if os.Getenv("WEZTERM_PANE") != "" && !contains(order, "wezterm") {
		order = append(order, "wezterm")
	}
	if os.Getenv("KITTY_WINDOW_ID") != "" {
		order = append(order, "kitty")
	}
	order = append(order, "terminal-app")
	var reasons []string
	for _, name := range order {
		p := r.providers[name]
		caps, _, err := p.Detect(ctx)
		if err == nil && caps.Available {
			return p, caps, nil
		}
		if err != nil {
			reasons = append(reasons, name+": "+err.Error())
		} else {
			reasons = append(reasons, name+": "+caps.Reason)
		}
	}
	return nil, Capabilities{}, errors.New("no terminal provider is available: " + strings.Join(reasons, "; "))
}

type Zellij struct{}

type zellijTab struct {
	Position int `json:"position"`
	ID       int `json:"tab_id"`
}

type zellijPane struct {
	ID       int  `json:"id"`
	Plugin   bool `json:"is_plugin"`
	Exited   bool `json:"exited"`
	TabID    int  `json:"tab_id"`
	Position int  `json:"tab_position"`
}

func (Zellij) Detect(_ context.Context) (Capabilities, int, error) {
	_, err := exec.LookPath("zellij")
	available := err == nil && os.Getenv("ZELLIJ") != ""
	reason := "not inside a Zellij session"
	if err != nil {
		reason = "zellij executable not found"
	} else if available {
		reason = ""
	}
	return Capabilities{Name: "zellij", Available: available, Placements: []string{"right", "down", "tab", "floating"}, CanFocus: true, CanClose: true, Reason: reason}, boolScore(available, 100), nil
}
func (Zellij) Open(ctx context.Context, spec Spec) (Handle, error) {
	prefix := zellijSessionPrefix()
	args := append([]string{}, prefix...)
	if spec.Placement == "tab" {
		args = append(args, "action", "new-tab", "--cwd", spec.Cwd, "--name", cleanTitle(spec.Title))
		if spec.CloseOnSuccess {
			args = append(args, "--close-on-exit")
		}
		args = append(args, "--")
		args = append(args, spec.Command...)
		handle, err := runOpen(ctx, "zellij", args, "zellij")
		handle.Aux = "tab"
		return handle, err
	}
	args = append(args, "action", "new-pane")
	if spec.Placement == "floating" {
		args = append(args, "--floating")
	} else {
		if spec.NearCurrentPane {
			// Zellij 0.44.3 can return a terminal ID for
			// --near-current-pane while leaving that pane detached from the
			// visible layout. Resolve the caller's stable tab explicitly instead.
			tabID, err := currentZellijTabID(ctx, prefix)
			if err != nil {
				return Handle{}, err
			}
			args = append(args, "--tab-id", strconv.Itoa(tabID))
		}
		args = append(args, "--direction", direction(spec.Placement))
	}
	args = append(args, "--name", cleanTitle(spec.Title))
	if spec.CloseOnSuccess {
		args = append(args, "--close-on-exit")
	}
	args = append(args, "--")
	args = append(args, spec.Command...)
	handle, err := runOpen(ctx, "zellij", args, "zellij")
	if err != nil {
		return Handle{}, err
	}
	if spec.RequireVisible {
		if err := waitForZellijPane(ctx, prefix, handle.ID); err != nil {
			return Handle{}, err
		}
		focusID := handle.ID
		if !spec.Focus {
			if origin := os.Getenv("ZELLIJ_PANE_ID"); origin != "" {
				focusID = "terminal_" + strings.TrimPrefix(origin, "terminal_")
			}
		}
		if focusID != "" {
			focusArgs := append(append([]string{}, prefix...), "action", "focus-pane-id", focusID)
			if output, focusErr := exec.CommandContext(ctx, "zellij", focusArgs...).CombinedOutput(); focusErr != nil {
				return Handle{}, fmt.Errorf("zellij focus pane %s: %w: %s", focusID, focusErr, strings.TrimSpace(string(output)))
			}
		}
	}
	return handle, nil
}

func zellijSessionPrefix() []string {
	if session := os.Getenv("ZELLIJ_SESSION_NAME"); session != "" {
		return []string{"--session", session}
	}
	return nil
}

func currentZellijTabID(ctx context.Context, prefix []string) (int, error) {
	args := append(append([]string{}, prefix...), "action", "current-tab-info", "--json")
	out, err := exec.CommandContext(ctx, "zellij", args...).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("query current Zellij tab: %w: %s", err, strings.TrimSpace(string(out)))
	}
	var tab struct {
		ID int `json:"tab_id"`
	}
	if err := json.Unmarshal(out, &tab); err != nil {
		return 0, fmt.Errorf("decode current Zellij tab: %w", err)
	}
	return tab.ID, nil
}

func waitForZellijPane(ctx context.Context, prefix []string, handleID string) error {
	id, err := strconv.Atoi(strings.TrimPrefix(handleID, "terminal_"))
	if err != nil {
		return fmt.Errorf("invalid Zellij pane id %q", handleID)
	}
	for attempt := 0; attempt < 20; attempt++ {
		args := append(append([]string{}, prefix...), "action", "list-panes", "--json")
		out, listErr := exec.CommandContext(ctx, "zellij", args...).Output()
		if listErr == nil {
			var panes []zellijPane
			if decodeErr := json.Unmarshal(out, &panes); decodeErr != nil {
				return fmt.Errorf("decode Zellij panes: %w", decodeErr)
			}
			for _, pane := range panes {
				if pane.ID == id && !pane.Plugin {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	return fmt.Errorf("Zellij returned pane %s but it never became visible", handleID)
}
func (Zellij) Inspect(ctx context.Context, h Handle) (State, error) {
	if h.Aux == "tab" {
		out, err := exec.CommandContext(ctx, "zellij", "action", "list-tabs", "--json").Output()
		if err != nil {
			return State{}, err
		}
		var tabs []zellijTab
		if err := json.Unmarshal(out, &tabs); err != nil {
			return State{}, fmt.Errorf("decode Zellij tabs: %w", err)
		}
		id, err := strconv.Atoi(strings.TrimPrefix(h.ID, "tab_"))
		if err != nil {
			return State{}, fmt.Errorf("invalid Zellij tab id %q", h.ID)
		}
		for _, tab := range tabs {
			if tab.ID == id {
				return State{Exists: true, Running: true}, nil
			}
		}
		return State{}, nil
	}
	out, err := exec.CommandContext(ctx, "zellij", "action", "list-panes", "--json").Output()
	if err != nil {
		return State{}, err
	}
	var panes []zellijPane
	if err := json.Unmarshal(out, &panes); err != nil {
		return State{}, fmt.Errorf("decode Zellij panes: %w", err)
	}
	id, err := strconv.Atoi(strings.TrimPrefix(h.ID, "terminal_"))
	if err != nil {
		return State{}, fmt.Errorf("invalid Zellij pane id %q", h.ID)
	}
	for _, pane := range panes {
		if pane.ID == id && !pane.Plugin {
			return State{Exists: true, Running: !pane.Exited}, nil
		}
	}
	return State{}, nil
}
func (Zellij) Focus(ctx context.Context, h Handle) error {
	if h.Aux == "tab" {
		out, err := exec.CommandContext(ctx, "zellij", "action", "list-tabs", "--json").Output()
		if err != nil {
			return err
		}
		var tabs []zellijTab
		if err := json.Unmarshal(out, &tabs); err != nil {
			return err
		}
		id, err := strconv.Atoi(strings.TrimPrefix(h.ID, "tab_"))
		if err != nil {
			return err
		}
		for _, tab := range tabs {
			if tab.ID == id {
				return exec.CommandContext(ctx, "zellij", "action", "go-to-tab", strconv.Itoa(tab.Position+1)).Run()
			}
		}
		return fmt.Errorf("Zellij tab %s no longer exists", h.ID)
	}
	return exec.CommandContext(ctx, "zellij", "action", "focus-pane-id", h.ID).Run()
}
func (Zellij) Close(ctx context.Context, h Handle) error {
	if h.Aux == "tab" {
		return ignoreMissing(exec.CommandContext(ctx, "zellij", "action", "close-tab", "--tab-id", strings.TrimPrefix(h.ID, "tab_")).Run())
	}
	return ignoreMissing(exec.CommandContext(ctx, "zellij", "action", "close-pane", "--pane-id", h.ID).Run())
}

type Tmux struct{}

func (Tmux) Detect(_ context.Context) (Capabilities, int, error) {
	_, err := exec.LookPath("tmux")
	available := err == nil && os.Getenv("TMUX") != "" && os.Getenv("TMUX_PANE") != ""
	reason := "not inside a tmux pane"
	if err != nil {
		reason = "tmux executable not found"
	} else if available {
		reason = ""
	}
	return Capabilities{Name: "tmux", Available: available, Placements: []string{"right", "down", "tab"}, CanFocus: true, CanClose: true, Reason: reason}, boolScore(available, 90), nil
}
func (Tmux) Open(ctx context.Context, spec Spec) (Handle, error) {
	var args []string
	if spec.Placement == "tab" {
		args = []string{"new-window", "-P", "-F", "#{pane_id}", "-n", cleanTitle(spec.Title), "-c", spec.Cwd}
	} else {
		args = []string{"split-window", "-t", os.Getenv("TMUX_PANE"), "-P", "-F", "#{pane_id}", "-c", spec.Cwd}
		if spec.Placement == "right" || spec.Placement == "" {
			args = append(args, "-h")
		}
		if spec.Size != "" {
			args = append(args, "-l", spec.Size)
		}
		if !spec.Focus {
			args = append(args, "-d")
		}
	}
	args = append(args, spec.Command...)
	return runOpen(ctx, "tmux", args, "tmux")
}
func (Tmux) Inspect(ctx context.Context, h Handle) (State, error) {
	out, err := exec.CommandContext(ctx, "tmux", "display-message", "-p", "-t", h.ID, "#{pane_dead}").Output()
	return State{Exists: err == nil, Running: err == nil && strings.TrimSpace(string(out)) != "1"}, nil
}
func (Tmux) Focus(ctx context.Context, h Handle) error {
	return exec.CommandContext(ctx, "tmux", "select-pane", "-t", h.ID).Run()
}
func (Tmux) Close(ctx context.Context, h Handle) error {
	return ignoreMissing(exec.CommandContext(ctx, "tmux", "kill-pane", "-t", h.ID).Run())
}

type WezTerm struct{}

func (WezTerm) Detect(_ context.Context) (Capabilities, int, error) {
	_, err := exec.LookPath("wezterm")
	available := err == nil && (os.Getenv("TERM_PROGRAM") == "WezTerm" || os.Getenv("WEZTERM_PANE") != "")
	reason := "not running inside WezTerm"
	if err != nil {
		reason = "wezterm executable not found"
	} else if available {
		reason = ""
	}
	return Capabilities{Name: "wezterm", Available: available, Placements: []string{"right", "down", "tab"}, CanFocus: true, CanClose: true, Reason: reason}, boolScore(available, 80), nil
}
func (WezTerm) Open(ctx context.Context, spec Spec) (Handle, error) {
	var args []string
	if spec.Placement == "tab" {
		args = []string{"cli", "spawn", "--cwd", spec.Cwd, "--"}
	} else {
		args = []string{"cli", "split-pane", "--cwd", spec.Cwd}
		if spec.Placement == "down" {
			args = append(args, "--bottom")
		} else {
			args = append(args, "--right")
		}
		if percent := percentValue(spec.Size); percent != "" {
			args = append(args, "--percent", percent)
		}
		args = append(args, "--")
	}
	args = append(args, spec.Command...)
	return runOpen(ctx, "wezterm", args, "wezterm")
}
func (WezTerm) Inspect(ctx context.Context, h Handle) (State, error) {
	out, err := exec.CommandContext(ctx, "wezterm", "cli", "list", "--format", "json").Output()
	if err != nil {
		return State{}, err
	}
	var panes []struct {
		ID int `json:"pane_id"`
	}
	if err := json.Unmarshal(out, &panes); err != nil {
		return State{}, fmt.Errorf("decode WezTerm panes: %w", err)
	}
	for _, pane := range panes {
		if strconv.Itoa(pane.ID) == h.ID {
			return State{Exists: true, Running: true}, nil
		}
	}
	return State{}, nil
}
func (WezTerm) Focus(ctx context.Context, h Handle) error {
	return exec.CommandContext(ctx, "wezterm", "cli", "activate-pane", "--pane-id", h.ID).Run()
}
func (WezTerm) Close(ctx context.Context, h Handle) error {
	return ignoreMissing(exec.CommandContext(ctx, "wezterm", "cli", "kill-pane", "--pane-id", h.ID).Run())
}

type Kitty struct{}

func (Kitty) Detect(_ context.Context) (Capabilities, int, error) {
	_, err := exec.LookPath("kitty")
	available := err == nil && os.Getenv("KITTY_WINDOW_ID") != ""
	reason := "not running inside kitty or remote control is unavailable"
	if err != nil {
		reason = "kitty executable not found"
	} else if available {
		reason = ""
	}
	return Capabilities{Name: "kitty", Available: available, Placements: []string{"right", "down", "tab"}, CanFocus: true, CanClose: true, Reason: reason}, boolScore(available, 75), nil
}
func (Kitty) Open(ctx context.Context, spec Spec) (Handle, error) {
	typeName := "window"
	if spec.Placement == "tab" {
		typeName = "tab"
	}
	args := []string{"@", "launch", "--type=" + typeName, "--cwd", spec.Cwd, "--title", cleanTitle(spec.Title)}
	if typeName == "window" {
		location := "vsplit"
		if spec.Placement == "down" {
			location = "hsplit"
		}
		args = append(args, "--location", location)
		if percent := percentValue(spec.Size); percent != "" {
			args = append(args, "--bias", percent)
		}
	}
	if !spec.Focus {
		args = append(args, "--keep-focus")
	}
	args = append(args, "--")
	args = append(args, spec.Command...)
	return runOpen(ctx, "kitty", args, "kitty")
}
func (Kitty) Inspect(ctx context.Context, h Handle) (State, error) {
	out, err := exec.CommandContext(ctx, "kitty", "@", "ls").Output()
	if err != nil {
		return State{}, err
	}
	var osWindows []struct {
		Tabs []struct {
			Windows []struct {
				ID int `json:"id"`
			} `json:"windows"`
		} `json:"tabs"`
	}
	if err := json.Unmarshal(out, &osWindows); err != nil {
		return State{}, fmt.Errorf("decode kitty windows: %w", err)
	}
	for _, osWindow := range osWindows {
		for _, tab := range osWindow.Tabs {
			for _, window := range tab.Windows {
				if strconv.Itoa(window.ID) == h.ID {
					return State{Exists: true, Running: true}, nil
				}
			}
		}
	}
	return State{}, nil
}
func (Kitty) Focus(ctx context.Context, h Handle) error {
	return exec.CommandContext(ctx, "kitty", "@", "focus-window", "--match", "id:"+h.ID).Run()
}
func (Kitty) Close(ctx context.Context, h Handle) error {
	return ignoreMissing(exec.CommandContext(ctx, "kitty", "@", "close-window", "--match", "id:"+h.ID).Run())
}

type AppWindow struct{ Name, Application, RuntimeDir string }

func (a AppWindow) Detect(_ context.Context) (Capabilities, int, error) {
	if runtime.GOOS != "darwin" {
		return Capabilities{Name: a.Name, Reason: "macOS terminal application provider"}, 0, nil
	}
	if _, err := exec.LookPath("open"); err != nil {
		return Capabilities{Name: a.Name, Reason: "macOS open executable not found"}, 0, nil
	}
	return Capabilities{Name: a.Name, Available: true, Placements: []string{"window"}, CanClose: false}, 10, nil
}
func (a AppWindow) Open(ctx context.Context, spec Spec) (Handle, error) {
	id, err := identity.Random(8)
	if err != nil {
		return Handle{}, err
	}
	dir := filepath.Join(a.RuntimeDir, "terminal-launchers")
	path := filepath.Join(dir, id+".command")
	content := "#!/bin/sh\nrm -f -- " + shellQuote(path) + "\nexec"
	for _, arg := range spec.Command {
		content += " " + shellQuote(arg)
	}
	content += "\n"
	if err := fsutil.AtomicWrite(path, []byte(content), 0o700); err != nil {
		return Handle{}, err
	}
	if out, err := exec.CommandContext(ctx, "open", "-na", a.Application, path).CombinedOutput(); err != nil {
		_ = os.Remove(path)
		return Handle{}, fmt.Errorf("open %s: %w: %s", a.Application, err, strings.TrimSpace(string(out)))
	}
	return Handle{Provider: a.Name, ID: id, Aux: path}, nil
}
func (a AppWindow) Inspect(_ context.Context, h Handle) (State, error) {
	_, err := os.Stat(h.Aux)
	return State{Exists: err == nil || errors.Is(err, os.ErrNotExist), Running: true}, nil
}
func (a AppWindow) Focus(context.Context, Handle) error { return nil }
func (a AppWindow) Close(_ context.Context, h Handle) error {
	if h.Aux != "" {
		_ = os.Remove(h.Aux)
	}
	return nil
}

type Custom struct{ Name string }

func (c Custom) executable() string { return "pwnbridge-terminal-" + c.Name }
func (c Custom) Detect(_ context.Context) (Capabilities, int, error) {
	_, err := exec.LookPath(c.executable())
	available := err == nil
	reason := "provider executable not found"
	if available {
		reason = ""
	}
	return Capabilities{Name: "custom:" + c.Name, Available: available, Placements: []string{"right", "down", "tab", "floating", "window"}, CanFocus: true, CanClose: true, Reason: reason}, boolScore(available, 50), nil
}
func (c Custom) call(ctx context.Context, operation string, value any, response any) error {
	payload := map[string]any{"version": version.ProviderProtocol, "operation": operation, "value": value}
	data, _ := json.Marshal(payload)
	cmd := exec.CommandContext(ctx, c.executable())
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("custom provider: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if response != nil {
		return json.Unmarshal(out, response)
	}
	return nil
}
func (c Custom) Open(ctx context.Context, spec Spec) (Handle, error) {
	var h Handle
	err := c.call(ctx, "open", spec, &h)
	return h, err
}
func (c Custom) Inspect(ctx context.Context, h Handle) (State, error) {
	var s State
	err := c.call(ctx, "inspect", h, &s)
	return s, err
}
func (c Custom) Focus(ctx context.Context, h Handle) error { return c.call(ctx, "focus", h, nil) }
func (c Custom) Close(ctx context.Context, h Handle) error { return c.call(ctx, "close", h, nil) }

func runOpen(ctx context.Context, executable string, args []string, provider string) (Handle, error) {
	out, err := exec.CommandContext(ctx, executable, args...).CombinedOutput()
	if err != nil {
		return Handle{}, fmt.Errorf("%s open: %w: %s", provider, err, strings.TrimSpace(string(out)))
	}
	id := strings.Fields(string(out))
	value := "unknown"
	if len(id) > 0 {
		value = id[0]
	}
	return Handle{Provider: provider, ID: value}, nil
}

func cleanTitle(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, value)
	if len(value) > 80 {
		value = value[:80]
	}
	if value == "" {
		return "pwnbridge GDB"
	}
	return value
}
func direction(value string) string {
	if value == "down" {
		return "down"
	}
	return "right"
}
func percentValue(value string) string {
	value = strings.TrimSuffix(value, "%")
	if n, err := strconv.Atoi(value); err == nil && n > 0 && n < 100 {
		return strconv.Itoa(n)
	}
	return ""
}
func boolScore(value bool, score int) int {
	if value {
		return score
	}
	return 0
}
func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func ignoreMissing(err error) error {
	if err == nil {
		return nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return nil
	}
	return err
}
func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

func WaitUntilGone(ctx context.Context, p Provider, h Handle) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		state, err := p.Inspect(ctx, h)
		if err != nil || !state.Exists {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
