package bootstrap

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/pwnbridge/pwnbridge/internal/transport"
)

var Packages = []string{
	"build-essential", "cmake", "file", "binutils", "gdb", "gdbserver", "gdb-multiarch", "patchelf", "checksec",
	"python3", "python3-dev", "python3-venv", "python3-pip", "libssl-dev", "libffi-dev", "tmux",
	"python3-pwntools",
	"strace", "ltrace", "socat", "netcat-openbsd", "libc6-dbg", "git", "curl", "ca-certificates", "xz-utils",
}

const (
	PwndbgVersion = "2026.02.18"
	PwndbgURL     = "https://github.com/pwndbg/pwndbg/releases/download/" + PwndbgVersion + "/pwndbg_" + PwndbgVersion + "_x86_64-portable.tar.xz"
	PwndbgSHA256  = "eeb93972d7910bf8233abf296b00577efb7137d94655502985566a328e5cecce"
)

type Options struct{ DryRun, NoSudo, WithPwndbg bool }

func Plan(options Options) []string {
	commands := []string{
		"sudo apt-get update",
		"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y " + strings.Join(Packages, " "),
		`python3 -m venv --system-site-packages "$HOME/.local/share/pwnbridge/envs/pwn-v1"`,
		`"$HOME/.local/share/pwnbridge/envs/pwn-v1/bin/pip" install --upgrade pip wheel`,
		`"$HOME/.local/share/pwnbridge/envs/pwn-v1/bin/python" -c 'import importlib.metadata as m; assert m.version("pwntools") == "4.15.0"' || "$HOME/.local/share/pwnbridge/envs/pwn-v1/bin/pip" install "pwntools==4.15.0"`,
	}
	if options.NoSudo {
		commands = commands[2:]
	}
	if options.WithPwndbg {
		commands = append(commands,
			`set -eu; root="$HOME/.local/share/pwnbridge/pwndbg"; dest="$root/`+PwndbgVersion+`"; if test ! -x "$dest/bin/pwndbg"; then mkdir -p "$root"; tmp=$(mktemp -d "$root/.install-`+PwndbgVersion+`.XXXXXX"); trap 'rm -rf "$tmp"' EXIT HUP INT TERM; archive="$tmp/pwndbg.tar.xz"; curl --proto '=https' --tlsv1.2 -fL --retry 3 -o "$archive" '`+PwndbgURL+`'; printf '%s  %s\n' '`+PwndbgSHA256+`' "$archive" | sha256sum -c -; tar -xJf "$archive" -C "$tmp"; test -x "$tmp/pwndbg/bin/pwndbg"; test ! -e "$dest"; mv "$tmp/pwndbg" "$dest"; fi; ln -sfn '`+PwndbgVersion+`' "$root/current"`,
			`set -eu; root="$HOME/.local/share/pwnbridge/pwndbg"; envbin="$HOME/.local/share/pwnbridge/envs/pwn-v1/bin"; pwndbg="$root/current/bin/pwndbg"; test -x "$pwndbg"; if test -L "$envbin/gdb"; then case "$(readlink "$envbin/gdb")" in "$root"/*) rm -f "$envbin/gdb" ;; esac; fi; tmp="$envbin/.pwndbg.$$"; trap 'rm -f "$tmp"' EXIT HUP INT TERM; printf '%s\n' '#!/bin/sh' 'exec "$HOME/.local/share/pwnbridge/pwndbg/current/bin/pwndbg" -nx "$@"' > "$tmp"; chmod 0755 "$tmp"; mv -f "$tmp" "$envbin/pwndbg"`,
		)
	}
	return commands
}

func Run(ctx context.Context, client transport.Client, options Options) error {
	probe, err := client.BasicProbe(ctx)
	if err != nil {
		return err
	}
	if probe.OS != "linux" || probe.Architecture != "amd64" {
		return fmt.Errorf("bootstrap supports linux/amd64, got %s/%s", probe.OS, probe.Architecture)
	}
	preflight := `set -eu
. /etc/os-release
case "$ID" in ubuntu|debian) ;; *) printf 'unsupported-distribution:%s\n' "$ID"; exit 20 ;; esac
test -w "$HOME" || { printf 'home-not-writable:%s\n' "$HOME"; exit 21; }
available=$(df -Pk "$HOME" | awk 'NR==2 {print $4}')
inodes=$(df -Pi "$HOME" | awk 'NR==2 {print $4}')
test "${available:-0}" -ge 1048576 || { printf 'insufficient-disk-kib:%s\n' "${available:-0}"; exit 22; }
test "${inodes:-0}" -ge 1000 || { printf 'insufficient-inodes:%s\n' "${inodes:-0}"; exit 23; }
printf 'preflight-ok:%s:%s:%s\n' "$ID" "$available" "$inodes"`
	preflightCommand := exec.CommandContext(ctx, client.SSH, "-T", client.Destination, preflight)
	if output, preflightErr := preflightCommand.CombinedOutput(); preflightErr != nil {
		return fmt.Errorf("remote bootstrap preflight failed: %w: %s", preflightErr, strings.TrimSpace(string(output)))
	}
	if options.NoSudo {
		tools := []string{"bash", "cc", "cmake", "file", "readelf", "gdb", "gdbserver", "gdb-multiarch", "patchelf", "checksec", "python3", "tmux", "strace", "ltrace", "socat", "nc"}
		if options.WithPwndbg {
			tools = append(tools, "curl", "sha256sum", "tar", "xz")
		}
		check := "missing=''; for tool in " + strings.Join(tools, " ") + "; do command -v \"$tool\" >/dev/null 2>&1 || missing=\"$missing $tool\"; done; printf '%s' \"${missing# }\""
		command := exec.CommandContext(ctx, client.SSH, "-T", client.Destination, check)
		output, checkErr := command.CombinedOutput()
		if checkErr != nil {
			return fmt.Errorf("check existing remote tools: %w: %s", checkErr, strings.TrimSpace(string(output)))
		}
		if missing := strings.TrimSpace(string(output)); missing != "" {
			return fmt.Errorf("--no-sudo cannot complete because these remote tools are missing: %s", missing)
		}
	}
	commands := Plan(options)
	fmt.Fprintln(os.Stdout, "pwnbridge bootstrap plan:")
	for _, command := range commands {
		fmt.Fprintln(os.Stdout, "  "+command)
	}
	if options.DryRun {
		return nil
	}
	for _, command := range commands {
		cmd := exec.CommandContext(ctx, client.SSH, "-tt", client.Destination, command)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("bootstrap command failed: %s: %w", command, err)
		}
	}
	return nil
}
