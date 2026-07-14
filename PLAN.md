# pwnbridge — Comprehensive Project Plan

**Status:** Implemented and acceptance-tested, including interactive cross-distro bootstrap
**Last updated:** 2026-07-14
**Canonical project name:** `pwnbridge`

## 1. Vision

Pwn challenges are normally Linux x86-64 binaries, while the primary workstation is an Apple Silicon Mac. The existing workflow repeatedly copies files, opens SSH sessions, manages divergent paths, and fights terminal-multiplexer behavior whenever pwntools launches GDB.

`pwnbridge` creates a remote execution bubble. Files, the editor, Git tools, and static analysis remain local. Commands that need Linux x86-64 appear to run in the local project but execute natively on a configured Ubuntu host. Saving `solve.py` and immediately pressing Enter must never execute an older remote copy. Remote artifacts such as cores, logs, and patched binaries must be local before the next managed prompt appears.

An unchanged pwntools exploit using `process()`, `gdb.debug()`, or `gdb.attach()` runs inside the remote environment. GDB opens in a pane or terminal on the Mac, but GDB and the inferior remain in the same remote x86-64 runtime.

The intended daily experience is:

```console
$ cd challenge
$ pwnbridge
[pwnbridge:x86] ~/challenge $ ./chall
[pwnbridge:x86] ~/challenge $ python solve.py
```

## 2. Product philosophy

- One command for normal use; complexity appears only in diagnostics.
- The Mac is the human-facing workspace, but neither synchronized endpoint silently wins a conflict.
- Synchronization correctness comes from execution barriers, not optimistic timing.
- Never trade convenience for silent data loss.
- Use mature system primitives—OpenSSH, Mosh, and Mutagen—behind narrow internal interfaces.
- No publicly listening custom daemon.
- No mandatory remote tmux, local Zellij, container, editor integration, or modified exploit template.
- Zellij is first-class, because it is the primary host multiplexer, but terminal integration remains open and provider-based.
- Existing SSH aliases, keys, ProxyJump, Keychain, hardware keys, and host verification remain authoritative.
- Never modify `.ssh/config`, `.bashrc`, `.zshrc`, or user GDB configuration.
- A remote process may request a debugger pane but may never provide arbitrary commands to execute on the Mac.
- Configuration is small, strict, inspectable, and portable.
- Failures are explicit and recoverable: no stale execution, automatic conflict winner, or automatic deletion.
- Direct-host and container runtimes are part of one complete architecture; direct host execution is the default.
- Implementation workstreams are dependency ordering, not separate reduced product versions.

## 3. Success criteria

- One local installation and one idempotent host bootstrap.
- No per-challenge setup is required.
- No manual `scp`, `rsync`, SSH login, or remote path management.
- `./chall`, Python, pwntools, GDB, signals, resize, readline, job control, and GDB TUI behave like local tools.
- Save-then-run always observes the saved local version.
- Remote artifacts are synchronized before the next managed-shell prompt.
- Sync conflicts block execution and identify exact recovery commands.
- `gdb.debug()` and `gdb.attach()` work with pwntools 4.15 and current 5-dev behavior.
- Host Zellij and tmux create native panes; a Mac without either still has a terminal-window provider.
- Normal operation needs neither root nor a persistent pwnbridge daemon.
- Network loss never deletes a workspace and always restores the local terminal.
- The same configuration model works for other macOS ARM users and Ubuntu x86-64 hosts.

## 4. Research synthesis

### 4.1 Selected foundation

| Area | Decision | Reason |
|---|---|---|
| Language | Go | Fast startup, simple concurrency and Unix integration, straightforward Darwin ARM64/Linux AMD64 builds |
| File synchronization | External Mutagen 0.18.1 | Bidirectional three-way sync, executable propagation, explicit flush, inspectable conflict state |
| Control transport | System OpenSSH | Preserves user SSH behavior and avoids reimplementing security-sensitive configuration |
| Interactive transport | Predictive inline SSH; optional Mosh | Immediate local typing and normal terminal history by default, with explicit roaming support |
| Local terminal proxy | Go PTY proxy | Raw byte fidelity, resize/signal handling, and prompt-marker parsing |
| Remote execution | Small `pwnbridge-agent` | Structured execution, environment fidelity, runtime selection, and debugger lifecycle |
| Configuration | Strict TOML | Portable and readable without a large ambiguous configuration framework |
| Terminal integration | Provider interface | Zellij-first without making Zellij mandatory |
| Default runtime | Ubuntu host | Least setup and native target behavior |
| Isolation runtime | Docker or Podman | Optional hostile-binary isolation with the same user experience |
| Distribution | Homebrew and GoReleaser | Natural macOS installation and reproducible assets |

### 4.2 Rejected cores

- Repeated `scp` or `rsync` still exposes transfer state and has no safe bidirectional history.
- SSHFS/macFUSE makes editor metadata and indexing network-bound, adds mount lifecycle, and provides no command consistency barrier.
- Syncthing requires daemon pairing and exposes eventual completion rather than a per-command reconciliation barrier.
- Unison and rclone bisync add history/version coupling and are less suitable for low-latency watch-plus-barrier behavior.
- A custom synchronization protocol would recreate the component with the greatest data-loss risk.
- A Go SSH implementation loses OpenSSH aliases, ProxyJump, Keychain, FIDO, host verification, and existing configuration.
- Mandatory remote tmux creates a nested multiplexer and makes host Zellij secondary.
- Local x86 emulation is useful but does not faithfully reproduce the remote Ubuntu kernel, libraries, and ptrace behavior.
- Editor-specific remote solutions do not provide an editor-independent local CLI workflow.
- Mutagen embedding is unsuitable because its daemon API is unstable, official builds include SSPL components from 0.17 onward, and complete builds need a specialized agent bundle.

### 4.3 Critical Mutagen finding

`mutagen sync flush` returning success is insufficient. A flush waits for a post-request synchronization cycle, but conflicts are valid session state and can coexist with successful command exit.

Every execution barrier therefore:

1. Runs blocking `mutagen sync flush <identifier>`.
2. Queries the exact stored session with templated JSON.
3. Verifies it is connected, unpaused, not safety-halted, and contains no conflicts, excluded conflicts, scan problems, transition problems, or last error.
4. Blocks execution when any health check fails.

Continuous watching is a latency optimization. Flush plus complete health validation is the correctness boundary.

## 5. User experience and CLI

### 5.1 First-time setup

```console
brew install simonfalke-01/pwnbridge/pwnbridge
pwnbridge --version
pwnbridge host add x86 pwnbox
pwnbridge host default x86
pwnbridge host doctor x86
pwnbridge host bootstrap x86 --profile pwn
pwnbridge host use x86
```

`host bootstrap` is explicit, idempotent, displays the package plan before sudo, and supports `--dry-run` and `--no-sudo`.

### 5.2 Public CLI

```text
pwnbridge
pwnbridge shell
pwnbridge run [--tty=auto|always|never] -- COMMAND [ARG...]
pwnbridge init
pwnbridge status [--json]
pwnbridge doctor [--json]
pwnbridge stop
pwnbridge clean [--remote] [--yes]

pwnbridge host add NAME DESTINATION [--shell-transport=auto|mosh|ssh]
                                     [--mosh-port=PORT[:PORT]]
pwnbridge host list
pwnbridge host show NAME [--json]
pwnbridge host transport NAME auto|mosh|ssh [--mosh-port=PORT[:PORT]]
pwnbridge host default NAME
pwnbridge host use NAME
pwnbridge host use --default
pwnbridge host remove NAME (--dry-run|--yes) [--force] [--json]
pwnbridge host doctor NAME [--json]
pwnbridge host bootstrap NAME [--profile=pwn] [--with-pwndbg]
                              [--dry-run] [--no-sudo]

pwnbridge sync status [--json]
pwnbridge sync flush
pwnbridge sync pause
pwnbridge sync resume
pwnbridge sync conflicts [--json]
pwnbridge sync diff -- PATH...
pwnbridge sync resolve --prefer local|remote -- PATH...

pwnbridge terminal providers [--json]
pwnbridge terminal test [--provider NAME]

pwnbridge runtime status [--json]
pwnbridge runtime reset

pwnbridge config path
pwnbridge config validate
pwnbridge config show [--effective] [--json]

pwnbridge completion bash|zsh|fish
pwnbridge --version
pwnbridge version [--json]
```

Behavioral rules:

- Bare `pwnbridge` means `pwnbridge shell`.
- Host-scope interactive shells use pwnbridge prediction over inline SSH in
  `auto` mode; explicit Mosh provides roaming, while one-shot and control
  operations always use SSH.
- `host default NAME` changes the machine fallback; `host use NAME` changes only the current project, and `host use --default` clears that project override.
- In `host list`, `*` marks the machine default and `>` marks the current project's effective host.
- The nearest ancestor `.pwnbridge.toml` defines the project; otherwise the current directory is the project root.
- Git roots are not selected implicitly.
- `run` transmits argv structurally. Pipelines require an explicit `bash -lc`.
- `stop` performs a final barrier, closes dependent panes, pauses synchronization, and exits the bounded warm OpenSSH master.
- `clean` terminates pwnbridge session state but preserves both workspaces.
- Only `clean --remote`, with confirmation or `--yes`, deletes the remote workspace.
- Conflict resolution backs up the losing version outside the synchronized tree before changing it.
- Machine-readable commands use stable JSON envelopes and documented exit codes.

## 6. Configuration and state

### 6.1 Precedence

```text
built-in defaults
→ global config
→ project config
→ documented PWNBRIDGE_* variables
→ CLI flags
```

Unknown TOML keys and unsupported schema versions are errors. Configuration is merged through typed structures, without Viper.

Documented overrides are limited to:

```text
PWNBRIDGE_CONFIG
PWNBRIDGE_HOST
PWNBRIDGE_LOG
PWNBRIDGE_MUTAGEN_PATH
PWNBRIDGE_AGENT_PATH
PWNBRIDGE_RUNTIME
```

### 6.2 Global configuration

Path: `$XDG_CONFIG_HOME/pwnbridge/config.toml`, falling back to `~/.config/pwnbridge/config.toml`.

```toml
schema = 2
default_host = "x86"

[hosts.x86]
destination = "pwnbox"
platform = "linux/amd64"
workspace_root = "~/.local/share/pwnbridge/workspaces"
bootstrap_profile = "pwn"
shell_transport = "auto"
mosh_port = "60000:61000"

[sync]
engine = "mutagen"
pause_on_idle = false
barrier_timeout = "2m"

[terminal]
provider = "auto"
scope = "host"
placement = "right"
size = "50%"
focus = true
close_on_success = true
hold_on_failure = true

[terminal.zellij]
near_current_pane = true
direction = "right"
floating = false

[terminal.tmux]
direction = "horizontal"
size = "50%"

[runtime.container]
engine = "auto"
```

### 6.3 Portable project configuration

`.pwnbridge.toml` is optional:

```toml
schema = 1
target = "linux/amd64"

[workspace]
root = "."
ignore = ["recordings/", "*.bak"]

[environment]
profile = "pwn"
set = {}

[shell]
command = "bash"
source_user_rc = true

[runtime]
kind = "host"
```

Container projects use:

```toml
[runtime]
kind = "container"

[runtime.container]
engine = "auto"
image = "ghcr.io/simonfalke-01/pwnbridge-pwn@sha256:<digest>"
workdir = "/work"
network = "bridge"
```

Project files never contain hostnames, users, SSH keys, local terminal choices, or bearer tokens. `pwnbridge host default` updates the machine-wide fallback; `pwnbridge host use` stores the project-to-host binding in local state.

### 6.4 Workspace identity

- Generate a persistent random installation ID on first use.
- Resolve and canonicalize the project root.
- Hash installation ID, canonical root, and host ID with SHA-256.
- Remote name is `<sanitized-slug>-<first-16-hash-characters>`.
- Moving a project creates a new identity; Git remotes are not used for adoption.
- Persist Mutagen identifier and configuration fingerprint.
- Use per-workspace cross-process locks so shells, runs, and GDB panes share barriers and leases safely.

### 6.5 Ignores

Built-ins:

```text
.git/
.DS_Store
.pwnbridge/
.venv/
venv/
__pycache__/
*.pyc
.idea/
.vscode/
```

`.pwnbridgeignore` extends the list. `.gitignore` is never imported automatically. ELF binaries, libc, loaders, `core*`, dumps, logs, patched binaries, and exploit artifacts are never default-ignored.

### 6.6 State paths

```text
Local config:  $XDG_CONFIG_HOME/pwnbridge/
Local state:   $XDG_STATE_HOME/pwnbridge/
Local data:    $XDG_DATA_HOME/pwnbridge/
Local cache:   $XDG_CACHE_HOME/pwnbridge/

Remote agents:
~/.local/share/pwnbridge/agents/<protocol>/<content-hash>/pwnbridge-agent

Remote workspaces:
~/.local/share/pwnbridge/workspaces/<machine-id>/<slug-hash>/

Remote session scratch:
~/.cache/pwnbridge/sessions/<session-id>/
```

Use atomic writes, mode-0600 files, mode-0700 private directories, and advisory locks. Unix socket paths remain deliberately short for Darwin limits.

## 7. System architecture

```text
Local Mac                                          Ubuntu x86-64
─────────                                          ─────────────
Editor / Git / static tools
        │
        ▼
Local challenge directory
        │
        ├──── Mutagen two-way-safe sync ─────────► Remote workspace
        │                                             │
        ▼                                             ▼
pwnbridge CLI ───── OpenSSH control master ───── pwnbridge-agent
        │                                             │
        │                                             ├─ host process
        │                                             └─ container process
        │
        ├─ PTY proxy ◄──── predictive SSH or Mosh PTY ─ remote Bash/process
        │
        └─ terminal broker ◄── reverse SSH socket ─ pwntools-terminal
                  │
                  ├─ Zellij pane
                  ├─ tmux pane
                  ├─ terminal window
                  └─ custom provider
                              │
                              └─ second SSH PTY ── remote GDB
```

### 7.1 Go stack

- Go module language version 1.25; build and test on supported 1.25 and 1.26 patch releases.
- `github.com/spf13/cobra`
- `github.com/pelletier/go-toml/v2`
- `github.com/creack/pty`
- `golang.org/x/term`
- `golang.org/x/sys/unix`
- Standard-library `log/slog`, `encoding/json`, `crypto/rand`, `crypto/sha256`, `os/exec`, and `net`.

Avoid an SSH library, TUI framework, RPC framework, Viper, UUID dependency, and public Go package API until an external consumer exists.

### 7.2 Repository structure

```text
pwnbridge/
├── PLAN.md
├── README.md
├── CONTRIBUTING.md
├── LICENSE
├── go.mod
├── go.sum
├── Makefile
├── .goreleaser.yaml
├── cmd/
│   ├── pwnbridge/
│   └── pwnbridge-agent/
├── internal/
│   ├── agent/
│   ├── bootstrap/
│   ├── broker/
│   ├── cli/
│   ├── config/
│   ├── diagnostics/
│   ├── fsutil/
│   ├── identity/
│   ├── paths/
│   ├── protocol/
│   ├── runtime/
│   ├── shell/
│   ├── syncer/
│   ├── terminal/provider/
│   ├── transport/
│   ├── version/
│   └── workspace/
├── docs/
├── packaging/
│   ├── container/
│   ├── homebrew/
│   └── release/
├── test/e2e/
└── .github/workflows/
```

Important interfaces:

```go
type SyncEngine interface {
    Ensure(context.Context, Spec, *workspace.State) error
    Resume(context.Context, string) error
    Barrier(context.Context, string) (HealthReport, error)
    Status(context.Context, string) (HealthReport, error)
    Pause(context.Context, string) error
    Terminate(context.Context, string) error
}

type TerminalProvider interface {
    Detect(context.Context) (Capabilities, int, error)
    Open(context.Context, Spec) (Handle, error)
    Inspect(context.Context, Handle) (State, error)
    Focus(context.Context, Handle) error
    Close(context.Context, Handle) error
}
```

Runtime selection remains a small set of package functions over a typed
`RuntimeSpec`; it does not need a framework-style interface until another
runtime family exists.

## 8. Synchronization and command barriers

### 8.1 Mutagen policy

- Require and test Mutagen 0.18.1.
- Run it externally; never bundle or link it.
- Isolate it with `MUTAGEN_DATA_DIRECTORY` under pwnbridge state.
- Use `--no-global-configuration` for creation.
- Use `two-way-safe`, portable watch mode, and portable symlink mode.
- Offer `posix-raw` symlinks only as an explicit advanced option with a warning.
- Operate by stored unique identifier, not human-readable session name.
- Label sessions with pwnbridge version, workspace ID, and host ID.
- Recreate only after endpoint and configuration fingerprints have been validated.
- Pause after the last lease exits and a final barrier succeeds.
- Never automatically reset Mutagen history or resume a safety-halted root.

### 8.2 Interactive barrier

The remote managed Bash uses a generated rcfile that sources the user's `.bashrc`, installs private nonce-bearing command-complete and prompt-ready markers, preserves the user's prompt, and does not export the nonce.

At a trusted prompt, Enter is held locally. Remaining pasted input is buffered. pwnbridge acquires the workspace barrier lock, flushes Mutagen, validates complete health, and forwards the newline only on success.

When Bash reports command completion, pwnbridge continues draining the PTY, holds the next prompt and top-level input, flushes and validates, and reveals the prompt only after remote artifacts are local.

While Python, GDB, an inferior, curses program, or another foreground process owns the terminal, bytes pass unchanged. Ctrl-C, Ctrl-Z, EOF, job control, alternate-screen output, and resize remain native. `pwnbridge run` uses the same pre/post barriers without markers.

### 8.3 Conflict resolution

`sync resolve` validates conflict paths, copies the losing endpoint version into a timestamped recovery directory outside the synchronized root, deletes the losing endpoint copy, flushes until the preferred version propagates, and reports the backup path. Execution remains blocked until the whole session is healthy.

## 9. SSH, PTY, agent, and bootstrap

### 9.1 OpenSSH control plane

Use an owner-private, identity-keyed control master shared by nearby managed
invocations and bounded by OpenSSH's idle timer:

```text
ssh -M -N -f
    -S <short-private-control-path>
    -o ControlMaster=yes
    -o ControlPersist=2m
    -o ClearAllForwardings=yes
    -o ServerAliveInterval=15
    -o ServerAliveCountMax=3
    -o ForwardAgent=no
    -o ForwardX11=no
    <destination>
```

- Use the user's ordinary SSH configuration.
- Never disable strict host-key verification.
- Wait with `ssh -O check`, not sleeps.
- Publish the atomic active-session record only after the control master and
  reverse-broker ping are usable; it is a readiness boundary for `stop`.
- Auto host-scope shells use pwnbridge predictive echo over inline
  `ssh -S ... -tt -e none` channels; plain SSH disables prediction.
- Explicit Mosh uses `--predict=always` when its UDP path, `mosh-server`, and
  authenticated barrier bridge are ready.
- Keep broker tokens, remote session state, leases, and reverse forwards
  per invocation; cancel the exact forward when its owning session exits.
- Let OpenSSH retain only the authenticated base connection for two idle
  minutes, and issue `ssh -O exit` on `stop` or `clean`.
- Restore the local terminal immediately if transport fails.
- Let Mutagen maintain its own system-SSH connection rather than coupling it to UI channels.

### 9.2 Agent deployment

Build with `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`. Lookup order is `PWNBRIDGE_AGENT_PATH`, Homebrew libexec, then an adjacent release asset.

Probe OS/architecture, upload to a temporary user-owned path, verify SHA-256 remotely, chmod, and atomically rename into a protocol/content-addressed directory. Reuse exact matches and retain the two newest unused agents. Never use a system path and never run a persistent agent daemon.

### 9.3 Bootstrap profile

The cross-distribution `pwn` recipe verifies or installs manager-specific
equivalents of:

```text
build-essential cmake file binutils gdb gdbserver gdb-multiarch patchelf checksec
python3 python3-dev python3-venv python3-pip python3-pwntools libssl-dev libffi-dev tmux
strace ltrace socat netcat-openbsd libc6-dbg
```

It also includes Git, curl, certificates, xz, and Mosh, and creates a user-owned
virtual environment with pinned pwntools 4.15.0. The
checksum-verified Pwndbg profile is optional; any existing GEF/PEDA setup stays
user-owned and isolated from it. Bootstrap checks distro, amd64 architecture,
disk/inodes, home/workspace permissions, forwarding, ptrace, GDB, gdbserver,
and selected container components. Apt, dnf/yum, pacman, zypper, apk, XBPS,
Portage, and Nix adapters use fixed argv and configured repositories. Without
sudo it reports all privileged blockers before any user-owned mutation.

## 10. Pwntools and terminal broker

Pwntools selects explicit `context.terminal`, then `pwntools-terminal` in `PATH`, before built-in multiplexer detection. The remote session injects `pwntools-terminal`. Exploits normally remain unchanged; hard-coded configurations should be removed or set to:

```python
context.terminal = ["pwntools-terminal"]
```

### 10.1 Wrapper lifecycle

The agent exposed as `pwntools-terminal` is a long-lived lifecycle proxy. It receives pwntools' temporary command, creates a random request, and writes a mode-0600 remote manifest containing base64 argv/environment, cwd, session, and runtime. It sends only opaque IDs to the Mac broker, remains alive with the pane, translates SIGTERM into cancellation, and removes the manifest at completion.

The Mac constructs only:

```text
pwnbridge __pane --session <validated-id> --request <validated-id>
```

The helper opens a second SSH PTY and invokes a fixed remote agent command. The agent reads its local manifest and executes GDB directly, without shell reconstruction. Transport-owned `SSH_*`, terminal, multiplexer, `PWNBRIDGE_*`, `PWD`, `OLDPWD`, and `_` values are not restored; `PATH`, `VIRTUAL_ENV`, `LD_*`, locale, `PWNLIB_*`, and debugger variables are preserved.

### 10.2 Broker transport and protocol

Prefer `-R <remote-session-socket>:<local-broker-socket>` with mode-0700 directories, mode-0600 sockets, a 256-bit token, version handshake, `ExitOnForwardFailure=yes`, an end-to-end ping, 1 MiB frame cap, pane cap, and request-rate limit.

If stream-local forwarding is disabled, use token-authenticated reverse TCP bound to remote `127.0.0.1`. If forwarding is entirely disabled, normal shell operation remains available and debugger panes fail clearly; explicit remote-multiplexer scope remains possible.

Frames are four-byte big-endian length plus UTF-8 JSON. Messages are `hello`, `open`, `opened`, `close`, `cancel`, `exited`, `error`, `ping`, and `pong`. State transitions are idempotent:

```text
created → open-requested → pane-opening → running
                                          └→ completed | cancelled | failed
```

Parent exit closes the pane and GDB. Natural GDB exit propagates status. Manual pane close cancels the wrapper. Debugger failure holds the pane when configured. Multiple debugger requests are independently tracked.

### 10.3 Terminal providers

Auto-selection:

```text
explicit provider
→ host Zellij
→ host tmux
→ current supported terminal application
→ macOS Terminal.app
→ actionable error
```

Remote Zellij/tmux scope is an explicit configuration choice rather than a
silent fallback, because it changes the presentation model and may create a
nested multiplexer. Built-ins are Zellij, tmux, WezTerm, Kitty, iTerm2,
Terminal.app, explicit remote Zellij/tmux, and a custom provider executable
named `pwnbridge-terminal-<name>`. Custom providers exchange versioned JSON and
receive only the trusted local pane helper, never remote argv.

Zellij supports right, down, tab, floating, stable returned pane IDs, origin
targeting, feature probing, structured inspection, focus, and close. tmux
supports right, down, window, stable `%pane_id`, direct multi-argument
invocation, focus, and idempotent close. Terminal.app is the zero-configuration
fallback via a private generated `.command` containing only the local helper.

Local `$ZELLIJ*`, `$TMUX`, and `$TMUX_PANE` are never forwarded remotely.

## 11. Runtime providers

### 11.1 Direct host runtime

Execute in the remote workspace, activate the pwnbridge Python environment when selected, preserve user GDB configuration, and keep GDB and inferior on the same Ubuntu host. Warn that untrusted binaries have the remote account's privileges.

### 11.2 Container runtime

Docker and Podman share one adapter. A session uses one long-lived named container with a digest-pinned image, workspace at `/work`, session state at `/run/pwnbridge`, read-only agent mount, remote UID/GID, configured working directory, `SYS_PTRACE`, appropriate seccomp adjustment, and no mounted engine control socket. Network mode is configurable with `bridge` default. Shell, process, gdbserver, GDB, manifest, and broker use the same container. `runtime reset` recreates the container without deleting the workspace.

## 12. Security and recovery

- Challenge binaries are untrusted.
- A same-UID remote process may read same-user state; tokens alone do not isolate it.
- The hard invariant is that remote requests can trigger approved remote debugger execution but never arbitrary Mac execution.
- Container mode improves challenge isolation but is not a complete server trust boundary.
- Never forward SSH agent or X11, expose broker TCP beyond loopback, or disable host-key checking.
- Sanitize pane titles, cap metadata, and redact tokens/environment secrets from logs.
- GDBserver is not publicly exposed.
- Network loss restores the terminal and preserves both workspaces.
- Local cancellation owns exit status 130 even when an SSH child or teardown
  command fails concurrently.
- Mutagen crashes cause isolated daemon restart and full session revalidation.
- Conflicts, root deletion, disk full, and permission errors block execution without automatic reset.
- A kernel advisory lease, not PID existence alone, proves that a session is
  live; even old corrupt records are removed only after ownership, age, and
  non-blocking lease acquisition validate them as stale.
- Version mismatch uploads the matching content-addressed agent.
- Interrupted bootstrap is idempotently resumable.
- No workspace is removed without explicit `clean --remote` authorization.

## 13. Implementation workstreams

These are dependency-ordered parts of one complete target.

### A. Repository and feasibility

- Create this repository and canonical plan.
- Add module, license, build tooling, tests, and CI skeleton.
- Capture Mutagen 0.18.1 JSON fixtures.
- Prove flush-plus-health validation, PTY marker chunking, terminal pane launch, and reverse forwarding fallbacks.

### B. Configuration, state, and hosts

- Implement strict TOML and precedence.
- Implement XDG paths, identities, locks, and atomic state.
- Implement host registry, selection, probes, doctor, JSON, agent upload, and bootstrap.

### C. Synchronization

- Implement the `SyncEngine` and Mutagen adapter.
- Implement version gates, lifecycle, health barriers, fingerprints, leases, serialization, conflicts, backups, and explicit resolution.

### D. Execution and shell

- Implement structured agent protocol, `run`, SSH master, predictive inline SSH,
  optional Mosh, PTY proxy, terminal restoration, resize/signals, Bash
  markers/barrier hooks, paste buffering, and direct-host runtime.

### E. Terminal broker

- Implement reverse broker transport, remote manifest, long-lived wrapper, pane SSH channels, lifecycle, concurrent requests, and every terminal provider.

### F. Container runtime

- Implement Docker/Podman discovery, pinned session lifecycle, mounts, ownership, ptrace, networking, same-runtime GDB, and teardown.

### G. Hardening and distribution

- Add fuzzing, race/failure testing, end-to-end automation, docs, completions, GoReleaser, checksums, SBOMs, attestations, and Homebrew packaging.

## 14. Test and acceptance plan

### 14.1 Unit and fuzz

- Config defaults, precedence, strict keys, schema rejection, and paths.
- Workspace identity stability and collision handling.
- SSH argv, short control paths, hostile filenames, and no interpolation.
- Protocol framing, invalid input, caps, authentication, and version mismatch.
- Marker parser over every chunk boundary, fake markers, binary output, and pasted commands.
- Mutagen JSON conflicts, excluded conflicts/problems, disconnect, and safety halt.
- Provider detection, argv, handles, capabilities, and lifecycle.
- Runtime construction and container identity.
- Native fuzzing for protocol, marker, JSON, ignore, and path parsers.

### 14.2 Integration

- Fake `ssh`, `scp`, `mutagen`, Zellij, tmux, Docker, and Podman record argv and inject failure.
- Real PTY raw mode, readline, Ctrl-C/Z/D, jobs, resize, alternate screen, and restoration.
- Concurrent shell/run/pane barriers share one lock.
- Initial sync, pause/resume, chmod, symlink, delete, conflict, root deletion, disk full, and permissions.
- Save `solve.py`, immediately press Enter, and verify new content runs.
- Generate a remote core/patched file and verify it is local before the prompt.
- Spaces, Unicode, and byte-oriented debugger arguments.

### 14.3 Pwntools and terminals

- Pwntools 4.15.0 and current 5-dev.
- Wrapper precedence and explicit `context.terminal` behavior.
- `gdb.debug()`, `gdb.attach()`, process attach, and `api=True`.
- Virtualenv, `LD_PRELOAD`, scripts, and temporary executables.
- Every parent/GDB/pane/broker exit order, duplicate cancellation, and two debuggers.
- Zellij right/down/tab/floating, structured inspect, focus, close, and hold.
- tmux right/down/window, origin, stable handles, focus, and kill.
- WezTerm, Kitty, iTerm2, Terminal.app, custom, and no-multiplexer flows.
- Unix forwarding, TCP fallback, authentication failures, flood, and pane caps.
- Malicious remote metadata cannot alter local argv.

### 14.4 End to end

- Apple Silicon macOS to Ubuntu amd64.
- The current `ret2win` ELF executes through pwnbridge from its local project.
- GDB TUI resizes correctly.
- Zellij 0.44.3 and tmux 3.6a host workflows.
- Direct-host and container runtimes.
- Solve, gdbserver, and GDB share a container namespace.
- Disconnect/reconnect preserves data and terminal state.
- Clean install/bootstrap requires no manual configuration-file editing.

## 15. Packaging and licensing

- pwnbridge uses the MIT license.
- Mutagen is a separately licensed external runtime and is never vendored, linked, or redistributed.
- Homebrew depends on `mutagen-io/mutagen/mutagen` and `mosh`.
- Releases contain Darwin ARM64/AMD64 clients, Linux AMD64 agent, completions, README, license, checksums, and SBOM.
- Product SemVer is independent from config, agent, broker, terminal-provider, and bootstrap protocol integers.
- Client and agent release together; content-addressed older agents are retained for rollback.
- The supported complete scenario is macOS ARM/AMD64 to Ubuntu/Debian AMD64, while internal interfaces remain portable.

## 16. Research references

- [Pwntools terminal selection, stable 4.15](https://github.com/Gallopsled/pwntools/blob/4.15.0/pwnlib/util/misc.py#L2521-L2933)
- [Pwntools terminal selection, 5-dev](https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/util/misc.py)
- [Pwntools GDB integration](https://docs.pwntools.com/en/stable/gdb.html)
- [Pwntools SSH integration](https://docs.pwntools.com/en/stable/tubes/ssh.html)
- [Mutagen synchronization](https://mutagen.io/documentation/synchronization)
- [Mutagen flush usage](https://mutagen.io/documentation/introduction/getting-started)
- [Mutagen safety](https://mutagen.io/documentation/synchronization/safety-mechanisms/)
- [Mutagen permissions](https://mutagen.io/documentation/synchronization/permissions)
- [Mutagen symlinks](https://mutagen.io/documentation/synchronization/symbolic-links/)
- [Mutagen ignores](https://mutagen.io/documentation/synchronization/ignores/)
- [Mutagen VCS guidance](https://mutagen.io/documentation/synchronization/version-control-systems/)
- [Mutagen names and labels](https://mutagen.io/documentation/introduction/names-labels-identifiers/)
- [Mutagen embedding warning](https://mutagen.io/documentation/introduction/daemon/)
- [Mutagen SSH transport](https://mutagen.io/documentation/transports/ssh/)
- [Mutagen license](https://github.com/mutagen-io/mutagen/blob/master/LICENSE)
- [Mutagen 0.18.1](https://github.com/mutagen-io/mutagen/releases/tag/v0.18.1)
- [OpenSSH client](https://man.openbsd.org/ssh)
- [OpenSSH configuration](https://man.openbsd.org/ssh_config)
- [OpenSSH server forwarding](https://www.man7.org/linux/man-pages/man5/sshd_config.5.html)
- [Mosh](https://mosh.org/)
- [PTY semantics](https://www.man7.org/linux/man-pages/man7/pty.7.html)
- [Zellij CLI recipes](https://zellij.dev/documentation/cli-recipes.html)
- [Zellij programmatic control](https://zellij.dev/documentation/programmatic-control.html)
- [Zellij actions](https://zellij.dev/documentation/cli-actions.html)
- [Zellij integration](https://zellij.dev/documentation/integration.html)
- [tmux getting started](https://github.com/tmux/tmux/wiki/Getting-Started)
- [tmux advanced use](https://github.com/tmux/tmux/wiki/Advanced-Use)
- [WezTerm split panes](https://wezterm.org/cli/cli/split-pane.html)
- [Go compatibility](https://go.dev/doc/go1compat)
- [Go fuzzing](https://go.dev/doc/security/fuzz/)
- [creack/pty](https://github.com/creack/pty)
- [GoReleaser](https://goreleaser.com/getting-started/intro/)
- [GoReleaser reproducible builds](https://goreleaser.com/blog/reproducible-builds/)
- [Homebrew tap trust](https://docs.brew.sh/Tap-Trust)
- [Apple Rosetta Linux alternative](https://developer.apple.com/documentation/virtualization/running-intel-binaries-in-linux-vms-with-rosetta)
- [SSHFS maintenance](https://github.com/libfuse/sshfs)
- [rclone bisync safety](https://rclone.org/bisync/)
- [Syncthing REST model](https://docs.syncthing.net/dev/rest.html)

## 17. Locked decisions

- Project, directory, executable, and prefix are `pwnbridge`.
- MIT license and Go implementation.
- Mutagen 0.18.1 is external and version-gated.
- System OpenSSH is the control transport and default predictive interactive
  transport; host-scope shells can explicitly select Mosh.
- Ubuntu/Debian amd64 is the remote platform.
- Direct host execution is default; Docker/Podman is configurable.
- Bash is the deterministic managed shell; one-shot execution is shell-independent.
- Zellij is preferred when detected, never required.
- A local terminal application provides the no-multiplexer fallback.
- Sync is `two-way-safe`; portable symlinks are the default.
- No public daemon, agent forwarding, silent conflict resolution, automatic reset, or automatic deletion.
- Terminal providers, pwntools broker, host runtime, and container runtime all belong to the complete target.

## 18. Implementation completion record

The complete target described by this plan is implemented. There is no
deferred reduced-product phase: host execution, the optional container
runtime, synchronization safety, the PTY shell, debugger broker, host and
remote multiplexers, packaging, and operator documentation ship together.

Acceptance was completed on 2026-07-13 from an Apple Silicon macOS host against
a real Ubuntu amd64 Lima guest. The same production OpenSSH, Mutagen, uploaded
agent, broker, and runtime paths used by the CLI were exercised.

| Area | Acceptance evidence |
|---|---|
| Go implementation | `go test ./...`, `go vet ./...`, cross-builds, and `go test -race ./...` pass on the supported Go 1.25.12 and 1.26.5 lines; native fuzz targets cover strict TOML, framed protocol, shell markers, Mutagen health JSON, ignore parsing, and workspace slugs |
| Synchronization | Real two-way-safe initial sync, save-before-run barriers, executable bits, portable symlinks, Unicode, remote deletion, endpoint permission failure/recovery, conflicts (including spaces), explicit resolution backups, and remote-root deletion protection pass |
| PTY lifecycle | Predictive inline SSH, plain SSH, readline, bracketed paste, Ctrl-C/Z/D, job control, alternate-screen bytes, resize, prompt barriers, disconnect restoration, reconnect, and artifact return pass in real PTYs; explicit Mosh coverage validates clean exit, roaming transport selection, and remote barriers |
| Pwntools/GDB | pwntools 4.15.0 and pinned 5-dev commit `6571ec7de50d3c8fc235fad2a27bcdb07ca87acf` exercise `gdb.debug()`, process attach, `api=True`, and concurrent debuggers; Pwndbg 2026.02.18 and GDB TUI/resize pass |
| Terminal integration | Zellij 0.44.3 and tmux 3.6a host panes pass; custom-provider PTYs and explicit remote tmux pass; remote tmux remains correct in the presence of a stale unrelated tmux server because each managed session has a private server/socket |
| Runtime coverage | Direct Ubuntu amd64 and Podman container execution pass; solve process, gdbserver, GDB, wrapper, and API bridge remain in the intended runtime namespace |
| Degradation and recovery | Reverse-forwarding denial degrades ordinary shell/run cleanly and retains explicit remote-multiplexer GDB; live SSH-master termination restores the host terminal and preserves/reconciles data; session records publish only after broker readiness, and a ten-run immediate-stop stress test terminates leased sessions with deterministic status 130 |
| Security and quality | `gosec` passes under the documented deliberate exclusions; `govulncheck` reports no reachable vulnerabilities; ShellCheck, actionlint, workflow YAML parsing, Python syntax, Ruby syntax, and Homebrew style pass |
| Distribution | GoReleaser emits Darwin arm64/amd64 clients plus a static Linux amd64 agent, documentation, completions, checksums, and SPDX 2.3 SBOMs; output and archive file times are fixed independently from embedded version metadata, checksums verify, and two clean builds produce byte-identical archives even without a configured Git remote |

The CI and release workflows repeat the deterministic gates, publish draft
tag releases, attach checksum-based GitHub attestations, and publish the
optional amd64 container with provenance and SBOM metadata. Future work is
normal maintenance and compatibility expansion, not unfinished scope from
this plan. Evidence, findings, and follow-up priorities from that ongoing work
are maintained in [docs/audit-log.md](docs/audit-log.md).

## 19. Continuous-improvement roadmap — Cycle 14

### Product and technical assessment

The repository has no open or closed public GitHub issues as of 2026-07-14,
and the 0.1.0–0.1.13 release history is concentrated in the preceding day.
Issue volume therefore provides no mature usage signal. The strongest current
workflow evidence is an internal contradiction: the troubleshooting guide
instructs users to inspect both conflict copies before choosing a winner, but
an unhealthy session blocks normal remote execution and the synchronization
CLI can only list paths or immediately resolve them.

Mutagen's documented `two-way-safe` resolution model requires deleting the
losing endpoint. A trustworthy preview is therefore part of the data-loss
decision rather than cosmetic convenience. Current macOS `diff` and POSIX
Issue 8 both define unified output, and the macOS implementation supports
explicit labels, allowing a familiar local-to-remote presentation without a
new Go dependency or editor integration.

Ranked opportunities:

| Rank | Opportunity | User value / severity | Fit | Effort / risk | Evidence and decision |
|---:|---|---|---|---|---|
| 1 | `pwnbridge sync diff -- PATH...` | High / medium | Very high | Medium / medium | Completes the documented conflict journey and makes the explicit winner choice informed; selected |
| 2 | One-command redacted support bundle | Medium / low | Medium | Medium / high | Comparable remote tools collect diagnostics, but Pwnbridge has no support issue evidence and redaction creates disclosure risk; defer |
| 3 | Combined first-host setup wizard | Medium / low | Medium | High / medium | Comparable tools guide connection setup, but the existing bootstrap wizard already handles the complex part and the four explicit host commands are well documented; defer |
| 4 | Descriptor-relative conflict-tree deletion | High / high security | High | High / high | Same-user concurrent namespace mutation remains a real residual risk, but it is a narrow hardening project; reassess after this product cycle |
| 5 | Broad statement-coverage expansion | Medium / low | High | Medium / low | Current core package coverage ranges from 32–73%; add tests around changed behavior now and pursue risk-directed coverage rather than a percentage-only campaign |

### Selected feature and acceptance criteria

Implement `pwnbridge sync diff -- PATH...` as a read-only preview for exact
current conflict paths:

1. Reject absolute paths, traversal, duplicates, non-conflicts, and sessions
   without resolvable conflicts before starting remote inspection.
2. Capture each endpoint through descriptor-relative, no-follow, nonblocking
   traversal rooted at its workspace. Missing files, regular files,
   directories, symlinks, and special files are typed explicitly; no pathname
   is followed outside either workspace.
3. Bound preview content to 1 MiB per endpoint. Display-safe UTF-8 regular
   files receive a unified local-to-remote diff with escaped labels. Binary or
   control-bearing content, oversized files, links, directories, and special
   files receive bounded metadata instead of raw terminal output.
4. Treat `diff` status 1 as the expected "different" result, preserve
   cancellation/errors, use the content-addressed bundled agent for remote
   capture, and never delete, overwrite, resume, or resolve endpoint content.
5. Document discovery, directionality, limits, failure modes, and the intended
   inspect-then-resolve workflow in CLI, troubleshooting, architecture,
   security, and end-to-end guidance.
6. Add unit tests for descriptor traversal and every preview class, an agent
   request test, CLI path-validation tests, and a real Lima conflict preview.
   Run formatting, module verification, all tests, vet, Darwin cross-builds,
   Linux agent build/size/dependency checks, race tests, security scans, fuzz
   smoke, and a focused performance measurement.

### Risks and mitigations

- Rendering remote bytes can inject terminal controls. Only valid UTF-8 with
  tabs/newlines and no other control runes is eligible for unified output.
- Files can change during an explicit preview. The opened descriptor fixes
  identity and the response describes the captured bytes; the final
  `sync resolve` command independently re-reads current conflict state.
- Starting SSH and deploying a content-addressed agent adds latency. One master
  is reused for every requested path, and no full execution session, broker,
  runtime, or synchronization barrier is created.
- POSIX `diff -u` is part of the supported macOS base; `-L` labels are present
  in the macOS implementation. Missing `diff` is reported by doctor and by the
  command itself rather than introducing a bundled diff library.

### Completion status

Cycle 14 delivered the selected feature end to end. The CLI, shared
descriptor-rooted capture layer, Linux agent operation, strict response
validation, control-safe renderer, local diagnostics, public documentation,
unit/race coverage, benchmark, and Lima scenario are integrated. The full
local verification, cross-build, race, security, fuzz, and ShellCheck gates
pass. A configured Lima VM is not present in this audit environment, so the
new real-host assertions are committed to the existing `lima.sh` scenario but
were not executed here; the earlier complete Lima acceptance remains recorded
in section 18.

## 20. Continuous-improvement roadmap — Cycle 15

### Product and technical assessment

Conflict resolution creates durable losing-endpoint copies, but users can
discover a copy only in the transient output of the resolving command. There
is no supported inventory, machine-readable recovery catalog, or restore
workflow. This leaves the product's strongest data-loss safeguard incomplete
at the point where it is needed. The fixed on-disk layout retains enough
information to expose older copies, while a small manifest can preserve the
original conflict boundary for new directory backups.

The local losing-copy flow also validates path parents and subsequently calls
path-based recursive copy and removal. A deterministic fixture replaced a
validated directory with a symlink before removal and caused the same
`rm -rf` shape to delete a victim outside the workspace. Go documents this as
a time-of-check/time-of-use traversal class and provides `os.Root` operations
implemented relative to a held directory descriptor. Go 1.25 additionally
provides rooted recursive removal, rename, and symlink creation, matching this
repository's minimum toolchain.

Comparable recovery tools make discovery and restoration distinct, explicit
operations. Borg exposes archive IDs, separate list/extract commands, and a
dry-run mode; restic exposes snapshot inventory including JSON and recommends
a non-existing target or no-overwrite mode when preserving current data. Git's
reflog similarly makes prior states addressable before an explicit restore.

Ranked opportunities:

| Rank | Opportunity | User value / severity | Fit | Effort / risk | Evidence and decision |
|---:|---|---|---|---|---|
| 1 | Recovery inventory and explicit restore | High / high | Very high | Medium / medium | Completes an existing safety workflow with no new service or dependency; selected |
| 2 | Descriptor-rooted local recovery copy/removal | High / high security | Very high | Medium / medium | Deterministic namespace-race reproduction and official Go guidance; selected as the recovery foundation |
| 3 | Agent-streamed remote backup-and-delete transaction | Medium / high security | High | High / high | Separate SCP and remote shell operations retain a same-user remote race; defer until a bounded streaming protocol can preserve directories and metadata atomically |
| 4 | Recovery retention/pruning policy | Medium / low | Medium | Medium / high | Backup tools expose explicit policy, but this young project has no capacity or retention evidence; avoid automatic deletion |
| 5 | Redacted support bundle | Medium / low | Medium | Medium / high | Still lacks disclosure-safe field-level evidence; defer rather than create a new secret-exposure path |

### Selected feature and acceptance criteria

Implement `pwnbridge sync recovery list [--json]` and
`pwnbridge sync recovery restore ID --to PATH`:

1. Give every new recovery copy a stable path-derived identifier and durable
   versioned manifest containing creation time, winning and losing endpoint,
   original relative path, object kind, byte count, item count, and mode.
   Update the manifest before deleting the loser. Inventory legacy pre-manifest
   copies as individually restorable leaf artifacts instead of hiding them.
2. Keep listing offline and read-only. Sort newest entries first, escape all
   human-facing paths, emit the standard versioned JSON envelope, and fail
   clearly on malformed manifests rather than silently omitting recovery data.
3. Require an explicit project-relative `--to` destination. Reject absolute,
   traversing, non-canonical, empty, and already-existing targets. Restore
   regular files, directories, and symlinks without following a recovery
   symlink; reject special files and remove partial destination trees on error.
4. Implement source traversal, destination creation, and local loser removal
   through `os.Root`. Bind regular reads to validated descriptors, open
   nonblocking, copy exactly the observed length, preserve permission bits,
   sync file and directory changes, and never cross either held root even if a
   path is replaced concurrently.
5. Serialize resolve and restore mutations with the existing workspace lock,
   but release it before the synchronization barrier to avoid recursive lock
   acquisition. Do not implicitly resume or flush synchronization during an
   offline restore; report the local result and document `sync flush` as the
   explicit propagation check.
6. Document discovery, JSON fields, restoration, no-overwrite behavior,
   offline semantics, legacy behavior, failure cleanup, and remaining remote
   limitations. Add package and CLI tests for manifests, legacy inventory,
   every supported type, traversal, collisions, partial cleanup, special/FIFO
   rejection, namespace replacement, command discovery, and escaped output.
7. Run formatting, module verification, focused repetitions, all tests, vet,
   Darwin cross-builds, Linux agent checks, race tests, security scans, fuzz
   smoke, packaging shell checks, and focused copy/list benchmarks.

### Risks and mitigations

- A recovery directory is mutable by the same local account. Rooted operations
  prevent namespace escape; manifest validation and exact exclusive creation
  prevent silent redirection or overwrite. This is a recovery catalog, not an
  authenticated archival format, so documentation will not claim tamper
  detection.
- Directory copies can fail after creating part of the destination. Exclusive
  top-level creation establishes ownership of the new tree, allowing safe
  rooted cleanup without touching pre-existing content.
- Legacy layout cannot distinguish a directory conflict from a group of
  independently backed-up nested paths. The inventory exposes conservative
  leaf artifacts; new manifests retain the original boundary.
- A restore inside the synchronized project may itself conflict or remain
  local while synchronization is paused. The command never resumes a session
  as a side effect and points users to the existing explicit barrier.
- Rooted operations prevent escaping a workspace but do not prevent access to
  mount points inside it. This matches Go's documented boundary; Pwnbridge does
  not create or manage mounts during conflict recovery.

### Research references

- [Go `os.Root` and traversal-resistant APIs](https://go.dev/blog/osroot)
- [Go `os` package rooted operations](https://pkg.go.dev/os?GOOS=linux#Root)
- [Borg list](https://borgbackup.readthedocs.io/en/stable/usage/list.html)
- [Borg extract](https://borgbackup.readthedocs.io/en/stable/usage/extract.html)
- [restic restore](https://restic.readthedocs.io/en/v0.19.1/050_restore.html)
- [restic JSON scripting output](https://restic.readthedocs.io/en/latest/075_scripting.html)
- [Git reflog](https://git-scm.com/docs/git-reflog)
- [Git restore](https://git-scm.com/docs/git-restore)

### Completion status

Cycle 15 delivered both commands, versioned durable manifests, conservative
legacy inventory, explicit no-overwrite restoration, rooted recursive copy and
removal, workspace-lock serialization, escaped human output, stable JSON, and
the documented local-only synchronization boundary. The deterministic pre-fix
namespace escape now fails without removing the outside victim; source-file
and source-directory replacement regressions bind reads to opened descriptors.

Focused repetitions, race repetitions, coverage, and copy/list benchmarks
pass. The complete formatting, module, unit, vet, Darwin cross-build, static
agent, race, gosec, govulncheck, eight-target fuzz, ShellCheck, Python syntax,
and release snapshot gates pass. Release archives, checksums, embedded agent,
documentation, completions, and three SPDX 2.3 SBOMs were inspected. The
existing Lima scenario now restores a real remote losing copy, but no Lima VM
or SSH configuration is installed in this audit environment, so that assertion
was not executed locally.

## 21. Continuous-improvement roadmap — Cycle 16

### Product and technical assessment

Cycle 15 contained local conflict mutations below held filesystem roots, but a
remote losing copy still crosses three independent pathname resolutions: a
shell parent check, SCP, and shell `rm -rf`. A deterministic reproduction
backed up the expected object, replaced its checked parent with an outside
symlink, and made the final deletion remove the outside replacement. Merely
moving deletion into the agent would contain escape but would not establish
that the client durably received the streamed object before deletion.

OpenSSH transports remote standard input/output without a PTY. Go's `archive/tar`
is sequential, permitting arbitrary-size trees with bounded memory, while its
reader documentation explicitly requires callers to reject non-local names.
Rsync's documented `--remove-source-files` model removes only successfully
duplicated sender files and skips removal when source size or modification time
changes. POSIX Issue 8 defines descriptor-relative directory operations and
atomic rename/unlink calls, but exposes no portable conditional unlink by inode;
Pwnbridge must therefore combine acknowledgement, a second content pass,
identity checks, and rooted removal while documenting the final in-root race.

Ranked opportunities:

| Rank | Opportunity | User value / severity | Fit | Effort / risk | Evidence and decision |
|---:|---|---|---|---|---|
| 1 | Acknowledged agent-streamed remote backup and rooted removal | High / high security | Very high | High / high | Removes SCP/shell pathname escape and makes local durability precede deletion; selected |
| 2 | Recovery content digests and restore verification | High / medium | Very high | Medium / low | The stream already needs an end-to-end digest; integrate it into manifests and restore rather than add a separate partial feature |
| 3 | Automatic recovery retention/pruning | Medium / low | Medium | Medium / high | Still no capacity or policy evidence and automatic deletion conflicts with recovery's purpose; defer |
| 4 | Redacted support bundle | Medium / low | Medium | Medium / high | Disclosure-safe field classification remains unresolved; defer |
| 5 | Remote delta transfer | Low / low | Low | High / high | Conflict losers are exceptional, correctness-sensitive transfers; complexity is not justified by throughput evidence |

### Selected feature and acceptance criteria

Replace remote SCP plus shell deletion with one acknowledged agent session:

1. Bump the client/agent protocol and add a typed recovery request, client
   acknowledgement, and result. Run over a verified content-addressed agent and
   one private SSH control master with no PTY. Bound request, acknowledgement,
   result, and stderr control data independently from unbounded file content.
2. Stream a deterministic uncompressed tar containing only one regular file,
   directory tree, or symbolic link. Traverse sorted names through nested
   `os.Root` descriptors; open regular files nonblocking; bind identity, size,
   mode, and mtime before/after each exact-length read; preserve permission bits
   and raw link targets; reject special files. Do not retain whole files or the
   whole archive in memory.
3. On the client, accept only canonical local tar names, one root entry,
   parent-before-child ordering, unique paths, known regular/directory/symlink
   types, bounded names/link targets, sane modes/sizes, no sparse/PAX/device or
   hard-link metadata, and at most one million entries. Extract below a held
   recovery root with exclusive creation, exact-length writes, partial cleanup,
   and file/directory durability syncs.
4. Hash every byte of the deterministic tar and its fixed completion trailer at
   both endpoints. Persist the
   local manifest and its digest before sending an acknowledgement. EOF,
   extraction, fsync, manifest, digest, cancellation, or SSH failure before the
   acknowledgement must leave the remote loser untouched.
5. After acknowledgement, regenerate the deterministic digest from the current
   remote path and compare it with the streamed digest, recheck the top object's
   descriptor identity, then use rooted recursive removal and sync its parent.
   A changed source fails closed. If deletion succeeds but the response is lost,
   retain and report the already durable local recovery copy.
6. Store archive SHA-256 in all new recovery manifests. Compute it for local
   losers as well, validate it before every restore, expose it in human/JSON
   inventory, and keep legacy/schema-compatible entries usable without falsely
   claiming verification.
7. Reuse one agent/master for all selected conflicts, preserve exact conflict
   validation and workspace locking, remove the remote shell parent-check/SCP/
   `rm -rf` path, and close the master on every error/cancellation path.
8. Add pipe-level handshake tests, deterministic archive/digest tests, hostile
   tar tests, no-ack and digest-mismatch preservation, namespace replacement,
   large streaming/allocation coverage, client error cleanup, CLI discovery,
   and a real Lima remote-loser recovery assertion. Update architecture,
   security, CLI, troubleshooting, development, and protocol-path documentation.
9. Run formatting, module verification, focused repetitions, all tests, vet,
   Darwin cross-builds, static agent checks, race tests, security scans, fuzz
   smoke, ShellCheck, realistic streaming benchmarks, and the release snapshot.

### Risks and mitigations

- Tar readers have a broad compatibility surface. The agent emits a deliberately
  tiny deterministic subset and the client validates every header itself rather
  than relying on `GODEBUG=tarinsecurepath`. Sparse, PAX, hard-link, device,
  FIFO, ownership, timestamp, and extended metadata are rejected.
- The client and agent wait on each other mid-command. Tar end markers plus a
  fixed application trailer form the acknowledgement boundary, all control frames are bounded, context
  cancellation closes pipes, and pipe tests cover truncation and no-ack paths.
- Integrity verification reads the remote loser twice and local restore reads
  recovery content again. This is intentional for a rare destructive operation;
  benchmarks will quantify the cost and no content is buffered wholesale.
- There is no POSIX conditional recursive unlink by previously observed inode.
  A same-account process can still replace an object inside the remote root
  after the final comparison and before rooted removal. The narrowed operation
  cannot escape the held root; the residual is documented rather than obscured.
- Unbounded content can exhaust local recovery storage. Streaming keeps memory
  bounded, exclusive extraction removes partial output on failure, and remote
  deletion is withheld until local fsync and manifest completion.
- A link target may point outside a workspace when later followed. It is stored
  and restored as link metadata only; Pwnbridge never dereferences it during
  backup, hashing, or extraction.

### Research references

- [Go `archive/tar`](https://pkg.go.dev/archive/tar)
- [Go traversal-resistant filesystem APIs](https://go.dev/blog/osroot)
- [OpenSSH `ssh(1)`](https://man.openbsd.org/ssh.1)
- [POSIX Issue 8 directory-operation atomicity](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [POSIX Issue 8 descriptor-relative rename](https://pubs.opengroup.org/onlinepubs/9799919799/functions/rename.html)
- [rsync `--remove-source-files`](https://download.samba.org/pub/rsync/rsync.1)

### Completion status

Cycle 16 replaced the remote conflict-loser SCP/check/`rm -rf` sequence with a
single no-PTY agent stream over one private control master. Protocol 4 carries
the request, durable digest acknowledgement, and exact result. The sorted GNU
tar subset supports regular files, directories, empty directories, and raw
symlinks; a fixed trailer makes generation failure distinguishable from a
complete prefix. Both emission and extraction traverse held `os.Root`
descriptors, bound entries/names/links/control data, reject all unowned
metadata and special types, use constant-memory exact reads, and sync every
created file and directory before cataloging.

New and local conflict backups receive deterministic SHA-256 identities. The
agent does not remove a remote loser until the manifest is durable and its ACK
matches, then regenerates the entire identity and rechecks the original top
object before rooted deletion. Restoration verifies the recovery source and
the completed destination; old schema-one and pre-manifest entries remain
usable but are clearly `unverified`. Human and JSON inventory expose digests,
and post-ACK transport ambiguity reports the durable backup path.

The pre-fix parent-symlink reproduction no longer reaches the outside victim.
Round-trip, special-file prefix, truncated stream, hostile header, traversal,
duplicate, ordering, replacement, no-ACK, mismatched-ACK, changed-source,
strict-result, bounded-stderr, same-size tamper, legacy compatibility, and real
subprocess handshake regressions pass. Recovery archive fuzzing was added to
the standard smoke matrix.

The complete unit, vet, formatting, module, race, 20-repeat focused, nine-target
fuzz, gosec, govulncheck, ShellCheck, cross-build, artifact-size, dependency
separation, release snapshot, checksums, archive inventory, and three SPDX 2.3
SBOM validations pass. Recovery/CLI/agent coverage is 75.7/39.5/35.2 percent.
One MiB streaming measures about 0.97 ms and 35 KiB/29 allocations; durable
extract-and-remove measures about 1.33 ms and 36 KiB/60 allocations. Snapshot
binaries are 8.215 MiB Darwin arm64, 8.722 MiB Darwin amd64, and 3.305 MiB Linux
agent. No Lima configuration, actionlint, or Ruby YAML tooling is installed in
this environment; the updated Lima assertion is therefore documented but not
executed, while the same protocol completed through an actual subprocess and
OS pipes locally.

## 22. Continuous-improvement roadmap — Cycle 17

### Product and technical assessment

Pwnbridge has detailed `doctor`, `status`, synchronization, recovery, and
bootstrap commands, but its reporting guide still asks a user to manually
collect version/platform/runtime/provider information and redact it. The raw
commands are not designed for sharing: they can include local executable and
project paths, SSH aliases/destinations, remote paths, workspace/session IDs,
conflict names, and raw command errors. Bootstrap/Mutagen logs can additionally
contain challenge output. This makes a common failure journey—asking for
help—both tedious and disclosure-prone.

The public repository currently has zero open or closed issues and restricts
issue creation, so no issue backlog provides a higher-priority user signal.
Docker's official support documentation warns that diagnostic bundles can
contain usernames and IP addresses; a recent Docker release specifically fixed
credential-adjacent data being bundled. OWASP recommends excluding or masking
session IDs, tokens, file paths, and internal names/addresses. Kubernetes
demonstrates stdout-first diagnostic dumps but includes broad logs. For this
small security-oriented tool, an explicit field allowlist and no log collection
is safer than post-hoc regex redaction or a binary archive.

Ranked opportunities:

| Rank | Opportunity | User value / severity | Fit | Effort / risk | Evidence and decision |
|---:|---|---|---|---|---|
| 1 | Privacy-allowlisted support report | High / medium security | Very high | Medium / medium | Existing reporting workflow is manual and raw diagnostics disclose identifiers; selected |
| 2 | Recovery integrity `verify` command | Medium / medium | High | Low / low | Borg/restic expose explicit checks and Pwnbridge now has digests; valuable next, but restore already verifies before use |
| 3 | Doctor partial-results/time-budget redesign | Medium / medium | High | Medium / medium | Support report will establish safe partial collection; avoid changing established doctor exit/output behavior simultaneously |
| 4 | Mutagen daemon-log descriptor hardening | Low / medium security | High | Low / low | Private XDG parent reduces exposure; retain for a focused hardening follow-up after user workflow work |
| 5 | Automatic recovery pruning | Medium / low | Medium | Medium / high | Still lacks a defensible retention/capacity policy and deletes the very data recovery promises to preserve |

### Selected feature and acceptance criteria

Deliver `pwnbridge support [--json] [--local-only]` end to end:

1. Always emit a useful report when base XDG setup and stdout are available,
   even if project/global configuration, Mutagen status, recovery inventory, or
   remote SSH collection fails. Represent collection availability and a small
   safe error category instead of returning raw errors or suppressing all data.
2. Use typed report structs and a positive allowlist. Include client/build/
   protocol/schema/required-Mutagen and Go/platform versions; safe effective
   behavior (sync/runtime/provider category/scope); counts rather than names;
   coarse sync/recovery state; and safe remote platform/capability inventory.
3. Never include local/home/project/executable/state paths, host names, SSH
   aliases or addresses, remote roots, workspace/machine/session/runtime IDs,
   config/environment keys or values, shell commands, container image names,
   conflict/original recovery paths, logs, tokens, command output, or raw error
   strings. Collapse custom provider identity to `custom`.
4. Perform remote collection through the existing ordinary read-only bootstrap
   inventory—no agent deployment, sudo, repository refresh, probe file, or
   remote write—and give local, status, and remote probes independent finite
   deadlines. `--local-only` must perform no SSH operation.
5. Default output is concise line-oriented Markdown suitable for issue text.
   `--json` uses the standard schema-one envelope and identical typed fields.
   Both explicitly state the privacy exclusions and still tell users to review
   before sharing; no report is uploaded or persisted automatically.
6. Add sentinel-based privacy regressions covering every forbidden data class,
   malformed config partial output, unavailable Mutagen/SSH, hostile remote
   inventory text/control bytes, deterministic ordering, JSON schema, command
   discovery, local-only behavior, and output write failure.
7. Document discovery, field meanings, partial/error semantics, network side
   effects, privacy boundary, review responsibility, and the distinction from
   full local logs. Update reporting guidance and realistic E2E discovery.
8. Measure collection/output overhead and run formatting, modules, all unit and
   race tests, vet, repeated privacy tests, fuzzing where a new parser exists,
   security scans, ShellCheck, cross-builds, release snapshot, checksums, and
   SBOM validation. Independently review product, architecture, security, QA,
   performance, UX, operations, and documentation before Cycle 18.

### Risks and mitigations

- Regex redaction can miss novel secrets. The report never serializes broad
  source objects or logs; every output field is constructed from primitives on
  a reviewed allowlist, and sentinel tests scan both renderings.
- Distro/version strings originate remotely. Accept only closed distro/tool/
  service vocabularies and numeric version grammars; replace anything else
  with `unavailable` instead of escaping attacker-controlled diagnostic text.
- A support command that fails with the broken subsystem is not useful. Each
  collector is independent, bounded, and records only availability/category;
  the report itself fails only for base setup or output failure.
- Remote inventory creates network traffic and can prompt according to normal
  OpenSSH policy. Document this and provide `--local-only`; the remote script is
  the already-reviewed read-only bootstrap inventory.
- Omitting identifiers can reduce forensic detail. Keep full private logs and
  existing raw commands available locally; the support report deliberately
  optimizes for a safe first public exchange, after which a user can provide a
  specifically requested field through a private channel.

### Research references

- [Docker support diagnostic-data privacy](https://docs.docker.com/support/)
- [Docker Desktop troubleshooting and diagnostic bundles](https://docs.docker.com/desktop/troubleshoot-and-support/troubleshoot/)
- [Docker Desktop release notes](https://docs.docker.com/desktop/release-notes/)
- [OWASP Logging Cheat Sheet: data to exclude](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Kubernetes `cluster-info dump`](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_cluster-info/kubectl_cluster-info_dump/)
- [Borg `check`](https://borgbackup.readthedocs.io/en/latest/usage/check.html)
- [restic integrity troubleshooting](https://restic.readthedocs.io/en/stable/077_troubleshooting.html)
- [Pwnbridge public issue index (zero issues)](https://github.com/simonfalke-01/pwnbridge/issues)

### Completed implementation

- Added `pwnbridge support [--json] [--local-only]` as a first-class command.
  It emits either concise issue-ready Markdown or the standard schema-one JSON
  envelope and explicitly states both its positive-allowlist posture and the
  need to review output before sharing.
- Added a dedicated typed `internal/support` model and renderer. Collection
  copies only reviewed scalar summaries; it never serializes configuration,
  workspace/state, Mutagen, recovery-entry, error, command-output, or bootstrap
  inventory source objects.
- Local configuration, platform/tool availability, workspace sync health,
  recovery counts, and remote inventory are independent partial collectors.
  Configuration errors become safe categories; local, sync-status, and remote
  work have 10/10/20-second deadlines. `--local-only` returns before any SSH
  construction or execution.
- All configuration behavior maps through closed vocabularies or canonical
  values. Custom terminal providers and user-defined container networks become
  `custom`; environment-controlled log text cannot escape the log-level
  vocabulary. Release, commit, build-date, Go, distro, service, libc, package,
  tool, and version fields use narrow field-specific grammars. Snapshot release
  metadata supports only the known `X.Y.Z-SNAPSHOT-<hex>` form; that parser is
  now a fuzz target.
- Remote collection reuses only `bootstrap.Inspect`: no agent deployment, sudo,
  package action, probe file, or remote write. The post-implementation audit
  found that its SSH deadline still retained unbounded output. Added
  `transport.Client.RawBounded`, which concurrently drains stdout/stderr while
  retaining at most 1 MiB, reports overflow without raw discarded content, and
  now protects support, doctor, and bootstrap inventories.
- Added forbidden-value sentinels for host/destination/root/path, ignore and
  environment names/values, custom provider and network names, image and tool
  paths, log-level text, sync status/conflict names, recovery original paths,
  raw SSH errors, hostile inventory fields, and unknown capability labels.
  Both output modes, invalid-config partial output, local-only network
  exclusion, schema/discovery, deterministic rendering, output failures,
  bounded hostile SSH output, and release grammars have regressions.
- Updated the README, CLI, architecture, troubleshooting, security, and
  development guides plus the realistic Lima scenario. The report is described
  as a safe first exchange rather than a replacement for private raw logs.

### Validation and measurements

- The privacy-focused CLI/support suite passed 20 consecutive repetitions;
  the new support renderer reached 98.2% statement coverage. Collector
  functions are predominantly 80–100% covered (`collectSupportReport` 84.1%,
  workspace 80%, configuration/project/capability/remote mapping 100%).
- Markdown rendering measures 4.48–5.21 microseconds, 2,544 bytes, and 24
  allocations. Twenty isolated `support --local-only --json` processes averaged
  8.74 milliseconds including startup and local executable/version probes.
  Typical first-run JSON/Markdown outputs are 2,088/1,050 bytes.
- The hostile 2 MiB inventory regression retains exactly the 1 MiB limit and
  fails safely; focused transport/bootstrap overflow tests passed ten
  race-enabled repetitions.
- `make verify` passed formatting, module verification, all package tests, vet,
  dependency separation, and final cross-builds of 8,629,058-byte Darwin arm64,
  9,077,904-byte Darwin amd64, and 5,026,691-byte Linux agent binaries.
  `make test-race` passed every package. ShellCheck 0.11.0 and `bash -n` passed
  every shell script.
- All ten five-second native fuzz targets passed, including hostile recovery
  archives and the new support release-version grammar. Gosec completed cleanly
  and `govulncheck` reported `No vulnerabilities found`.
- The final GoReleaser snapshot completed with Go 1.26.5. All archive checksums,
  tar reads, and Syft 1.44.0 SBOM conversions passed. Stripped binaries measure
  8.264 MiB Darwin arm64, 8.778 MiB Darwin amd64, and 3.305 MiB Linux amd64.
  Lima remains unavailable in this environment, so the updated full remote E2E
  assertion is documented but not executed.

### Independent post-implementation audit

- **Product:** the command completes the public-help workflow with materially
  less manual redaction and without adding an archive/upload subsystem.
- **Architecture:** a small typed package and collector-specific mappings keep
  raw subsystem objects outside the serialization boundary; no new dependency
  was added.
- **Security:** review caught and fixed free-form log/network/build metadata and
  the deadline-only remote-output memory risk. Coarse counts, booleans, sizes,
  and allowlisted versions remain intentional disclosures, so review-before-
  sharing stays explicit.
- **QA:** partial failures, malformed inputs, hostile remote text/output,
  cancellation/error categories, both renderings, discovery, and write failure
  are covered. Actual Lima SSH remains the only unavailable validation layer.
- **Performance:** local collection is single-digit milliseconds on this host;
  remote latency dominates. Output and retained SSH memory are now bounded.
- **UX:** default text is short and pasteable, JSON is stable, network behavior
  is discoverable, and `--local-only` gives a clear no-SSH path.
- **Operations:** collection neither deploys nor elevates remotely; timeouts,
  partial results, release packaging, checksums, and SBOMs are verified.
- **Documentation:** discovery, semantics, exclusions, side effects, failure
  behavior, and private-log distinction are covered across user and security
  guides.

Residual risks are explicit: default remote collection may trigger ordinary
OpenSSH authentication or host-key interaction, so `--local-only` remains the
safe offline choice; an allowlist cannot prove that every coarse fact is
non-sensitive for every challenge, so users must still review output; and the
report deliberately omits forensic identifiers that may later need to be
shared individually through an appropriate private channel.

## 23. Continuous-improvement roadmap — Cycle 18

### Product and technical assessment

Conflict recovery now has durable manifests, deterministic SHA-256 identities,
offline inventory, and verified restore. Its remaining user-journey gap is
proactive assurance: `list` only prints the recorded digest and the first full
content check occurs while restoring. Corruption, accidental editing, missing
content, or an unreadable tree can therefore remain latent until an urgent
recovery attempt. The existing deterministic descriptor-rooted archive digest
already provides the necessary primitive, so an explicit check requires no new
format, daemon, dependency, or configuration.

Current authoritative comparisons consistently make integrity checking an
explicit read-only workflow. Borg `check --verify-data` reads and
cryptographically verifies archive data and is read-only unless the dangerous
`--repair` option is separately selected. Restic recommends `check --read-data`
to detect damaged content and warns that full verification reads the entire
repository. Git `fsck` distinguishes fast connectivity checking from full blob
validation. GNU Coreutils provides checksum verification with nonzero status on
failure. Pwnbridge is much smaller, but should likewise make the full-byte cost,
read-only behavior, incomplete legacy coverage, per-entry results, and process
status explicit.

Ranked opportunities:

| Rank | Opportunity | User value / severity | Strategic fit | Effort / risk | Evidence and decision |
|---:|---|---|---|---|---|
| 1 | `sync recovery verify` | High reliability / medium | Very high | Low / low | Digests already exist but latent damage is found only during restore; selected as an end-to-end recovery workflow |
| 2 | Mutagen daemon-log descriptor hardening | Low user / medium local security | High | Low / low | Fallback startup still uses path-based stat/rename/append; owner-private XDG state and no remote access reduce urgency |
| 3 | Doctor partial-result/time-budget redesign | Medium / medium | High | Medium / medium | Support established safe partial collectors, but changing established doctor output/exit behavior needs separate UX design |
| 4 | Bound other SSH command outputs | Medium reliability / medium | High | Medium / medium | Inventory is now bounded; general commands have different output semantics and need per-operation limits rather than a global truncation |
| 5 | Automatic recovery pruning | Medium / low | Medium | Medium / high | Deletion policy remains hard to justify and conflicts with preservation; verify is safer and more directly evidenced |

### Selected feature and acceptance criteria

Deliver `pwnbridge sync recovery verify [ID...] [--json]` end to end:

1. With no IDs, verify every currently listed recovery copy in deterministic
   inventory order. With IDs, require exact listed IDs, preserve request order,
   reject duplicates/invalid identifiers, and fail before hashing if any ID is
   unknown.
2. Operate entirely on the local recovery catalog: no SSH, Mutagen status or
   resume, workspace content change, manifest rewrite, digest enrollment,
   repair, deletion, or other side effect. Hold the existing workspace lock so
   conflict resolution cannot mutate the catalog during a check.
3. For every cataloged digest, regenerate the deterministic descriptor-rooted
   archive identity and compare SHA-256 plus kind, mode, byte, and item metadata.
   Continue checking later entries after an individual mismatch or read error.
4. Add context-aware digesting so Ctrl-C/caller cancellation interrupts the
   full-byte scan. Keep verification sequential to avoid saturating local disk
   and memory; document that runtime is proportional to stored content.
5. Report `verified`, `failed`, or `unverified` for each selected entry plus
   aggregate counts and completeness. Legacy/pre-digest entries are never
   silently blessed: mark them `unverified` and return nonzero because the full
   requested assurance was incomplete. Any failed entry also returns nonzero.
6. Default human output must safely quote IDs and give a concise stable reason;
   JSON uses the normal schema-one envelope with the same per-entry results and
   aggregate counts. Buffer human output and propagate output write failures.
7. Cover regular files, directory trees, symlinks, tampering that preserves
   structural metadata, unavailable digests, selected/all ordering, duplicate/
   unknown IDs, continuation after failure, cancellation, output errors,
   command discovery, JSON, no SSH/Mutagen invocation, and empty inventory.
8. Update README, CLI, troubleshooting, architecture, security, development,
   and realistic E2E guidance. State clearly that SHA-256 detects accidental or
   one-sided modification but is not authenticated against the same local
   account.
9. Benchmark representative file/tree verification and run formatting, module
   verification, all unit/race tests, vet, focused repetition, fuzzing, security
   scans, ShellCheck, cross-builds, final release snapshot, checksums, archives,
   and SBOM validation. Perform the eight-perspective independent audit before
   immediately starting Cycle 19.

### Risks and mitigations

- A full integrity check is I/O proportional to recovery size and can hold the
  workspace lock for a long time. Document the cost, check sequentially, emit a
  result per completed entry, and make archive writes context-aware so
  cancellation returns promptly.
- A same-user process can alter both manifest and data, so matching SHA-256 is
  not proof against a malicious local account. Preserve the existing threat
  statement and describe verification as accidental/one-sided corruption
  detection.
- Legacy entries lack a trusted digest. Computing a new digest would only
  describe their current state, not verify historical integrity; do not mutate
  or enroll them implicitly, and make incompleteness machine-visible.
- The catalog can change concurrently with conflict resolution. Acquire the
  existing workspace lock before listing/selecting and retain it through the
  scan; do not invent a second recovery lock.
- A corrupt manifest can prevent safe enumeration before per-entry checks.
  Treat structural/catalog corruption as a fatal inventory error rather than
  guessing at boundaries or accepting unverifiable paths.

### Research references

- [Borg `check` data verification and read-only default](https://borgbackup.readthedocs.io/en/latest/usage/check.html)
- [Restic damaged-data workflow](https://restic.readthedocs.io/en/stable/077_troubleshooting.html)
- [Restic full/subset data-check cost](https://restic.readthedocs.io/en/v0.15.2/045_working_with_repos.html)
- [Git `fsck` full versus connectivity-only validation](https://git-scm.com/docs/git-fsck)
- [GNU SHA-2 checksum verification](https://www.gnu.org/software/coreutils/sha256sum)
- [Go traversal-resistant `os.Root` guidance](https://go.dev/blog/osroot)
- [Mutagen isolated/hosted daemon model](https://mutagen.io/documentation/introduction/daemon/)
- [OWASP file-log permission and failure guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

### Completed implementation

- Added `pwnbridge sync recovery verify [ID...] [--json]`. No IDs checks all
  entries newest-first; explicit exact IDs retain argument order and duplicate,
  invalid, or unknown IDs fail before content hashing.
- Verification loads the host-scoped local recovery catalog and holds the
  existing workspace lock through selection and scanning. It never constructs
  an SSH or Mutagen command, changes workspace/synchronization state, rewrites a
  manifest, enrolls a digest, repairs, deletes, or restores content.
- Added `recovery.DigestContext` and `recovery.Verify`. The deterministic
  descriptor-rooted archive stream now observes caller cancellation on output
  writes; verification compares SHA-256, type, permissions, total bytes, and
  item count for files, directories, and links.
- Kept ordinary `recovery.List` fail-closed against current structural mismatch,
  but added `ListForVerification`, which validates catalog structure and returns
  recorded metadata without first requiring current content to match. This
  independent-review correction lets a changed-size/mode/type entry be reported
  as failed while later entries are still read. Corrupt manifest syntax or
  boundaries remain a fatal inventory error.
- Human output quotes arbitrary IDs, uses stable `verified`, `failed`, and
  `unverified` states/reasons, and ends with aggregate counts/completeness. JSON
  carries identical typed data in the schema-one envelope. Failed reads or
  integrity mismatches and legacy/pre-digest entries produce nonzero status;
  JSON/human results are still emitted. Buffered human output propagates its
  single write error.
- Added coverage for all supported types, recorded metadata and same-size
  content changes, changed structural metadata, missing/unreadable content,
  continuation, exact and all-entry ordering, duplicate/unknown/escaping IDs,
  control-bearing ID rendering, legacy incompleteness, empty inventory,
  cancellation, command discovery, JSON, output failure, and explicit proof
  that SSH/Mutagen are not invoked.
- Updated README, CLI, troubleshooting, architecture, security, development,
  and Lima E2E guidance. Documentation states full-byte/lock cost, nonzero
  incomplete semantics, no-repair/no-enrollment behavior, and the
  non-authenticated same-account threat boundary.

### Validation and measurements

- Focused recovery/CLI verification tests passed 20 repetitions in 0.061/0.198
  seconds, and the focused structural/CLI suite passed ten race repetitions.
  The recovery package has 76.8% statement coverage; `Digest`,
  `DigestContext`, `Verify`, `List`, and `ListForVerification` are 100% covered.
  CLI selection, verification aggregation, rendering, and incomplete-status
  functions are 100% covered; command construction is 80.9% covered.
- A 1 MiB regular-file verification measures 0.99–1.06 milliseconds, about
  35.7 KiB, and 40 allocations. A 100-file/100 KiB tree measures 1.87–1.93
  milliseconds, about 293.6 KiB, and 3,058 allocations. The cost is linear I/O
  and deterministic tar metadata construction; no parallelism was added.
- `make verify` passed formatting, module verification, all package tests, vet,
  dependency separation, and cross-builds of 8,645,954-byte Darwin arm64,
  9,094,688-byte Darwin amd64, and 5,026,811-byte Linux agent binaries.
  `make test-race` passed every package.
- All ten five-second fuzz targets passed. Gosec completed cleanly,
  `govulncheck` reported `No vulnerabilities found`, and ShellCheck 0.11.0 plus
  `bash -n` passed every script.
- The GoReleaser snapshot completed with Go 1.26.5; all six checksums, three tar
  reads, and three Syft 1.44.0 SBOM conversions passed. Stripped binaries are
  8.280 MiB Darwin arm64, 8.794 MiB Darwin amd64, and 3.305 MiB Linux amd64.
  Lima remains unavailable, so the updated actual remote recovery verification
  assertion is documented but not executed here.

### Independent post-implementation audit

- **Product:** proactive verification closes the recovery journey between
  inventory and emergency restore with an evidenced, familiar integrity-check
  workflow rather than speculative backup management.
- **Architecture:** the command reuses deterministic archives, rooted I/O,
  catalog types, workspace locking, and JSON conventions; no dependency,
  format, daemon, or configuration was added. A narrow verification inventory
  view preserves strict ordinary listing while enabling per-entry failures.
- **Security:** the operation is read-only, no-follow/root-bounded, does not
  bless legacy data, and preserves structural catalog fail-closed behavior.
  SHA-256 remains explicitly non-authenticated against the same account.
- **QA:** review caught the original fail-fast listing conflict and added
  structural-mismatch continuation. Supported types, malformed selection,
  missing data, legacy entries, cancellation, output, automation, and no-network
  behavior are covered; external Lima remains the only unavailable layer.
- **Performance:** measured full-byte cost is low for representative conflict
  artifacts, sequential checking avoids disk saturation, and cancellation
  interrupts hashing. Very large first entries still provide no live progress
  until the buffered report is emitted.
- **UX:** all-vs-selected semantics are simple, IDs are copyable from `list`,
  states/reasons and summary are stable, and JSON plus exit status support
  automation. Incomplete legacy assurance is not disguised as success.
- **Operations:** the existing cross-process workspace lock prevents concurrent
  catalog mutation, all package/release/security gates pass, and no repair or
  retention policy is introduced.
- **Documentation:** discovery, cost, locking, cancellation, status semantics,
  side-effect boundary, recovery workflow, and threat limits are documented.

Residual risks: verification is a point-in-time read and a same-user attacker
can alter both manifest and content; a corrupt manifest prevents safe inventory
and remains fatal; legacy entries cannot gain historical assurance without an
explicit future enrollment design; and a very large check holds the workspace
lock and buffers results until completion, although Ctrl-C cancels it. These are
preferable to implicit repair, guessed boundaries, or silently trusting current
legacy content.

## 24. Continuous-improvement roadmap — Cycle 19

### Product and technical assessment

The highest current risk is in the isolated Mutagen daemon's compatibility
fallback. `StartDaemon` first invokes the documented fast/idempotent `daemon
start`, then falls back to the documented hidden `daemon run` embedding entry
point. If the caller's context expires during the first command, the current
code nevertheless starts and releases the fallback process. A cancelled first
run can therefore leave an unexpected detached daemon behind. The fallback log
also uses path-based `Stat`, ignored rotation failures, and ordinary `OpenFile`:
a final symlink is followed, opening a FIFO for write can block indefinitely,
an unsafe existing mode/owner is accepted, and rotation is not tied to the file
descriptor that was validated. This is a user-visible startup/recovery failure
path, not merely cosmetic log cleanup.

Repository history emphasizes interactive remote workflows and bootstrap
polish, while the audit has now completed recovery inventory, restore, and
verification end to end. The next product gap is richer partial-result `doctor`
diagnostics, but changing its public output and timeout composition has broader
compatibility risk. Securing daemon fallback is smaller, independently
verifiable, and removes both a hang primitive and a lifecycle violation before
more diagnostic work depends on this startup path.

| Rank | Opportunity | User value / severity | Strategic fit | Effort / risk | Evidence and decision |
| --- | --- | --- | --- | --- | --- |
| 1 | Cancellable, descriptor-safe Mutagen fallback startup | High reliability / medium local security | High | Low / low | Current code detaches after cancellation and follows/blocks on unsafe log objects; implement now |
| 2 | Partial-result `doctor` with bounded independent probes | High diagnostic value / medium reliability | High | Medium / medium | Support-report collectors established the pattern; retain as the leading Cycle 20 product candidate |
| 3 | Per-operation SSH output bounds beyond inventory | Medium reliability / medium availability | High | Medium / low | Raw inventory, bootstrap, and doctor are bounded; audit remaining call sites after daemon startup |
| 4 | Automatic recovery retention/pruning | Medium convenience / medium destructive risk | Medium | Medium / high | Explicit list/restore/verify is safe; retention policy still lacks enough evidence to delete user recovery data |
| 5 | Live progress for very large recovery verification | Medium UX / low correctness | Medium | Medium / medium | Current checks are cancellable and measured fast for representative artifacts; buffered output remains documented |

This cycle selects a meaningful operational product improvement: cancellation
must mean that Pwnbridge does not create a new background service, and corrupt
or adversarial log entries must fail promptly with an actionable error instead
of hanging or appending elsewhere. No new dependency, configuration knob,
daemon protocol, or user-facing command is justified.

### Acceptance criteria and implementation plan

1. Preserve the normal `mutagen daemon start` attempt and return immediately on
   success. If its context is cancelled or its deadline expires, return that
   context error and never invoke `daemon run`.
2. Keep Mutagen's socket-length alias for the child environment, but anchor log
   operations in the actual configured data directory rather than the mutable
   temporary symlink alias.
3. Add a narrow reusable filesystem primitive that opens an owner-private
   directory with `O_DIRECTORY|O_NOFOLLOW`, opens the log relative to that
   descriptor with `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, and accepts only a regular
   file owned by the current user with no group/other permissions.
4. Rotate an existing log only above the current 5 MiB startup threshold. Use
   descriptor-relative rename, verify device/inode before and after rename, and
   surface every validation/rotation error. Preserve one `.previous` generation
   and atomically replace its directory entry without following it.
5. Pass the verified descriptor directly to both child output streams. On child
   start failure, close it and return a contextual error; on success, release
   the process only after startup and close the parent's duplicate.
6. Cover normal daemon-start success, fallback success, pre-cancelled and
   deadline cancellation, symlink/FIFO/non-private/wrong-type logs, private
   directory validation, oversized rotation, unsafe rotation destinations,
   no alias-target append, command-start failure, environment isolation, and
   prompt failure rather than blocking.
7. Document the isolated daemon log location, owner-private validation,
   startup-only 5 MiB rotation semantics, recovery steps for an unsafe entry,
   and cancellation behavior. Do not imply a hard runtime cap while the
   detached daemon owns its descriptor.
8. Format and run focused repetition/race tests, full module verification,
   vet, all tests/race tests, fuzzing, gosec, govulncheck, ShellCheck, cross
   builds, and a release snapshot with checksum/archive/SBOM validation. Record
   startup/rotation measurements and perform the eight-perspective independent
   audit before immediately beginning Cycle 20.

### Risks and mitigations

- Mutagen documents `daemon run` as a directly hosted child, while Pwnbridge
  intentionally releases it so the daemon survives the short CLI process. Keep
  this established behavior, but make the handoff boundary explicit: context is
  honored before start; after successful process creation, later CLI
  cancellation must not kill the service.
- The daemon can continue writing beyond 5 MiB after it is detached. Calling
  this a hard cap would be false, and piping through the short-lived parent
  would break daemon lifetime. Retain and document startup rotation only.
- POSIX rename replaces an existing destination atomically. Descriptor-relative
  operation and inode verification prevent path escape or silent source swaps;
  an existing destination directory remains an error rather than being removed.
- A process with the same UID can still race or alter Pwnbridge state and has no
  privilege boundary from Pwnbridge. Fail closed on detected inode changes and
  preserve the documented same-account threat limit rather than adding locks or
  platform-specific complexity that cannot create isolation.
- `os.Root` received a July 2026 trailing-slash advisory before Go 1.25.12. The
  audit toolchain is patched, but this primitive uses direct `openat` operations
  on fixed basenames and no trailing slash, avoiding dependency on that edge
  case while retaining Darwin/Linux portability.

### Research references

- [Mutagen daemon lifecycle and embedding](https://mutagen.io/documentation/introduction/daemon/)
- [Linux `open(2)` `O_NOFOLLOW`, `O_NONBLOCK`, and FIFO semantics](https://man7.org/linux/man-pages/man2/open.2.html)
- [Linux/POSIX `rename(2)` replacement and descriptor semantics](https://man7.org/linux/man-pages/man2/rename.2.html)
- [Go traversal-resistant filesystem guidance](https://go.dev/blog/osroot)
- [Go `os.Root.Rename` documentation](https://pkg.go.dev/os#Root.Rename)
- [Go July 2026 `os.Root` advisory GO-2026-4970](https://pkg.go.dev/vuln/GO-2026-4970)

### Completed implementation

- `StartDaemon` now returns a pre-existing cancellation before creating state,
  and returns cancellation/deadline errors after the normal launcher failure
  and immediately before fallback process creation. It cannot intentionally
  detach `daemon run` after the caller's startup budget expires.
- The actual Mutagen data directory is created and then opened with
  `O_DIRECTORY|O_NOFOLLOW`; it must be owned by the current user and have no
  group/other permissions before either launcher executes. A long socket-path
  alias is revalidated after the normal launcher fails, closing a discovered
  alias-swap interval before fallback.
- Added `fsutil.ValidatePrivateDirectory` and
  `OpenPrivateRotatingAppendFile`. The latter anchors all file operations to a
  held directory descriptor, uses no-follow/nonblocking/close-on-exec append,
  validates owner/type/mode and current device/inode, and returns the exact
  opened descriptor for child stdout/stderr.
- Logs above 5 MiB at fallback startup are renamed descriptor-relatively to one
  `.previous` generation. The opened source inode is verified after rename; a
  previous symlink is replaced as an entry without touching its target, while
  an existing destination directory or any other rotation error fails closed.
- Fallback process creation now reports contextual start errors and closes the
  log on every pre-start path. After `Start`, a parent-close or `Release` failure
  kills and reaps the new child rather than returning an ambiguous result; a
  clean handoff preserves the established detached service behavior.
- Added fake-process and filesystem integration coverage for normal/fallback
  launch, cancellation and deadline, private/linked data directories,
  symlink/FIFO/directory/non-private logs, prompt rejection, oversized rotation,
  destination-directory failure, previous-symlink replacement, disappearing
  executable, and a swapped long-path alias. Existing environment-isolation
  and inherited-output bounds remain covered.
- Architecture, security, troubleshooting, and development documentation now
  describe discovery, cancellation, path and permission rules, recovery from
  unsafe entries, the real-state-versus-alias boundary, and the fact that 5 MiB
  is a startup rotation threshold rather than a live cap.

### Validation and measurements

- The focused filesystem/startup suite passed 20 repetitions in 0.050/1.952
  seconds and ten race repetitions in 1.079/2.121 seconds. Targeted coverage is
  75.0% for rotating open, 83.3% for directory validation, 100% for inode and
  private-directory predicates, and 76.3% for `StartDaemon`; remaining branches
  are primarily descriptor-construction, `fstat`, close, release, and injected
  same-UID race failures.
- A validated non-rotating open measures 9.9–11.4 microseconds, 928 bytes, and
  11 allocations. Descriptor-relative rotation measures 38.6–42.6
  microseconds, 1,752 bytes, and 25 allocations. Both are negligible beside an
  external Mutagen process start; no cache or persistent helper was added.
- `make verify` passed formatting, module verification, all package tests, vet,
  dependency separation, and cross-builds of 8,646,242-byte Darwin arm64,
  9,115,440-byte Darwin amd64, and 5,026,835-byte Linux agent binaries.
  `make test-race` passed every package.
- All ten five-second fuzz targets passed. Gosec completed cleanly,
  `govulncheck` reported `No vulnerabilities found`, and ShellCheck 0.11.0 plus
  `bash -n` passed every repository shell file.
- GoReleaser completed with Go 1.26.5. All six checksums, three archive reads,
  both embedded-agent hashes, and three non-empty SPDX 2.3-to-Syft conversions
  passed. Stripped binaries measure 8,698,722 bytes Darwin arm64, 9,237,456
  bytes Darwin amd64, and 3,465,378 bytes Linux amd64 agent.
- Mutagen 0.18.1 and Lima are not installed in this audit environment, so the
  real daemon and VM layers were unavailable. Fake executable integration runs
  the actual cancellation, environment, descriptor inheritance, session,
  rotation, and error paths on Linux; Darwin compilation passed.

### Independent post-implementation audit

- **Product:** a cancelled or malformed first run no longer creates a surprise
  service or hangs on its log. The improvement strengthens an existing core
  workflow without adding commands, settings, dependencies, or maintenance
  surface that users must understand.
- **Architecture:** validation lives in the shared filesystem boundary and the
  Mutagen adapter retains its two documented launcher modes. Review expanded
  validation from the fallback log to the data directory before either
  launcher and added post-failure alias revalidation; no parallel lifecycle or
  wrapper daemon was introduced.
- **Security:** the log cannot follow a final symlink, block on a FIFO, escape
  the held data directory, accept broad permissions/foreign ownership, or
  silently rotate a different inode. Patched Go 1.25.12 addresses the current
  rooted-filesystem advisory; fixed-basename `openat` calls do not use its
  trailing-slash edge case.
- **QA:** ordinary success, fallback, malformed filesystem objects, rotation,
  cancellation boundaries, alias changes, start failure, repetition, race,
  fuzz, cross-build, static analysis, and packaging pass. Artificial `fstat`,
  close, and process-release failures would require production hooks with
  little additional confidence, and are left as explicit residual branches.
- **Performance:** measured descriptor validation adds roughly ten microseconds
  only when daemon startup is considered; rotation remains under 43
  microseconds excluding intentionally external I/O. There is no hot-loop or
  memory-pressure regression.
- **UX:** errors identify data-directory validation, log opening, rotation,
  process start, close, or release distinctly. Troubleshooting gives the exact
  log location and safe remediation while avoiding a false hard-cap promise.
- **Operations:** one previous generation preserves bounded startup history,
  normal `daemon start` remains fast/idempotent, and a failed handoff cannot
  knowingly leave an unmanaged new child. Release archives, completions,
  embedded agent, checksums, and SBOMs remain valid.
- **Documentation:** architecture, security boundary, cancellation behavior,
  operator recovery, test coverage, and rotation limitations are aligned with
  the implementation and authoritative Mutagen/POSIX/Go evidence.

Residual risks: the detached daemon can grow its active log beyond 5 MiB; a
same-UID process can still race state that is outside Pwnbridge's privilege
boundary; a crash cannot make non-critical log rotation durable without a
directory sync; and real Mutagen/Lima execution remains an external validation
layer. A log-forwarding wrapper, new lock service, or durable rotation protocol
would add disproportionate lifecycle complexity. Cycle 20 should prioritize
the higher-value partial-result `doctor` workflow and audit remaining unbounded
SSH diagnostics before reconsidering retention or live verification progress.

## 25. Continuous-improvement roadmap — Cycle 20

### Product and technical assessment

`pwnbridge doctor` is currently least reliable when it is most needed. Local
Mutagen version checking, agent discovery/deployment, basic SSH, forwarding,
and agent probing all share the unbounded command context and delay all output
until every stage returns. A failed basic probe suppresses later remote checks;
`host doctor` returns no structured result at all when its one inventory call
fails. The project-level command also writes remotely by deploying an agent,
although the existing bootstrap inventory can derive the selected recipe's
health through one bounded, explicitly read-only SSH script. The two doctor
commands consequently disagree: one hard-codes tools and the other evaluates
the configured bootstrap profile.

The rendering boundary compounds this problem. Human writes ignore errors and
remote/error text can contain newlines or terminal controls; successful JSON
uses the stable envelope, but it has no `complete` signal to distinguish a
fully evaluated unhealthy system from an unavailable collector. Basic/agent
probes and the forwarding control operation also retain unbounded combined SSH
output despite their tiny protocols. These are correctness, security, UX,
automation, and support gaps in one core diagnostic workflow.

Homebrew's official `doctor` contract runs named checks and exits nonzero when
any potential problem is found. GitHub CLI's authentication status tests every
known account and reports issues before its failure status. Docker version
separates locally available client data from the independently contacted
server. Kubernetes exposes request-scoped timeouts, and Go's context guidance
recommends derived per-operation deadlines that preserve parent cancellation.
Together these support a complete partial-report model rather than fail-fast or
one global deadline.

| Rank | Opportunity | User value / severity | Strategic fit | Effort / risk | Evidence and decision |
| --- | --- | --- | --- | --- | --- |
| 1 | Read-only partial-result doctor with independent probe budgets | High diagnostic value / high reliability | Very high | Medium / medium | Current command can hang, mutate, suppress evidence, and disagree with host doctor; selected |
| 2 | Bound all small-protocol SSH probe/control output | Medium reliability / medium availability | High | Low / low | Inventory is already capped, but basic/agent/forwarding probes are not; include the directly exercised paths |
| 3 | Bound remaining execution/control-master response paths | Medium reliability / medium availability | High | Medium / medium | Some responses carry intentional command output; audit separately after tiny diagnostic protocols are fixed |
| 4 | Live progress for large recovery verification | Medium UX / low correctness | Medium | Medium / medium | Verification remains cancellable and measured; diagnostics have greater first-run value |
| 5 | Automatic recovery retention/pruning | Medium convenience / high destructive risk | Medium | Medium / high | No capacity or policy evidence justifies deleting recovery data automatically |

This cycle selects a meaningful end-to-end product improvement: both doctor
commands should always return the useful checks they could complete, clearly
state whether the evaluation itself was complete, make no persistent remote
change, and finish within documented per-probe budgets. The existing output
schema, recipe model, inventory, transport, and remediation vocabulary are
sufficient; no dependency, daemon, persistent cache, or configurable timeout
surface is needed.

### Acceptance criteria and implementation plan

1. Replace project-doctor agent deployment/probing with the existing bounded,
   read-only bootstrap inventory. Resolve the selected host's bootstrap profile
   and derive component checks through the same planner used by `host doctor`.
   Preserve explicit configured container and Mosh transport checks.
2. Give local prerequisites, remote inventory, and reverse-forwarding probes
   separate child contexts (10, 20, and 15 seconds). Run remote probes
   sequentially to avoid simultaneous passphrase/hardware-token prompts, but
   continue to forwarding after an inventory failure or timeout. Parent Ctrl-C
   stops further probes immediately.
3. Introduce one typed report shared by `doctor` and `host doctor` with stable
   `ok`, `complete`, and ordered `checks` fields. Probe failures become typed
   checks with stable `timeout`, `cancelled`, or `failed` states instead of
   aborting before output. Missing capabilities remain a complete evaluation;
   an unavailable/timed-out collector makes `complete=false`.
4. Keep the standard schema-one JSON envelope and nonzero health semantics.
   Emit the accumulated report before returning a failure or parent
   cancellation; preserve cancellation as exit 130. Human output uses one
   buffered write and propagates output failure.
5. Normalize all human/JSON check detail and remediation strings into bounded
   single-line valid UTF-8. Remove C0/DEL and terminal escape sequences, replace
   structural whitespace safely, and cap lengths without splitting a rune.
   Preserve fixed check names, component IDs, severities, and states.
6. Cap tiny SSH protocols at their actual boundaries: basic probe and
   forwarding control output at 64 KiB, agent probe JSON at 1 MiB. Drain excess,
   preserve context errors, and add regression tests for stdout/stderr floods
   and inherited descriptors.
7. Refactor bootstrap inventory to depend only on its narrow bounded-SSH
   interface so fake integration can exercise timeouts, continuation, ordering,
   optional forwarding, recipe-derived checks, and parent cancellation without
   production hooks or a real host.
8. Cover no remote writes/deployment, local and each remote timeout, inventory
   failure followed by successful forwarding, parent cancellation, complete
   unhealthy versus incomplete reports, project/host command parity, configured
   runtime/transport requirements, hostile detail text, bounded rendering,
   JSON compatibility, exit status, output failure, and no-host behavior.
9. Update README, CLI, troubleshooting, architecture, security, development,
   and Lima E2E guidance. Measure healthy and worst-case timeout paths, then run
   formatting, module verification, focused repetition/race tests, full tests,
   vet, fuzzing, gosec, govulncheck, ShellCheck, cross-builds, and a fully
   inspected release snapshot before the eight-perspective audit and Cycle 21.

### Risks and mitigations

- Removing diagnostic agent deployment means doctor no longer rehearses SCP or
  remote installation. The local `scp` capability remains checked and every
  real execution path verifies/deploys the content-addressed agent. A health
  command should not create remote files merely to diagnose them; document the
  read-only boundary and let real startup report deployment failures.
- Two sequential remote probes can each require authentication. Running them in
  parallel would create confusing simultaneous prompts; fixed 20/15-second
  budgets cap the worst case at 35 seconds while preserving ordinary OpenSSH
  interaction and parent cancellation.
- A timeout does not prove a capability is absent. Represent it as an incomplete
  fatal check rather than `missing`, retain remediation, and avoid guessing
  downstream component state when inventory is unavailable.
- Bounded one-line detail can omit the tail of a verbose SSH error. Include an
  explicit truncation marker, retain enough prefix for diagnosis, and point
  support sharing to the privacy-allowlisted `support` command rather than raw
  doctor output.
- Reverse-forwarding inspection temporarily starts a private local OpenSSH
  control master but creates no persistent remote state. Existing bounded,
  idempotent teardown remains mandatory on success, failure, and timeout.
- Fixed timeout values may be tight for unusually slow authentication. They are
  diagnostic budgets rather than connection policy; normal run/bootstrap paths
  retain their configured/parent contexts, and evidence can justify a future
  flag without adding one speculatively now.

### Research references

- [Homebrew `doctor` contract](https://docs.brew.sh/Manpage#doctor-dr---list-checks---audit-debug-diagnostic_check-)
- [GitHub CLI partial authentication status](https://cli.github.com/manual/gh_auth_status)
- [Docker independently versioned client/server output](https://docs.docker.com/reference/cli/docker/version/)
- [Kubernetes per-request timeout option](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_wait/#options)
- [Go context deadlines and cancellation](https://go.dev/blog/context)
- [Go `context.WithTimeout` resource guidance](https://pkg.go.dev/context#WithTimeout)
- [OWASP output/log injection and length guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Python `-B` no-bytecode-write option](https://docs.python.org/3/using/cmdline.html#cmdoption-B)

### Completed implementation

- Project and host doctor now share a narrow remote collector built from the
  bounded bootstrap inventory and resolved recipe planner. Project doctor no
  longer discovers, uploads, or runs the agent; neither form invokes SCP,
  `sudo`, package installation, or persistent remote diagnostic storage.
  Configured Mosh, container-engine, and reverse-forwarding requirements remain
  explicit checks. The inventory's optional managed-Python metadata read uses
  the documented `-B` mode so imports do not create bytecode caches.
- Local, inventory, and reverse-forwarding collectors receive independent
  10/20/15-second derived contexts. Ordinary inventory failure or timeout is
  retained as a typed check and forwarding still runs; parent cancellation
  stops new work and is returned after accumulated output so Ctrl-C remains
  exit 130.
- Added a common `{ok,complete,checks}` report for human and schema-one JSON
  output. `complete=false` distinguishes unavailable evaluation from an
  evaluated missing prerequisite. Timeout, cancellation, and ordinary probe
  failures use stable states. Human output is assembled before one checked
  write; both formats return output errors and health failures only after the
  report is emitted.
- Diagnostic detail and remediation are valid UTF-8, single-line, free of C0,
  DEL, ANSI CSI/OSC, and Unicode format controls, rune-safely capped at 512/256
  bytes, and visibly truncated. A new integrated fuzz target exercises this
  boundary. Fixed names, components, severity, and states remain machine-safe
  closed vocabularies.
- Basic and forwarding SSH protocols now retain at most 64 KiB, while agent
  probe JSON retains at most 1 MiB. Excess stdout/stderr is drained and
  rejected, context causes are preserved, inherited descriptors cannot hold
  commands indefinitely, and control-master startup output is likewise capped.
  Bootstrap inventory now depends only on its bounded command interface.
- README, CLI, architecture, security, troubleshooting, installation,
  development, and Lima E2E guidance document the read-only boundary, timeout
  budgets, partial-result semantics, JSON contract, exit behavior, and public
  support-report distinction. The Lima assertion checks completeness and both
  remote inventory and forwarding without expecting an agent deployment.

### Validation and measurements

- One hundred collector repetitions, five realistic project/host CLI
  repetitions, twenty inventory/script repetitions, focused transport
  repetitions, and focused race repetitions pass. The fake OpenSSH integration
  covers recipe/config parity, required/optional forwarding, no SCP or agent
  operation, cancellation output, exit 130, and writer failure. A standalone
  built binary emits the expected complete unhealthy JSON and human results
  before exit 1 on Linux.
- New report entry points measure 100% `NewReport`, 100% `Healthy`, 88.9%
  failure classification, 89.5% rendering, 95.0% single-line normalization,
  and 83.3% escape parsing coverage. Doctor aggregation measures 100% local,
  85.7% remote, 100% configured requirements/forwarding/rendering; bounded SSH
  output measures 91.7% with its writer/snapshot at 100%.
- A 32-check normalize-and-render operation measures 78.7–136.7 microseconds,
  18,433–18,434 bytes, and 375 allocations. Healthy remote collection measures
  23.9–27.5 microseconds, 21,042 bytes, and 72 allocations; both are outside
  interactive network latency and introduce no hot-loop cost.
- `make verify`, full race tests, all eleven integrated fuzz targets, gosec,
  `govulncheck` (`No vulnerabilities found`), ShellCheck 0.11.0, `bash -n`, and
  standalone CLI checks pass. Cross-builds are 8,679,554 bytes Darwin arm64,
  9,123,936 bytes Darwin amd64, and 5,026,835 bytes Linux agent.
- GoReleaser succeeds with its automatically selected Go 1.26.5 toolchain.
  Six checksums, three archive reads, two embedded-agent hash comparisons, and
  three Syft-to-SPDX 2.3 conversions pass. Stripped release binaries are
  8,699,026 bytes Darwin arm64, 9,254,144 bytes Darwin amd64, and 3,465,378
  bytes Linux agent.

### Independent post-implementation audit

- **Product:** one command now yields actionable partial evidence during the
  exact authentication, host, and tool failures it is meant to diagnose. It
  remains aligned with Pwnbridge's managed-host workflow without adding config
  or a daemon.
- **Architecture:** the narrow inventory/forwarding interface and common report
  remove the project/host divergence and agent dependency. Sequential probes
  keep authentication comprehensible; fixed derived contexts keep ownership
  explicit.
- **Security:** doctor no longer uploads executable content, details cannot
  forge terminal lines, tiny protocols cannot consume unbounded memory, and
  Python inventory imports cannot write `.pyc` files. The temporary private
  forwarding master remains the sole ephemeral remote-side capability probe.
- **QA:** complete unhealthy, incomplete, timeout, parent cancellation,
  malformed output, configured capabilities, output flood, inherited pipe,
  output error, JSON, human, parity, and no-host paths are covered across unit,
  integration, repetition, race, fuzz, and cross-platform compilation layers.
- **Performance:** local aggregation is microsecond-scale and bounded memory;
  wall time is dominated by explicit network budgets. No probe is parallelized
  into competing authentication prompts.
- **UX:** ordered checks survive failures, final human status states
  complete/incomplete, JSON automation can distinguish health from collection,
  remediation stays adjacent, and public-sharing guidance avoids leaking raw
  paths or remote errors.
- **Operations:** exit 1 and 130 semantics, output failure, cleanup, package
  contents, completions, checksums, embedded agent, SBOM, and size caps remain
  verified. No migration or persisted schema change is required.
- **Documentation:** discovery, first run, normal failure, timeout, cancellation,
  privacy, mutation boundaries, automation fields, and test expectations agree
  with the implementation and primary-source evidence.

Residual risks: OpenSSH cleanup is separately bounded and can extend slightly
beyond a probe's work deadline; a process that ignores context cannot be made
cooperative by the collector interface, although production subprocesses are
force-terminated; raw doctor detail is intentionally diagnostic rather than
public-safe; and invalid project configuration still fails before remote
collection because no trustworthy effective requirements exist. Lima and real
Mutagen execution are unavailable in this environment, leaving fake OpenSSH,
subprocess/race coverage, Darwin cross-compilation, and release inspection as
the accessible validation layers. Cycle 21 should audit remaining unbounded
SSH/control responses and select the highest-value bounded execution or
recovery-progress improvement rather than adding timeout configuration.

## 26. Continuous-improvement roadmap — Cycle 21

### Product and technical assessment

Recovery verification now checks every byte and filesystem object against a
deterministic digest, but a large file/tree holds the workspace mutation lock
without any visible indication that work is advancing. All results are buffered
until the final entry: Ctrl-C returns 130 but discards already completed checks,
so the user cannot tell which copies are known-good or how much work remains.
This is the largest current gap in an otherwise complete list/verify/restore
workflow and is directly called out by Cycle 18's residual audit.

The transport audit also found a narrower availability issue. Control-master
forwarding, agent management replies, ordinary setup commands, and SCP errors
still use `CombinedOutput`, whose Go implementation attaches an unrestricted
`bytes.Buffer`. These protocols return an empty acknowledgement, one allocated
port, bounded JSON, or short diagnostics; a hostile/misconfigured SSH endpoint
or executable can consume client memory without adding legitimate user value.
Interactive shell/run streams and remote recovery archives are intentionally
streamed and must not be capped by this change.

The public repository has no issue or pull-request history as of 2026-07-14;
the v0.1.0–v0.1.13 release and local audit history are therefore the available
product evidence. Restic shows progress for long check operations by default on
interactive consoles and disables it for non-interactive logs. Borg makes
progress explicit, writes it to stderr, and separates JSON log events. Both
reinforce transient terminal progress that cannot corrupt Pwnbridge's final
schema-one JSON document. Restic's repair guidance also retains the complete
check output, supporting partial evidence on interruption rather than an empty
result.

| Rank | Opportunity | User value / severity | Strategic fit | Effort / risk | Evidence and decision |
| --- | --- | --- | --- | --- | --- |
| 1 | Live recovery verification progress and cancellation report | High UX/recovery confidence / medium reliability | Very high | Medium / low | Full byte scans can be long, lock state is invisible, and completed work is discarded on Ctrl-C; selected feature |
| 2 | Bound remaining SSH management/control replies | Medium availability/security | Very high | Low / low | Protocol outputs are structurally tiny but `CombinedOutput` is unbounded; selected hardening |
| 3 | Bound Mutagen, container-engine, and provider diagnostics | Medium availability / medium reliability | High | Medium / medium | Legitimate status/conflict/provider output sizes differ; audit with workload-specific caps next |
| 4 | Stream JSON progress events | Medium automation value / compatibility risk | Medium | Medium / high | Would replace the stable single-document envelope; reject until a versioned JSONL use case exists |
| 5 | Automatic recovery retention/pruning | Medium convenience / high destructive risk | Medium | Medium / high | Still lacks a safe capacity/policy signal; defer |

This cycle selects one complete product workflow plus its adjacent transport
hardening. No new dependency, persistent state, background job, configuration
knob, extra archive pass, or destructive behavior is justified.

### Acceptance criteria and implementation plan

1. Extend deterministic archive generation with an optional monotonic progress
   callback reporting content bytes and filesystem items actually read. Existing
   `WriteArchive`, `DigestContext`, and `Verify` APIs delegate to the new path;
   their stream bytes, summaries, race checks, cancellation, and performance
   remain identical when no callback is supplied.
2. Make `sync recovery verify` show a delayed transient progress line only when
   human stderr is a terminal. Report selected entry index/count and a bounded
   0–100 percentage derived from recorded content bytes, falling back to item
   counts for zero-byte trees. Throttle refreshes, avoid paths/IDs, erase the
   line before final output, and emit no progress for `--json` or non-TTY use.
3. Add `checked` and `total` to the additive verification report. On parent
   cancellation, retain completed entry results, set `complete=false`, emit the
   human or JSON report, then return the original context cause so Ctrl-C remains
   exit 130. Discovery/selection/lock failures before a trustworthy scan still
   fail without fabricating a report.
4. Keep verification sequential and under the existing workspace lock so
   integrity evidence remains point-in-time and I/O is not multiplied. Read
   errors continue to be per-entry results; cancellation is the only early stop.
5. Cap ordinary SSH setup/control output at 1 MiB, forwarding/SCP diagnostics at
   64 KiB, and agent management output at 2 MiB. The agent cap must accept a
   maximum 1 MiB conflict snapshot after JSON base64 expansion while rejecting
   larger floods. Drain discarded bytes, preserve context causes, and retain
   inherited-descriptor shutdown through `WaitDelay`.
6. Route clean/runtime-reset management commands through the bounded transport
   instead of direct unbounded SSH capture. Bound stream-local/TCP forwarding
   and relay acknowledgements without changing fallback or loopback behavior.
7. Test monotonic/final archive progress for files, directories, links, zero-byte
   trees, cancellation mid-file, and nil-callback equivalence. Test percentage
   clamping/throttling, partial human/JSON reports, additive counters, output
   failure, exit 130, no progress in JSON/non-TTY mode, maximum snapshot success,
   stdout/stderr floods, and inherited descriptors.
8. Update README, CLI, architecture, security, troubleshooting, development, and
   E2E expectations. Measure callback overhead and large-file/tree progress,
   then run repetitions, race, all fuzz targets, full verify/security/shell
   gates, cross-builds, and an inspected release snapshot before the independent
   eight-perspective audit and Cycle 22.

### Risks and mitigations

- Recorded recovery size/item totals may be stale or tampered. Treat them only
  as display estimates, clamp percentage, and let digest/structural comparison—
  never progress—determine integrity. Do not expose original paths in the
  transient line.
- Per-read callbacks can make a hot I/O loop noisy. Keep archive reporting
  allocation-free when nil and throttle terminal refreshes to human timescales;
  benchmark both paths and avoid a preliminary counting pass.
- Printing partial results changes cancellation from silent to informative.
  Emit before returning `context.Canceled`, keep `complete=false`, include exact
  checked/total counters, and preserve exit 130 so scripts retain their signal.
- A 1 MiB raw snapshot expands to roughly 1.4 MiB in JSON base64. Use a 2 MiB
  agent-management cap and regression-test the actual maximum payload rather
  than reusing the 1 MiB framed-protocol constant blindly.
- Bounded collectors still drain excess until the process exits or its context
  ends. This prevents pipe deadlock and memory exhaustion; parent cancellation
  remains the wall-time control.
- The transport change must not touch PTY shell/run output or recovery archive
  streaming. Limit only management calls whose response contracts are already
  bounded or tiny.

### Research references

- [Restic interactive/non-interactive progress behavior](https://restic.readthedocs.io/en/stable/manual_rest.html)
- [Restic full-data check and retained results guidance](https://restic.readthedocs.io/en/stable/077_troubleshooting.html)
- [Restic single-document versus JSON-lines contracts](https://restic.readthedocs.io/en/latest/075_scripting.html)
- [Borg progress and stderr/JSON logging contract](https://borgbackup.readthedocs.io/en/latest/usage.html)
- [Borg frontend progress-event guidance](https://borgbackup.readthedocs.io/en/1.4.1/internals/frontends.html)
- [Go `CombinedOutput` unrestricted buffer implementation](https://go.dev/src/os/exec/exec.go#L1035)
- [OpenSSH control forwarding and allocated-port output](https://man.openbsd.org/ssh.1#O)
- [Pwnbridge issue history (empty as assessed)](https://api.github.com/repos/simonfalke-01/pwnbridge/issues?state=all&per_page=100)

### Completed implementation

- Deterministic archive generation now has optional synchronous monotonic
  content-byte/item progress. Existing archive/digest/verify APIs delegate to
  the same implementation, and nil progress preserves the original stream and
  allocation path. Updates coalesce at 256 KiB or 64 items with an exact forced
  final state, avoiding both a preliminary traversal and per-read UI overhead.
- Recovery verification uses that one source reader to drive a delayed
  transient terminal line with entry/count and clamped percentage. Recorded
  bytes drive ordinary entries, item counts cover zero-byte trees, 100% is
  reserved for a finished entry, refreshes are throttled to 100 ms, and neither
  recovery ID nor original path is displayed. Non-terminal and `--json` runs
  emit no progress.
- Verification reports add stable additive `checked` and `total` fields.
  Parent cancellation during an entry, in the final callback, or immediately
  before rendering retains fully completed ordered results, emits a report with
  `complete=false`, and returns the original context cause for exit 130. Read
  failures still become per-entry results and later entries continue; catalog,
  selection, and lock failures still fail before inventing evidence.
- All SSH management collection now has a protocol-specific cap: 64 KiB for
  forwarding and SCP diagnostics, 1 MiB for ordinary remote setup/control, and
  2 MiB for agent management. Excess stdout/stderr is drained and rejected,
  context and inherited-descriptor behavior is preserved, and the maximum
  1 MiB conflict snapshot succeeds after its roughly 1.4 MiB JSON/base64
  expansion. Clean and runtime-reset use the same bounded transport path.
- README, CLI, architecture, security, troubleshooting, development, and Lima
  E2E guidance describe progress visibility, partial cancellation, JSON fields,
  management bounds, privacy, and streaming exclusions. E2E now asserts a
  complete one-entry checked/total JSON result before restore.

### Validation and measurements

- Fifty recovery-core repetitions, twenty CLI/PTY repetitions, three management
  flood repetitions, ten final cancellation/limit repetitions, and focused
  race repetitions pass. Tests cover deterministic stream equivalence,
  file/tree/link progress, mid-stream and final-boundary cancellation, retained
  completed results, real PTY rendering/erasure, silent JSON/non-TTY output,
  output failure, maximum snapshot success, ordinary/agent/forward/SCP floods,
  inherited pipes, and context causes.
- New recovery coverage is 78.9% archive-progress construction, 100% progress
  digest and verification, 100% progress reader, and 87.5% coalescing. CLI
  aggregation is 93.1%, progress formatting/percentage and final rendering are
  100%, and display throttling is 85.7%. The complete transport suite covers
  ordinary/raw bounded capture, management run, bounded writer, and snapshot at
  100%; agent management is 93.3% and forwarding setup 81.0%.
- Ordinary 1 MiB verification measures 0.93–1.15 ms after the cold run, about
  35.9 KiB, and 41 allocations. Progress-enabled verification overlaps at
  0.99–1.07 ms, about 35.9 KiB, and 43 allocations: coalescing reduces the
  initial per-read ~10% cost to benchmark noise with only 39 bytes/two
  allocations of callback state.
- `make verify`, the full race suite, all eleven fuzz targets, gosec,
  `govulncheck` (`No vulnerabilities found`), ShellCheck 0.11.0, `bash -n`, and
  module verification pass. Cross-builds are 8,680,242 bytes Darwin arm64,
  9,136,912 bytes Darwin amd64, and 5,028,441 bytes Linux agent.
- GoReleaser succeeds with Go 1.26.5. Six checksums, all three archive reads,
  both embedded-agent hash comparisons, both packaged current-plan/audit checks,
  and all three Syft-to-SPDX 2.3 conversions validate. Final stripped release
  binaries are 8,716,210 bytes Darwin arm64, 9,267,104 bytes Darwin amd64, and
  3,469,474 bytes Linux agent.

### Independent post-implementation audit

- **Product:** a previously opaque, lock-holding full-content workflow now
  proves forward motion and preserves completed evidence on interruption. It
  completes the existing recovery journey without retention policy, jobs, or
  new configuration.
- **Architecture:** progress is derived inside the authoritative deterministic
  archive reader, not a second scanner. Existing APIs delegate, callbacks are
  optional/coalesced, final reports remain single documents, and streamed bulk
  channels stay separate from bounded management capture.
- **Security:** transient output cannot expose recovery names, stale totals
  cannot affect integrity, management floods cannot grow memory without bound,
  and the larger agent cap is justified by tested base64 expansion. No PTY or
  recovery stream is truncated.
- **QA:** boundaries include zero/maximum sizes, directories, links, malformed
  and oversized responses, stdout/stderr, inherited descriptors, non-terminal
  output, writer errors, mid-file/final-render cancellation, read continuation,
  JSON compatibility, and Darwin compilation.
- **Performance:** progress performs no extra pass, adds no measurable scan time
  after coalescing, and refreshes terminal output at human—not I/O—frequency.
  Verification remains intentionally sequential to avoid multiplying disk I/O.
- **UX:** slow interactive scans show index/count/percentage after the existing
  quiet delay, fast scans remain silent, machine output remains clean, 100%
  means finished, and partial summaries say exactly how many of the selection
  were checked.
- **Operations:** the workspace lock still defines the point-in-time boundary,
  is released before final output, Ctrl-C remains 130, output failure is
  propagated, no schema migration is needed, and package size remains bounded.
- **Documentation:** periodic verification, terminal/redirection behavior,
  partial recovery, public-safe progress, JSON automation, transport caps, E2E
  assertions, and test coverage agree with implementation and official
  restic/Borg/Go/OpenSSH evidence.

Residual risks: progress is an estimate derived from recorded totals and can
remain at 99% while final metadata/digest checks complete; interruption never
persists a resume checkpoint, so unchecked entries must be selected again; a
callback is synchronous by design and must remain fast; and bounded collectors
still drain until process exit or context cancellation. Mutagen, container
engine, and terminal-provider `CombinedOutput` paths retain workload-dependent
unbounded diagnostics and should be audited separately rather than assigned an
arbitrary shared cap. Several UI/TOML dependencies have newer releases but the
current vulnerability scan is clean, so a focused compatibility upgrade is a
better Cycle 22 candidate than mixing dependency churn into this feature.
Lima and Mutagen 0.18.1 remain unavailable for live execution here.

## 27. Continuous-improvement roadmap — Cycle 22

### Product and technical assessment

The first container-backed shell or command can spend minutes pulling a remote
image, but Pwnbridge currently captures every Docker/Podman progress update in
an unrestricted in-memory `bytes.Buffer` and displays nothing until failure.
An interactive user sees an apparently stuck session; a large or malicious
engine response can exhaust the remote agent before the command starts. The
setup uses `context.Background`, so an interrupt terminates the SSH-facing
agent but does not explicitly cancel and reap the engine client. This is the
largest remaining first-run workflow gap and the highest-value Cycle 22 feature.

The repository-wide subprocess audit found 23 remaining unrestricted
`Output`/`CombinedOutput` sites across Mutagen, container management, terminal
providers, and agent probes, plus an unbounded buffered `diff` diagnostic.
Their contracts differ materially: Docker/Podman pull is a progress stream;
Mutagen status can contain many conflicts; Zellij, WezTerm, and Kitty return a
JSON inventory of all panes; and image IDs, pane IDs, versions, disk counts,
and launch acknowledgements are tiny. Applying one low limit would regress real
projects, while leaving them unrestricted retains an avoidable availability
boundary.

Official Docker documentation says pull progress is verbose, cancellable, and
can be suppressed with `--quiet`; Podman documents that quiet pull preserves
the final error or successful identifier. Docker documents that detached run
prints one container ID and image inspect supports a caller-provided format.
Mutagen documents that `sync list` includes all conflicts/problems and can
manage arbitrarily many sessions, justifying a much larger structured limit
than management acknowledgements. Zellij, WezTerm, and Kitty document complete
structured pane/window inventories. Go documents that `CommandContext` kills
the process on cancellation, `WaitDelay` bounds inherited pipes, and
`NotifyContext.stop` restores normal signal behavior.

| Rank | Opportunity | User value / severity | Strategic fit | Effort / risk | Evidence and decision |
| --- | --- | --- | --- | --- | --- |
| 1 | Stream interactive container-image pull progress and cancel setup correctly | High first-run UX / high reliability | Very high | Medium / medium | Pulls are currently silent, buffered, and detached from signals; selected product improvement |
| 2 | Bound all remaining captured subprocess output by response contract | High availability/security | Very high | Medium / low | 23 capture sites and one diagnostic buffer remain; selected hardening |
| 3 | Upgrade Bubble Tea/Bubbles/Lip Gloss/TOML dependencies | Medium compatibility/maintenance | High | Medium / medium | Updates exist but current scans are clean; isolate after process-boundary work |
| 4 | Persist recovery-verification checkpoints | Medium repeat-work reduction | Medium | High / high | Requires authenticated mutable checkpoint semantics for changing copies; defer |
| 5 | Automatic recovery retention/pruning | Medium convenience / high destructive risk | Medium | Medium / high | No safe capacity or policy signal exists; continue to reject |

This cycle selects an end-to-end visible first-run feature and the adjacent
process-boundary hardening. It adds no dependency, configuration, daemon,
protocol version, persistent state, preliminary image request, or destructive
behavior.

### Acceptance criteria and implementation plan

1. Add a small subprocess capture primitive that drains stdout/stderr
   concurrently, retains a bounded stdout prefix and bounded diagnostic tail,
   records truncation, applies the existing one-second `WaitDelay`, and prefers
   the parent context cause. It must be race-safe when writers are shared,
   reject invalid limits, and avoid memory growth after the cap.
2. Give Mutagen structured stdout a 16 MiB ceiling so conflict-heavy sessions
   remain usable, while retaining at most 64 KiB of final diagnostics. Return an
   actionable limit error, never decode a truncated JSON document, keep daemon
   startup behavior unchanged, and preserve cancellation/inherited-pipe bounds.
3. Add optional runtime setup progress. If the image is absent and agent stderr
   is a terminal, stream Docker/Podman pull stdout and stderr directly as they
   arrive without buffering. In non-terminal operation, pass the officially
   supported `--quiet` flag and capture at most 64 KiB per stream so scripted
   stdout/stderr and JSON/control channels remain quiet and bounded.
4. Bound runtime inspect, detached create, status, and removal replies at 64
   KiB; they return a boolean, immutable SHA-256 ID, container ID/name, or short
   diagnostic. Continue resolving the configured tag/digest to an immutable
   image ID before `run`, and keep the existing Podman post-remove recheck.
5. Derive SIGINT/SIGTERM/SIGHUP-aware setup contexts in agent exec, shell, and
   debugger-pane entry points; call `NotifyContext.stop` before replacing the
   process. On setup cancellation, kill/reap the container client, return the
   original context cause, and do not write a successful runtime record.
6. Cap terminal provider JSON inventories at 4 MiB, the custom provider
   response at 1 MiB, and pane/version/disk/launcher acknowledgements at 64
   KiB. Retain final 64 KiB diagnostics, drain excess, preserve extensible JSON
   decoding, and leave terminal process streams themselves unbounded.
7. Replace the conflict-preview stderr buffer with a bounded diagnostic tail.
   Do not cap the user-facing diff stream, PTY/Mosh/SSH streams, bootstrap event
   stream, or recovery archive stream. Audit production Go source until no
   direct `Output`/`CombinedOutput` call or unbounded subprocess diagnostic
   buffer remains outside the tested capture package.
8. Test prefix/tail ordering, exact-limit and overflow behavior, concurrent
   writes, context cancellation, output floods, inherited descriptors,
   Mutagen large structured state, terminal inventories, custom providers,
   engine IDs, interactive early progress, silent quiet mode, and cancellation
   before pull completion. Add fake Docker and Podman argv coverage and update
   container E2E expectations.
9. Update README, container, CLI/architecture, security, troubleshooting, and
   development documentation. Measure bounded-writer memory/throughput and
   cross-build sizes, then run repetitions, race, every fuzz target, full
   verify/security/shell gates, and an inspected release snapshot before the
   independent eight-perspective audit and Cycle 23.

### Risks and mitigations

- Setup output can contaminate scripts. Stream only when the remote agent's
  stderr is a character-terminal; non-terminal pulls use quiet mode and retain
  diagnostics only on failure. Never emit progress from management JSON calls.
- A terminal can have an unusually large pane inventory and Mutagen can have
  many conflicts. Use evidence-specific 4 MiB and 16 MiB ceilings, report the
  exact limit, and never silently decode a truncated response.
- An error at the end of a long progress stream is more useful than its first
  lines. Retain a tail for diagnostics but a prefix for structured stdout;
  annotate truncation so omitted output cannot be mistaken for completeness.
- Docker and Podman progress render differently on terminals. Treat bytes as an
  opaque stream and let each official CLI detect the PTY; do not parse, rewrite,
  persist, or include progress in support reports.
- `NotifyContext` changes process signal behavior until stopped. Confine it to
  setup and explicitly stop before `syscall.Exec`, as required by the official
  signal contract.
- Stream writers can be called concurrently by `os/exec`. Make bounded writers
  synchronized, test with the race detector, and keep memory proportional only
  to the declared cap.

### Research references

- [Docker pull progress, quiet mode, and cancellation](https://docs.docker.com/reference/cli/docker/image/pull/)
- [Podman pull quiet-mode output contract](https://docs.podman.io/en/stable/markdown/podman-pull.1.html)
- [Docker formatted image inspection](https://docs.docker.com/reference/cli/docker/image/inspect/)
- [Docker detached-run container-ID contract](https://docs.docker.com/reference/cli/docker/container/run/)
- [Mutagen synchronization/list/conflict behavior](https://mutagen.io/documentation/synchronization)
- [Mutagen session-list output](https://mutagen.io/documentation/introduction/getting-started/)
- [Zellij structured programmatic control](https://zellij.dev/documentation/programmatic-control.html)
- [WezTerm JSON pane inventory](https://wezterm.org/cli/cli/list.html)
- [Kitty JSON remote-control inventory](https://sw.kovidgoyal.net/kitty/rc_protocol/)
- [Go command cancellation and `WaitDelay`](https://pkg.go.dev/os/exec)
- [Go `NotifyContext` and stop semantics](https://pkg.go.dev/os/signal#NotifyContext)
- [Go unrestricted `Output`/`CombinedOutput` implementation](https://go.dev/src/os/exec/exec.go)

### Completed implementation

- Added a shared, cancellation-aware subprocess collector with synchronized
  bounded stdout-prefix and stderr-tail retention, explicit truncation, valid
  UTF-8 diagnostics, one-second inherited-pipe teardown, and context-cause
  precedence. Invalid limits or preconfigured pipes fail before a child starts.
- Runtime setup first inspects the configured image to preserve the existing
  immutable-ID contract. A missing image now streams the engine's native pull
  output only to a real terminal; redirected and automation paths use
  `pull --quiet` and bounded diagnostics. SIGINT, SIGTERM, and SIGHUP cancel and
  reap the engine client before exec/shell/pane replacement, so interruption
  cannot write a successful runtime record.
- Applied response-specific bounds to every remaining local tool capture:
  16 MiB for full Mutagen state, 4 MiB for terminal inventories, 1 MiB for
  custom providers and ordinary Mutagen management, and 64 KiB for small
  identifiers, acknowledgements, probes, runtime management, versions, and
  diagnostic tails. Overflow is drained and rejected rather than parsed as a
  complete reply.
- Replaced the conflict-preview stderr buffer with a bounded diagnostic writer
  while leaving its user-facing diff stream intact. PTY/shell/container run,
  bootstrap events, remote recovery archives, and other bulk channels remain
  streams. Production Go source now has no direct `Output` or `CombinedOutput`
  use outside the shared bounded abstraction.
- Added exact-boundary, overflow, tail, concurrency, signal/reaping, real-PTY,
  `/dev/null`, inherited-descriptor, large Mutagen/provider/inventory, quiet
  pull, immediate progress, and cancellation tests. A twelfth fuzz target
  exercises bounded-writer invariants, and container E2E now rejects leaked
  pull progress in redirected operation.
- README, CLI, container-runtime, architecture, security, troubleshooting,
  development, and E2E documentation now agree on pull discovery, interactive
  progress, quiet automation, cancellation, bounds, and diagnostic behavior.
  No dependency, protocol, configuration, persistence, or schema changed.

### Validation and measurements

- Twenty subprocess and runtime repetitions, ten agent repetitions, five
  Mutagen and provider repetitions, focused race repetitions, the full unit
  suite, `make verify`, and the complete race suite pass. Tests prove a child
  is killed and reaped on a delivered signal, real PTYs get progress, regular
  files and `/dev/null` do not, exact ceilings succeed, excess replies fail,
  final diagnostic tails survive, and inherited descriptors cannot hang waits.
- All twelve three-second fuzz targets pass; the new writer target completed
  more than 26,000 executions in the aggregate run. Coverage is 95.1% for the
  subprocess package, including 100% capture and writer/snapshot paths;
  runtime image resolution is 100%, agent progress selection is 100%, the
  Mutagen runner is 90.9%, provider custom/open paths are 90%/100%, and the
  affected-package aggregate is 52.6%.
- Five 32 MiB flood benchmarks allocate 67,076,096–67,076,173 bytes and take
  18.3–24.0 ms with `bytes.Buffer`; the 64 KiB bounded tail allocates 180,288
  bytes in four allocations and takes 0.823–0.859 ms. That is a 99.73% memory
  reduction and about 22–29 times lower elapsed time on this runner.
- Gosec and `govulncheck` (`No vulnerabilities found`), ShellCheck 0.11.0,
  `bash -n`, module verification, `git diff --check`, and the production
  unrestricted-output audit pass. Cross-builds are 8,680,482 bytes Darwin
  arm64, 9,149,424 bytes Darwin amd64, and 5,056,177 bytes Linux agent.
- GoReleaser succeeds with Go 1.26.5. Final stripped release binaries are
  8,732,962 bytes Darwin arm64, 9,275,536 bytes Darwin amd64, and 3,489,954
  bytes Linux agent. The final post-record snapshot validates six checksums,
  all three archives, both embedded-agent comparisons, packaged plan/audit
  records, and three SPDX 2.3 conversions.

### Independent post-implementation audit

- **Product:** the previously opaque first image acquisition now visibly
  advances in an interactive session and remains clean in scripts. It improves
  an existing core workflow without a new mode, flag, or configuration burden.
- **Architecture:** one response-contract primitive replaces scattered
  unbounded buffers; policy stays at each integration boundary. Existing
  callers delegate through compatible methods, immutable image resolution is
  unchanged, and genuine data streams are not forced through collectors.
- **Security:** configured tool output can no longer grow agent memory without
  bound, truncated structured data is never trusted, diagnostics keep the most
  useful tail, and cancellation kills/reaps the engine child. Progress is
  terminal-only and is neither persisted nor included in support reports.
- **QA:** coverage spans exact and excess boundaries, concurrent floods,
  malformed replies, stderr tails, early progress, quiet argv, context and
  delivered signals, real PTYs, `/dev/null`, inherited pipes, provider retries,
  runtime cleanup, Darwin compilation, race, fuzz, and packaging.
- **Performance:** flood memory falls by 99.73% and benchmark time materially
  improves. The collector drains without retaining excess, allocates buffers
  lazily, and reserves the 16 MiB ceiling only for Mutagen's potentially
  conflict-heavy state.
- **UX:** users see the engine-native status they already understand; CI gets
  no progress noise; errors preserve final actionable detail and name the
  exceeded limit. No custom progress parser can drift from Docker or Podman.
- **Operations:** signal handling is confined to setup and restored before
  process replacement, `WaitDelay` bounds inherited pipes, all previous exit
  semantics remain, and no upgrade migration is required. Release and SBOM
  production remain reproducible through the documented snapshot path.
- **Documentation:** first-run, redirection, cancellation, limits, support
  privacy, testing, and troubleshooting guidance match implementation and the
  cited Docker, Podman, Mutagen, terminal-provider, and Go contracts.

Residual risks: engine-native progress may contain control sequences or image
references supplied by the configured, trusted engine, so it is confined to an
actual terminal and excluded from persistent/support output. A canceled Docker
client is reaped, but its daemon/content store may retain reusable partial
layers. Structured capture can transiently hold a bounded immutable snapshot
beside its collector; the 16 MiB Mutagen allowance is deliberate and should be
optimized only with profiling evidence. Extremely large legitimate terminal
inventories or Mutagen state now fail explicitly instead of exhausting memory.
Quiet non-terminal pulls intentionally offer no ongoing progress. Lima,
Mutagen 0.18.1, and live Docker/Podman engines remain unavailable in this
environment; fake process, PTY, race, fuzz, Darwin, and packaging checks cover
the accessible boundaries. Cycle 23 should isolate and assess the deferred UI
and TOML dependency compatibility upgrades against a fresh product-feature
inventory rather than mixing them into this process-boundary change.

## 28. Continuous-improvement roadmap — Cycle 23

### Product and technical assessment

Pwnbridge automatically discovers and decodes the nearest project TOML file
before most commands. Its own 1 MiB read ceiling and strict typed decoder bound
file memory and reject unknown keys, but the current go-toml 2.2.4 parser
predates an upstream fix that bounds nested arrays/inline tables to prevent a
stack-overflow denial of service. A malicious or simply malformed cloned
repository can therefore reach a parser weakness before Pwnbridge's semantic
validation. The latest 2.4.3 also removes `unsafe`, fixes decoder panics and
wrong EOF locations, implements TOML 1.1, and adds key/position context to
table-placement errors. This is a concrete security, reliability, and config
UX improvement rather than routine dependency churn.

The client-only bootstrap wizard directly uses Bubble Tea, Bubbles, Lip Gloss,
and x/ansi. The pinned Bubble Tea 2.0.2 predates fixes for an infinite loop/CPU
spike while rendering wide characters, a renderer mouse race, a panic when
input is unavailable, an accidental debug file, Kitty release correctness, and
emoji/grapheme rendering. Lip Gloss 2.0.4 fixes a writer panic, 2.0.5 and Bubble
Tea 2.0.8 add the same grapheme improvements, and x/ansi 0.11.7 corrects joining
character width. Bubbles 2.1.1 aligns the component stack and fixes textarea
prompt styling; its dynamic-height feature does not solve a Pwnbridge need and
will remain unused. All selected modules retain a Go requirement at or below
the project's Go 1.25.8 baseline.

The public repository still has no issue or pull-request history indicating a
different missing workflow. Repository inspection confirms that config
validation, config-path discovery, accessible prompts, no-color output,
completion, diagnostics, recovery, first-run bootstrap, and container progress
already exist. A combined connection wizard would duplicate four documented
host operations, and verification checkpoints or recovery pruning carry much
larger persistence/destructive-design risks. The dependency fixes affect the
actual config and wizard journeys and are the most evidenced current product
improvement.

| Rank | Opportunity | User value / severity | Strategic fit | Effort / risk | Evidence and decision |
| --- | --- | --- | --- | --- | --- |
| 1 | Upgrade go-toml and prove bounded pathological config handling | High security/reliability | Very high | Low / medium | Upstream 2.4.3 explicitly fixes nesting stack-overflow DoS and decoder panics; selected |
| 2 | Upgrade the coordinated Charm UI stack and harden Unicode integration | High bootstrap reliability/compatibility | High | Medium / medium | Directly relevant upstream CPU-loop, panic, race, width, and grapheme fixes; selected product improvement |
| 3 | Combined first-host setup wizard | Medium onboarding convenience | Medium | High / medium | Existing `host add/use/doctor/bootstrap` and bootstrap wizard cover the complex path; defer without issue evidence |
| 4 | Persist recovery-verification checkpoints | Medium repeat-work reduction | Medium | High / high | Authenticated mutable checkpoint semantics remain unresolved; defer |
| 5 | Automatic recovery retention/pruning | Medium convenience / high destructive risk | Medium | Medium / high | No safe capacity or operator-policy signal exists; continue to reject |

This cycle selects the two compatible dependency-boundary improvements as one
isolated upgrade. It adds no command, flag, dependency family, configuration,
protocol, persistent state, or automatic mutation. Current APIs and user
workflows must remain compatible.

### Acceptance criteria and implementation plan

1. Establish pre-upgrade benchmarks for strict representative project decode
   and narrow/wide/emoji wizard rendering. Upgrade go-toml from 2.2.4 to 2.4.3,
   keep `DisallowUnknownFields` and the 1 MiB outer bound, retain the Go 1.25.8
   directive, and ensure save/load output and schema migration remain stable.
2. Add an integration regression containing pathological but sub-megabyte
   nested TOML. It must return a bounded, actionable decode error without a
   panic or stack exhaustion. Add malformed table/type cases proving errors
   preserve the config path and useful key/line context; do not expose config
   contents in errors.
3. Upgrade Bubble Tea 2.0.2 to 2.0.8, Bubbles 2.0.0 to 2.1.1, Lip Gloss 2.0.1
   to 2.0.5, and x/ansi 0.11.6 to 0.11.7 as the coordinated compatible stack.
   Let `go mod tidy` select only required indirect updates; inspect the graph
   and sums rather than bulk-upgrading unrelated modules.
4. Add real program-level and model-level regressions for CJK wide characters,
   combining/joining marks, emoji graphemes, constrained widths, no-color
   visibility, ordinary pipe input, interruption, and unavailable input. Views
   must render without panic/hang, never request the alternate screen, retain a
   visible selection, and fit the declared terminal width.
5. Add a bounded Unicode wizard-render fuzz target with representative seeds
   and integrate it into `make fuzz-smoke`, raising the repository total to
   thirteen. It must sanitize control/newline input, constrain payload and
   width, and check the real view-width invariant rather than merely calling an
   upstream helper.
6. Compare post-upgrade benchmarks and module/build sizes against baseline.
   Review API, module graph, minimum Go version, license/SBOM, Darwin build,
   accessibility, terminal restoration, and error-output changes. Update
   security, troubleshooting, development, and dependency guidance only where
   it improves a user/operator journey.
7. Run focused repetitions, race tests, all thirteen fuzz targets, full verify,
   gofmt/vet/staticcheck, gosec, `govulncheck`, module verification, shell
   gates, cross-builds, and an inspected GoReleaser snapshot. Perform the
   independent product/architecture/security/QA/performance/UX/operations/
   documentation audit before recording results and beginning Cycle 24.

### Risks and mitigations

- go-toml 2.4 contains a parser/encoder rewrite and TOML 1.1 support, so valid
  edge cases or serialized formatting can change. Keep typed strict decoding,
  run round-trip/golden behavior, inspect saved configuration, and test actual
  CLI errors. Do not silently relax schema or unknown-field validation.
- Charm patch releases update several rendering transitive dependencies and
  can alter terminal bytes. Test semantic invariants at model and program
  boundaries, real Unicode width, plain/no-color output, normal pipes, race,
  Darwin compilation, and package size instead of pinning fragile escape-byte
  snapshots.
- Fuzzed arbitrary text could consume excessive time or introduce terminal
  controls. Bound input to a few KiB, normalize controls/newlines before view
  construction, and keep invariant checks width-aware.
- A nested-config regression can crash an old parser. Add and execute it only
  after the fixed parser is selected; separately benchmark representative
  ordinary input before and after the upgrade.
- Updating all transitive modules would obscure causality. Pin only the five
  researched direct dependencies, tidy, inspect the diff/graph, and reject
  unrelated upgrades unless required by their module constraints.

### Research references

- [go-toml 2.4.3 nesting bound, panic, and error-context fixes](https://github.com/pelletier/go-toml/releases/tag/v2.4.3)
- [go-toml 2.4 parser rewrite and TOML 1.1 support](https://github.com/pelletier/go-toml/releases/tag/v2.4.0)
- [go-toml 2.3 removal of `unsafe` and decoder fixes](https://github.com/pelletier/go-toml/releases/tag/v2.3.0)
- [Bubble Tea 2.0.8 emoji/grapheme correction](https://github.com/charmbracelet/bubbletea/releases/tag/v2.0.8)
- [Bubble Tea 2.0.7 renderer race, unavailable-input panic, and Kitty fixes](https://github.com/charmbracelet/bubbletea/releases/tag/v2.0.7)
- [Bubble Tea 2.0.6 wide-character infinite-loop fix](https://github.com/charmbracelet/bubbletea/releases/tag/v2.0.6)
- [Bubble Tea 2.0.5 unwanted debug-file removal](https://github.com/charmbracelet/bubbletea/releases/tag/v2.0.5)
- [Bubbles 2.1.1 textarea prompt-style fix](https://github.com/charmbracelet/bubbles/releases/tag/v2.1.1)
- [Lip Gloss 2.0.5 grapheme correction](https://github.com/charmbracelet/lipgloss/releases/tag/v2.0.5)
- [Lip Gloss 2.0.4 writer-panic fix](https://github.com/charmbracelet/lipgloss/releases/tag/v2.0.4)
- [x/ansi 0.11.7 joining-character width fix](https://github.com/charmbracelet/x/releases/tag/ansi%2Fv0.11.7)

### Completed implementation

- Upgraded only the five researched direct dependencies: go-toml 2.4.3,
  Bubble Tea 2.0.8, Bubbles 2.1.1, Lip Gloss 2.0.5, and x/ansi 0.11.7.
  `go mod tidy` moved only their required rendering/transitive modules. The Go
  directive remains 1.25.8, module sums verify, and neither the Charm stack nor
  go-toml appears in the Linux agent dependency graph.
- Retained the existing 1 MiB read ceiling and strict typed decoder. Decode
  failures now preserve the upstream typed error while reporting a concise
  file/line/column/key summary. Multiple unknown fields disclose only the first
  key and a count; configuration values and surrounding source are not echoed.
- Added sub-megabyte 100,000-level array and inline-table regressions. Both are
  rejected by the parser's 10,000-level nesting guard as ordinary positioned
  `DecodeError` values without a panic or stack exhaustion. Typed-value and
  multiple-unknown-key tests cover both contextual error paths.
- Added model and real-program wizard integration for CJK width, combining and
  joining graphemes, family/flag emoji, narrow terminals, pipe input, and
  unavailable input. The bounded Unicode fuzz target uses no-color output,
  enforces selection/line-width/no-alternate-screen invariants, and fails a
  case whose real view render exceeds 250 ms. `make fuzz-smoke` now contains
  thirteen targets.
- Updated configuration, security, troubleshooting, architecture, and
  development guidance at the affected user boundaries. No command, flag,
  format, schema, protocol, persistent state, or automatic mutation changed.
- Staticcheck 2026.1 exposed seven independent existing findings while
  validating the upgrade. They were fixed without suppression: a clearer
  character-membership predicate, three lowercase error strings, a meaningful
  synchronized broker-test access, removal of a redundant Mutagen assignment,
  and removal of a deprecated tar `Xattrs` check. Go's tar reader copies those
  records into `PAXRecords`, which the extractor already rejects, so archive
  policy remains strict.

### Verification and measurements

- Twenty focused config/UI repetitions, three focused race runs, the full unit
  suite, full race suite, `make verify`, vet, Staticcheck 2026.1, gosec,
  `govulncheck` (`No vulnerabilities found`), ShellCheck 0.11.0, `bash -n`,
  module verification, formatting/diff checks, and all cross-builds pass.
- All thirteen fuzz targets pass. The six first targets exercised 60,442
  portable-bootstrap, 47,301 bootstrap-event, 6,150 Unicode-view, 4,960 TOML,
  13,397 diagnostic, and 97,339 protocol cases; the remaining seven exercised
  5,215 recovery, 105,914 shell, 16,396 subprocess, 58,318 sync-health, 23,873
  version, 14,033 ignore, and 3,969 workspace cases. A separate single-worker
  30-second Unicode run rendered 67,059 cases without a deadline failure.
- Configuration package coverage is 65.4%; `decodeOptional` is 100% and the
  contextualizer is 89.5%. Wizard package coverage is 52.2%; the choice view is
  92.9%, terminal view 100%, and real session choice 80%. The deliberately
  dangerous nesting cases execute only after selecting the fixed parser.
- Representative strict project decode improved from 16.168–17.407 us,
  6,656 bytes, and 85 allocations to 13.900–15.590 us, 1,592 bytes, and 49
  allocations: about 15% lower median time, 76.1% fewer allocated bytes, and
  42.4% fewer allocations. Unicode view rendering moved from
  22.645–23.772 us to 26.627–31.074 us with the same 1,856 bytes and 30
  allocations. The roughly 5 us/~20.6% median latency cost is accepted for
  corrected complex-grapheme behavior in a human-paced setup screen.
- Cross binaries are 8,830,690-byte arm64 client, 9,306,640-byte amd64 client,
  and 5,056,457-byte Linux agent. Stripped snapshot binaries are 8,866,626,
  9,432,752, and 3,489,954 bytes respectively, all well below the 16 MiB caps.
  Relative to Cycle 22, release clients grew 133,664/157,216 bytes
  (~1.5%/~1.7%) and the agent is byte-size unchanged.
- The inspected snapshot has six valid checksums, three readable archives,
  matching standalone/embedded agent bytes in both clients, and three SBOMs
  that convert to SPDX 2.3. It packages the current documentation and plan; a
  final snapshot is rebuilt after this append-only completion record.

### Independent post-implementation audit

- **Product:** Config discovery and first-run bootstrap now survive concrete
  hostile-input and terminal cases that upstream fixed. The change improves
  existing journeys without inventing a weakly evidenced command.
- **Architecture:** Both dependency families stay behind their existing narrow
  config/UI boundaries. No abstraction, persistent state, or cross-platform
  agent coupling was added.
- **Security:** File size, parser depth, strict schema, value-private errors,
  fuzzing, vulnerability scanning, and agent graph isolation are verified. The
  upstream 10,000-level guard is defense in depth inside Pwnbridge's 1 MiB cap.
- **QA:** Parser-error types, positions, multiple unknown keys, pathological
  nesting, grapheme width, program input, races, fuzz deadlines, Darwin builds,
  and release contents all have regression evidence.
- **Performance:** Ordinary config parsing materially improves. Complex
  Unicode rendering has a measured microsecond regression but unchanged
  allocation and negligible impact on a human interaction; retain the
  benchmark to detect disproportionate future cost.
- **UX:** Errors point directly to a file/key/location without exposing values,
  and narrow Unicode choices remain selectable, readable, and inline. Existing
  accessible/no-color fallbacks remain unchanged.
- **Operations:** Minimum Go compatibility, module integrity, binary caps,
  checksums, embedded-agent identity, and SBOM conversion pass. No migration or
  operator action is required.
- **Documentation:** User, troubleshooting, security, architecture, and
  contributor guidance describe the exact new behavior and verification path.

### Residual risk and next targets

- The parser's 10,000-level limit is upstream policy, although ordinary valid
  configuration is many orders shallower and Pwnbridge also caps file bytes.
  File paths and key names can themselves contain local metadata; normal CLI
  diagnostics need them for repair, while support reports continue to emit
  only error categories.
- The unavailable-input regression exits immediately by design; ordinary pipe
  input traverses the real selection session. No live macOS interactive
  bootstrap, Lima, or Mutagen 0.18.1 environment is available, so program
  integration, races, Darwin cross-builds, and package inspection are the
  accessible evidence.
- Cycle 24 must return to high-value product/workflow assessment rather than
  continuing dependency churn. Reassess the complete first-host, conflict,
  recovery, and diagnosis journeys against current ecosystem behavior and
  issue evidence, then select only an end-to-end feature with stronger value
  than its state/destructive complexity.

## 29. Continuous-improvement roadmap — Cycle 24

### Product and technical assessment

Pwnbridge now creates durable, integrity-bound recovery archives before every
conflict loser is removed, and users can list, verify, and restore them. It
deliberately never deletes them. This preserves safety but leaves the lifecycle
incomplete: every resolved core dump, binary tree, or generated artifact
consumes local XDG data forever, the support report exposes only a coarse count,
and the documented escape hatch is effectively an unsupported manual `rm` that
bypasses catalog boundaries and workspace serialization. Finite disk is not a
speculative concern for pwn workloads, where cores and container-adjacent build
artifacts can be large.

Established backup tools treat retention as an explicit backup-unit operation.
Restic can forget exact snapshot IDs or apply a keep policy and recommends
previewing with `--dry-run`; Borg deletes/prunes whole archives, offers dry-run
listing, and warns that pruning is destructive. Both avoid pretending that
individual files inside a backup are independent retention units. Pwnbridge
already has the analogous natural unit: one timestamped archive groups every
loser from one conflict-resolution invocation under one manifest. Pruning only
whole archives avoids non-atomic per-entry manifest/data rewrites.

The public GitHub API contains no issues or pull requests requesting a
different workflow. Current repository journeys already cover first-host
registration/doctor/bootstrap, project initialization, conflicts, recovery,
support, runtime setup, and accessible bootstrap. A combined host setup wizard
could reduce four documented commands, but safely composing connection
validation, remote mutation, post-checks, recipe flags, rollback, and
non-interactive behavior is substantially larger and still lacks user evidence.
The recovery capacity gap is smaller, concrete, and completes an existing
safety promise.

| Rank | Opportunity | User value / severity | Strategic fit | Effort / risk | Evidence and decision |
| --- | --- | --- | --- | --- | --- |
| 1 | Previewable whole-archive recovery pruning | High operational reliability and completed recovery lifecycle | Very high | Medium / high destructive risk | Recovery is unbounded today; Restic/Borg use explicit archive/snapshot retention and dry runs; selected |
| 2 | Combined host registration/doctor/bootstrap setup | Medium-high onboarding convenience | High | High / medium | Four commands remain, but mutation/rollback and automation surface are unresolved; defer |
| 3 | Partial-result catalog listing when one archive is corrupt | Medium recovery availability | High | Medium / medium | Verification already preserves per-entry failures; listing remains fail-closed by design; reassess after pruning without weakening restore discovery |
| 4 | Persist verification checkpoints or enroll legacy digests | Medium repeat-work reduction | Medium | High / high | A newly computed digest is not historical evidence and mutable checkpoints need authentication semantics; continue to reject |
| 5 | Automatic age/size pruning | Medium convenience / high surprise risk | Medium | Medium / high | No operator policy or safe default exists; explicitly excluded from this cycle |

This cycle adds one `sync recovery prune` workflow with archive-granular
retention. It adds no daemon, dependency, configuration, background work,
network operation, automatic schedule, per-entry rewrite, or deletion outside
the current workspace's recovery root.

### Acceptance criteria and implementation plan

1. Add a typed recovery archive inventory that aggregates exact timestamped
   archive IDs, creation time, entry count, logical bytes/items, and legacy
   status from the existing strict catalog. Preserve newest-first ordering,
   reject overflow/corrupt manifests, and never infer an archive from an
   unrecognized directory.
2. Add `pwnbridge sync recovery prune --keep-last N (--dry-run|--yes) [--json]`.
   Require `N >= 1`, make preview and mutation mutually exclusive and explicit,
   retain the newest N complete archives, and report every selected archive plus
   aggregate counts/bytes. Zero-selection operation must be a successful no-op.
3. Hold the existing workspace mutation lock for inventory and pruning. Never
   invoke SSH, Mutagen, the agent, or synchronization. Work only on whole archive
   directories selected from the locked strict inventory; never rewrite a
   manifest or choose individual entries.
4. Before recursive deletion, descriptor-relatively rename each selected
   archive to a private, grammar-validated hidden tombstone in the same recovery
   root and sync the root directory. POSIX makes the directory rename atomic;
   the directory sync makes the catalog removal durable. A crash can therefore
   leave either a visible intact archive or an ignored tombstone, not a visible
   half-deleted manifest tree.
5. Remove tombstones through held `os.Root` descriptors with context checks
   between entries and without following symbolic links. A later confirmed
   prune must clean a valid stale Pwnbridge tombstone before selecting new work.
   Cancellation or cleanup failure must retain an ignored tombstone, report
   incomplete space reclamation, and remain safely retryable.
6. Test preview/confirmation grammar, archive ordering and aggregation,
   keep-at-least-one, full-archive grouping, legacy archives, exact tombstone
   grammar, symlink/special/race containment, stale cleanup, cancellation after
   durable rename, partial JSON/human reports, output failures, empty roots, and
   absence of network/tool execution. Add realistic tree benchmarks and compare
   catalog/prune cost with the existing baseline.
7. Document discovery, preview, confirmation, logical-size meaning, archive
   granularity, lock behavior, crash/cancellation recovery, and the fact that
   pruning is irreversible and never touches either synchronized workspace.
   Update CLI help, README, troubleshooting, architecture, security, development,
   and E2E guidance where the complete journey needs it.
8. Run focused repetitions, races, all fuzz targets, full verify, vet,
   Staticcheck, gosec, `govulncheck`, module/shell checks, Darwin/agent builds,
   and an inspected release snapshot. Review product, architecture, security,
   QA, performance, UX, operations, and documentation independently before
   beginning Cycle 25.

### Risks and mitigations

- Pruning destroys the only Pwnbridge-managed losing copy. Require an explicit
  keep count of at least one and either a successful dry-run or `--yes`; select
  exact complete archives only, quote IDs, and never add a default retention
  policy or implicit pruning to another command.
- Recursively deleting an archive in place can expose a half-deleted catalog
  after interruption. Atomically rename within the held root, durably sync that
  namespace change, then reclaim the hidden tree. Strictly recognize only
  Pwnbridge-generated random tombstone names on retries.
- A huge tree can make removal slow. Check context between descriptor-rooted
  entries, expose completion/pending-cleanup status, benchmark representative
  trees, and do not hold content in memory. The workspace lock intentionally
  excludes concurrent barriers/resolutions while mutation is active.
- Logical sizes do not equal allocated disk blocks or account for filesystem
  compression. Label them as logical bytes and avoid promising exact reclaimed
  capacity.
- A corrupt catalog could tempt deletion based only on directory names. Keep
  strict fail-closed inventory: repair or manually inspect corruption rather
  than allowing prune to guess backup boundaries.
- Same-account code can still mutate private state between operations. Held
  roots prevent path escape, archive selection is rechecked under the workspace
  lock, and replacement can affect only an object inside the recovery root; the
  local Unix account remains trusted as documented.

### Research references

- [Restic snapshot removal, retention, pruning, and dry-run guidance](https://restic.readthedocs.io/en/stable/060_forget.html)
- [Borg archive deletion, soft deletion, and dry-run guidance](https://borgbackup.readthedocs.io/en/master/usage/delete.html)
- [Borg prune retention policies and destructive-operation warning](https://borgbackup.readthedocs.io/en/stable/usage/prune.html)
- [POSIX atomic and serializable directory-operation requirements](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [POSIX rationale for directory synchronization after rename](https://pubs.opengroup.org/onlinepubs/9799919799/xrat/V4_xbd_chap01.html)
- [Go 1.25 `os.Root` rename/remove additions](https://go.dev/doc/go1.25)
- [Go `os.Root` descriptor-relative API](https://pkg.go.dev/os#Root)
- [Mutagen conflict resolution remains explicit endpoint deletion](https://mutagen.io/documentation/synchronization)

### Completed implementation

- Added strict newest-first archive inventory over the existing manifest and
  conservative legacy catalogs. It aggregates one resolution invocation into
  an exact timestamped retention unit with entry, logical-byte, item, and
  legacy totals; corrupt structure or integer overflow fails closed.
- Added `sync recovery prune --keep-last N (--dry-run|--yes) [--json]`.
  At least one newest archive must remain, preview and mutation are explicit
  and mutually exclusive, archive IDs are quoted in human output, and schema-one
  JSON reports per-archive `would-prune`, `pruned`, `pending-cleanup`, or
  `not-run` status plus kept/selected/pruned/pending/not-run/logical-byte totals.
  Zero selection is a successful no-op.
- Both preview and mutation inventory under the workspace lock. Pruning is
  entirely local and never constructs SSH, Mutagen, agent, or synchronization
  clients. Slow terminal cleanup uses the existing delayed path-free transient
  status; JSON and redirection stay quiet until the final report.
- Before reclamation, each complete selected archive is descriptor-relatively
  renamed to a 96-bit-random, grammar-validated hidden tombstone in the same
  recovery root and the root is synced. A failed stage sync rolls the visible
  archive back before returning. Recursive removal checks cancellation between
  entries, verifies opened-directory identities, removes links themselves,
  and refuses both nested and top-level filesystem/mount crossings.
- Cancellation or cleanup failure after the durable rename reports the archive
  as hidden but `pending-cleanup`. The next confirmed prune removes only exact
  valid Pwnbridge tombstones before new mutation; dry-run and unrelated hidden
  directories remain untouched. Manifests are never rewritten and neither
  synchronized workspace is ever a deletion target.
- Tests cover grouped modern and legacy inventory, ordering, overflow, preview,
  confirmation grammar, human/actual JSON/no-op reports, offline operation,
  keep-at-least-one, corrupt catalogs, symlink and post-rename replacement,
  synthetic device crossings, cancellation, stale retry, unrelated hidden
  data, duplicate/stale selection, stage-sync rollback, missing roots, partial
  statuses, and output failure. The Lima journey now previews and confirms a
  real two-archive prune, validates JSON, and proves the old ID is unavailable.
- Updated README, CLI, troubleshooting, architecture, security, development,
  help, and E2E guidance for archive granularity, irreversibility, logical size,
  crash recovery, locking, progress, and offline behavior. No dependency,
  configuration, schema, protocol, daemon, automatic policy, or background job
  was added.

### Verification and measurements

- Twenty focused CLI/recovery repetitions, focused and full race suites, full
  unit tests, `make verify`, vet, Staticcheck 2026.1, gosec, `govulncheck` (`No
  vulnerabilities found`), module verification, ShellCheck 0.11.0, `bash -n`,
  formatting/diff checks, and Darwin/agent cross-builds pass.
- All thirteen fuzz targets pass, exercising 20,990 portable-bootstrap, 46,002
  bootstrap-event, 2,927 Unicode-view, 3,564 TOML, 22,907 diagnostic, 84,089
  protocol, 193 recovery-archive, 106,390 shell, 52,614 subprocess, 64,885
  sync-health, 20,801 version, 18,612 ignore, and 8,998 workspace cases.
- Recovery package coverage is 77.7%. Archive inventory is 88.9%, the exported
  prune boundary 100%, core prune state transitions 75.8%, tombstone grammar
  91.7%, and context/rooted removal 70.6%. CLI coverage is 53.7%; prune
  selection and result application are 100%, report construction 90.9%, the
  integrated recovery command 85.7%, and rendering 72.7%.
- The existing strict 100-entry list benchmark remains allocation-identical at
  1,280 allocations/~205.2 KiB and measures 1.375–1.445 ms versus the
  pre-change 1.430–1.561 ms—overlapping runner variance, not a claimed speedup.
  Strictly re-inventorying, durably renaming, syncing, and descriptor-removing a
  100-file archive takes 1.588–1.680 ms, ~234.7 KiB, and 1,522 allocations.
  It streams filesystem traversal and does not read retained file contents.
- Cross binaries are 8,864,546-byte arm64 client, 9,348,448-byte amd64 client,
  and 5,056,489-byte Linux agent. Stripped snapshot binaries are 8,900,530,
  9,474,560, and 3,489,954 bytes. Relative to Cycle 23, clients grew only
  33,904/41,808 release bytes; the stripped agent is unchanged (the unstripped
  cross agent differs by 32 bytes).
- The inspected snapshot has six valid checksums, three readable archives,
  exact standalone/embedded agent equality in both clients, current prune help
  and documentation, and three SBOMs that convert to SPDX 2.3. The final
  snapshot is rebuilt after this append-only completion record.

### Independent post-implementation audit

- **Product:** Users can now complete the recovery lifecycle and reclaim finite
  storage without unsupported manual catalog deletion. Archive granularity and
  keep-at-least-one deliver value without inventing an automatic retention
  policy.
- **Architecture:** The feature composes the existing strict catalog, workspace
  lock, `os.Root`, durability helpers, JSON envelope, and progress primitive.
  It adds no manifest migration or coupling to sync/network state.
- **Security:** Destruction requires an explicit preview or confirmation mode,
  preserves one newest archive, fails on catalog ambiguity, uses durable
  same-root random tombstones, rejects links/mount crossings, and confines
  replacement races to the trusted recovery root.
- **QA:** Modern/legacy grouping, multiple-entry atomicity, corrupt/overflowing
  catalogs, cancellation after rename, failed durability rollback, stale
  cleanup, hostile replacement, partial output, Darwin compilation, E2E script,
  races, fuzzing, and packaging all have regression evidence.
- **Performance:** Selection is manifest-derived and reclamation is streaming.
  A representative 100-file archive completes around 1.6 ms with modest bounded
  metadata allocation; the workspace lock cost is proportional to entries
  actually removed.
- **UX:** Dry-run prints the exact deletion cohort, logical sizes are labeled,
  IDs are quoted, actual JSON is complete and scriptable, slow terminals receive
  transient feedback, and incomplete cleanup has an actionable retry state.
- **Operations:** A crash yields an intact visible archive or an ignored durable
  tombstone. Confirmed reruns reclaim valid stale tombstones; unrelated state,
  both workspaces, synchronization, the network, and the Linux agent remain
  unaffected.
- **Documentation:** Discovery, dry-run, confirmation, retention unit, size
  semantics, irreversibility, cancellation/crash behavior, security boundary,
  development coverage, and the real conflict journey are documented.

### Residual risk and next targets

- The command deliberately cannot prune the newest archive or select by age,
  size, or individual entry. This prevents accidental total erasure and policy
  bloat but can retain one very large archive; no evidence yet justifies an
  override or automatic schedule.
- Recursive deletion is linear and holds the workspace lock. Huge directory
  trees show a path-free spinner rather than item-level percentages; a mounted
  subtree blocks cleanup until unmounted. A killed process can leave hidden
  space until the next confirmed prune, while dry-run remains strictly
  non-mutating.
- Logical bytes exclude filesystem block allocation, metadata, compression,
  and sparse-file effects. Corrupt catalogs continue to block both selection and
  pruning rather than guessing archive boundaries.
- The local Unix account remains trusted and can alter recovery state directly.
  No live Lima, macOS interaction, or Mutagen 0.18.1 environment is available;
  unit/fake integration, races, cross-builds, shell-validated E2E, and inspected
  packages are the accessible layers.
- Cycle 25 should reassess the deferred combined host setup journey against the
  now-complete recovery lifecycle, but must solve mutation/rollback and
  automation semantics before adding a convenience wrapper. Also inspect
  partial-result recovery catalog diagnosis and packaging/onboarding evidence
  before selecting the next end-to-end improvement.

## 30. Continuous-improvement roadmap — Cycle 25

### Product and technical assessment

The first-host journey still has one high-impact gap after the recovery
lifecycle work. `host add` writes an endpoint without attempting ordinary SSH,
silently replaces an existing record, and loads portable project configuration
even though it mutates only machine-global XDG state. A typo, unsupported host,
unwritable/full home, unusable bootstrap plan, or disabled required reverse
forwarding is therefore discovered only by a later command, while an unrelated
malformed `.pwnbridge.toml` can prevent registration entirely. The README also
asks users to run `host default` after adding their first host even though the
first record already becomes the default.

Current remote-development guidance validates connection capability at the
configuration boundary. VS Code Remote SSH tells users to verify ordinary SSH
before connecting and provides an explicit add-host flow. DevPod parses and
validates provider options when the provider is added and recommends provider
initialization validation when those options change. Docker separates context
creation from context update, rather than advertising silent replacement as
one operation. OpenSSH documents bounded connection setup and explicit
forwarding-failure behavior; Pwnbridge already has separately bounded,
read-only inventory and reverse-forwarding probes built on those semantics.

| Rank | Opportunity | User value / severity | Strategic fit | Effort / risk | Evidence and decision |
| --- | --- | --- | --- | --- | --- |
| 1 | Transactional validated host registration | High onboarding reliability and configuration safety | Very high | Medium / low-medium | Current add persists unverified endpoints, silently overwrites, and is incorrectly project-coupled; existing read-only probes support a bounded implementation; selected |
| 2 | Combined add/doctor/bootstrap wizard | Medium-high command-count reduction | High | High / medium-high | Still conflates local persistence, interactive authentication, privileged remote mutation, recipes, retries, and rollback; reject until evidence outweighs that complexity |
| 3 | Partial-result corrupt recovery catalog diagnosis | Medium recovery supportability | High | Medium / medium | Would improve explanation but not repair a corrupt archive; strict fail-closed behavior remains safer and validated pruning now completes normal lifecycle; defer |
| 4 | Packaging installer/updater | Medium installation convenience | Medium | High / high supply-chain and platform risk | Homebrew/source/release paths are documented and verified; no issue evidence justifies another privileged/networked installer |
| 5 | Automatic registration checks on every add | Medium safety / possible automation friction | Medium | Low / medium | Interactive SSH can be intentional; retain fast local-only add and make remote validation explicit with `--check` |

This cycle adds an end-to-end `host add --check` path plus explicit replacement
and default-selection semantics. It does not bootstrap, deploy an agent, invoke
sudo, write remotely, refresh repositories, install packages, edit OpenSSH
configuration, or introduce a new dependency, daemon, schema, or protocol.

### Acceptance criteria and implementation plan

1. Make host registration load and validate global configuration only. Preserve
   the existing first-host default, add `--default` for an intentional default
   change, and refuse an existing name unless `--replace` is supplied. A failed
   validation, check, cancellation, or output preparation must leave the prior
   durable configuration unchanged.
2. Add `host add NAME DESTINATION --check [--replace] [--default] [--json]`.
   Under the established 20-second inventory and 15-second forwarding budgets,
   run only the existing ordinary read-only inventory and private temporary
   forwarding probes. Never deploy the agent, invoke SCP/Mutagen, create a
   remote file, install, or persist before the complete report is healthy.
3. Derive registration readiness from the same inventory and bootstrap plan as
   doctor/bootstrap, but do not classify merely missing installable components
   as registration failures. Require Linux/amd64, a writable home, known free
   space/inodes above the documented minima, non-blocking ptrace policy, an
   executable built-in `pwn` bootstrap plan, and reverse forwarding when the
   global terminal scope needs it. Report optional forwarding accurately for
   remote terminal scope.
4. Emit one bounded, control-safe human readiness report before the success
   line, or one schema-one JSON result containing candidate identity,
   persistence/default/replacement state, and the complete/partial check report.
   A failed check must be script-detectable through both structured output and a
   nonzero exit status without leaking the destination into generic errors.
5. Test new/successful/failed/replaced/default registration, unchanged prior
   records on failure, invalid-project independence, duplicate refusal before
   network access, JSON and human output, required/optional forwarding,
   inventory/forwarding timeouts, parent cancellation, output errors, and exact
   remote command non-mutation. Keep the no-check path fast and offline.
6. Update README setup, CLI/configuration/installation/troubleshooting/security/
   architecture/development guidance, help, completions, and Lima E2E coverage.
   Clearly distinguish local-only add, read-only checked add, doctor health, and
   explicit mutating bootstrap; document the `--replace` compatibility change.
7. Measure the new pure readiness collector against the current remote-doctor
   baseline (24.5–25.7 us, 21,042 bytes, 72 allocations on this runner), run
   focused repetitions, races, all fuzz targets, full verify, vet, Staticcheck,
   gosec, `govulncheck`, module/shell checks, Darwin/agent builds, and an
   inspected release snapshot.
8. Independently review product value, architecture, security, QA, performance,
   UX, operations, and documentation before recording completion and beginning
   Cycle 26.

### Risks and mitigations

- Remote authentication may be interactive and slow. Keep checking opt-in,
  reuse established independent budgets, preserve normal OpenSSH host-key and
  authentication behavior, report timeout versus evaluated failure, and honor
  parent cancellation deterministically.
- A check could accidentally become bootstrap. Restrict it to `Inspect`, plan
  construction, and the existing forwarding probe; test command transcripts
  against deployment, file-creation, package, sudo, SCP, and Mutagen markers.
- A slow check widens the interval between reading and writing global config.
  Run probes outside a shared global mutation lock, then acquire it, reload the
  latest file, re-evaluate duplicate/default semantics, validate, and atomically
  save. Route every CLI global read-modify-write through that short transaction
  so unrelated concurrent updates are retained.
- Treating missing tools as fatal would make every fresh host fail. Validate
  whether the resolved bootstrap plan can satisfy them; report pending actions
  informationally and fail only platform/resource/policy/plan blockers.
- Replacement can destroy a working endpoint reference. Require explicit
  `--replace`, build and validate the complete candidate before probes, and
  atomically save only after every requested check succeeds. Keep the old file
  intact on all earlier failures.
- `--default` can redirect future unbound projects. Make it opt-in except for
  the already-established first-host behavior and report the resulting state in
  both human and JSON output.
- A global terminal configuration may not require reverse forwarding. Reuse
  doctor's scope-aware classification so `terminal.scope=remote` records an
  unavailable probe as optional rather than rejecting an otherwise usable host.

### Research references

- [VS Code Remote SSH setup and connection verification](https://code.visualstudio.com/docs/remote/ssh)
- [DevPod provider add and option configuration](https://devpod.sh/docs/managing-providers/add-provider)
- [DevPod provider option validation guidance](https://devpod.sh/docs/developing-providers/options)
- [Docker context creation and separate update workflow](https://docs.docker.com/reference/cli/docker/context/create/)
- [OpenSSH client configuration: BatchMode, ConnectTimeout, and ExitOnForwardFailure](https://man.openbsd.org/ssh_config)
- [OpenSSH client `-G`, control operations, and allocated remote ports](https://man.openbsd.org/ssh)

### Completed implementation

- Added `host add NAME DESTINATION --check [--replace] [--default]
  [--json]`. Checked registration validates ordinary SSH, Linux amd64, writable
  home, known minimum disk/inodes, ptrace policy, full built-in `pwn` plan
  feasibility, and scope-required reverse forwarding before saving. Missing
  installable capabilities are reported as pending bootstrap actions rather
  than rejected as unhealthy.
- Kept registration explicitly non-mutating on the remote: it uses only the
  existing bounded inventory and temporary private forwarding probe. Tests
  record SSH argv and exclude agent deployment, SCP, Mutagen, file creation,
  package refresh/install, and bootstrap execution. Parent cancellation and
  collector timeouts retain a complete/partial report and never save the
  candidate.
- Existing host names now require `--replace`; checked replacement preserves
  the old durable record on every failed probe. `--default` intentionally
  changes the machine fallback, while the established first-host automatic
  default remains. Human output uses the bounded control-safe diagnostic
  renderer with a `host check` footer; schema-one JSON reports candidate,
  persisted/replaced/default state, and the exact ordered check report.
- Made `host add`, `host transport`, and `host default` independent of malformed
  project-local configuration. Introduced one shared short global-config
  transaction for every CLI global mutation: acquire the owner-private XDG
  state lock, reload the latest global file, apply and validate the mutation,
  then use the existing durable atomic write. Saved recipe changes, bootstrap
  profile binding, and host removal now use it as well.
- Kept the slow SSH check outside that lock. Commit re-evaluates duplicate and
  default state against the fresh file, merges unrelated concurrent changes,
  refuses a same-name race without explicit replacement, and aborts if terminal
  scope changed so an optional-forwarding result cannot become stale required
  policy.
- Updated the first-run journey to checked registration plus explicit bootstrap,
  removing the redundant first-host `host default` step. README, CLI,
  configuration, installation, troubleshooting, architecture, security,
  development, generated completion expectations, and the Lima journey cover
  offline add, checked add, health doctor, replacement compatibility, JSON,
  locking, and mutation boundaries. No dependency, schema, protocol, agent,
  daemon, automatic network behavior, or remote mutation was added.

### Verification and measurements

- Twenty focused repetitions, focused and full race suites, full unit tests,
  `make verify`, vet, Staticcheck 2026.1, gosec, `govulncheck` (`No
  vulnerabilities found`), module verification, ShellCheck 0.11.0, shell
  syntax, formatting/diff checks, realistic local CLI use, Darwin/agent builds,
  and all thirteen fuzz targets pass.
- Fresh fuzz runs exercised 104,437 portable-bootstrap, 82,465 bootstrap-event,
  9,296 Unicode-view, 2,712 strict-TOML, 35,611 diagnostic, 151,105 protocol,
  73 recovery-archive, 170,955 shell, 10,104 subprocess, 115,009 sync-health,
  38,047 version, 39,382 ignore, and 2,749 workspace cases without a failure.
- Combined CLI/diagnostics coverage is 56.2%. Registration readiness and common
  remote prerequisites are 100%, result rendering 100%, integrated add 91.5%,
  registration collection 80.0%, labeled diagnostic rendering 89.5%, and the
  global transaction 71.4%. Timeout, cancellation, concurrent writer/policy,
  output-error, invalid-project, and exact no-remote-mutation paths are covered.
- The pure full-`pwn` registration collector takes 30.9–38.7 us, 17,697 bytes,
  and 80 allocations on this runner. The pre-change minimal-profile doctor
  baseline was 24.5–25.7 us, 21,042 bytes, and 72 allocations. The extra few
  microseconds resolve the larger feasibility plan; registration allocates
  about 3.3 KiB less, and real latency is dominated by bounded SSH probes.
- Cross binaries are 8,881,282-byte arm64 client, 9,365,056-byte amd64 client,
  and 5,056,481-byte Linux agent. Stripped snapshot binaries are 8,917,266,
  9,499,360, and 3,489,954 bytes. Relative to Cycle 24, client cost is only
  16,736/24,800 stripped bytes and the stripped agent is unchanged.
- The inspected snapshot has six valid checksums, three readable archives,
  exact standalone/embedded agent equality in both clients, generated
  `--check`/`--replace`/`--default` completions, current documentation, and
  three SBOMs that convert to SPDX 2.3. The final snapshot is rebuilt after the
  append-only completion records below.

### Independent post-implementation audit

- **Product:** First-host setup is now two purposeful commands: checked
  registration and explicit bootstrap. Failures are caught before a bad record
  exists, while offline and automation users retain an explicit fast path.
- **Architecture:** Registration composes the existing typed inventory,
  planner, diagnostics, forwarding adapter, atomic writer, and workspace lock.
  The shared fresh-read transaction removes a broader lost-update weakness
  without placing network work or UI under a lock.
- **Security:** Host-key/authentication policy remains OpenSSH's responsibility;
  the check disables none of it and performs no remote writes or privilege
  changes. Duplicate replacement is explicit, output is bounded/control-safe,
  and stale forwarding policy fails closed before persistence.
- **QA:** New, replacement, default, malformed-project, unhealthy platform/home/
  disk, required/optional forwarding, both timeouts, cancellation, output
  failure, concurrent updates, concurrent policy changes, no-network local add,
  help/JSON/human output, fake argv, races, fuzzing, and packaging have evidence.
- **Performance:** Commit locking covers only a local reload/validate/fsync
  transaction. The pure full-plan collector is tens of microseconds and bounded
  output/inventory caps are unchanged; the two sequential SSH probes intentionally
  avoid competing password or hardware-token prompts.
- **UX:** The first host is visibly default, replacement/default selection is
  explicit, failures say configuration was unchanged, healthy missing tools are
  described as pending actions, JSON is one stable envelope, and doctor remains
  discoverable as installed-health rather than registration readiness.
- **Operations:** All CLI global writers merge from fresh durable state under one
  owner-private lock. Checks remain retryable and a failure cannot damage an old
  endpoint. Packages contain current help, completions, docs, agent, checksums,
  and SBOMs.
- **Documentation:** Setup, command reference, compatibility change, failure
  recovery, trust/mutation boundary, concurrency behavior, test coverage, and
  the real Lima acceptance path are documented end to end.

### Residual risk and next targets

- Checked registration is opt-in so existing offline automation does not gain
  network behavior. It evaluates the built-in `pwn` profile and remote
  readiness, not local Mutagen/macOS/provider health or arbitrary future saved
  profiles; `doctor` and bootstrap preview remain the appropriate broader
  views.
- Authentication and host-key prompts still follow the user's OpenSSH config.
  The 20/15-second budgets may be too short for a slow manual token interaction;
  retry after making ordinary SSH reliable. A direct text editor does not honor
  the advisory CLI lock, and same-account state remains inside the documented
  trust boundary.
- Advisory lock acquisition is not context-aware while another live CLI process
  owns it, but every migrated callback is bounded local work and no network,
  TTY, package, or bootstrap execution occurs inside the lock. A successful
  durable save can still be followed by a stdout write failure; the command
  returns that error and the valid configuration remains applied.
- No live Lima, macOS interaction, or Mutagen 0.18.1 environment is available.
  Fake-executable integration, shell-validated E2E, races, fuzzing, cross-builds,
  and inspected snapshots are the accessible evidence.
- Cycle 26 must again prioritize a complete user-facing capability. Reassess
  recovery-catalog repair/diagnosis, host removal/binding lifecycle, and actual
  daily pwn workflows against issue/ecosystem evidence; do not turn the now-safe
  registration path into a privileged combined wizard without a coherent retry
  and rollback model.

## 31. Continuous-improvement roadmap — Cycle 26

### Product and technical assessment

Host deletion is currently the largest user-visible lifecycle hazard. `host
remove NAME` immediately deletes the machine-global endpoint, requires the
current project's portable configuration to be valid, and clears at most that
one project's binding. It does not inspect other bindings, managed workspace
state, retained remote workspaces, conflict-recovery copies, or live sessions.
Removing a default or in-use host can therefore leave local state and remote
data dangling with no preview, confirmation, or recovery guidance.

The repository has no open or closed GitHub issues to override this evidence;
all fourteen published releases predate a complete host-retirement workflow.
Comparable stateful CLIs protect this boundary. Docker exposes context listing
and requires force to remove a context in use. Terraform refuses deletion of
the current workspace or one tracking resources unless force is explicit,
because otherwise resources become unmanaged and dangling. Kubernetes' simple
`delete-context` is not the right model here: a Pwnbridge host owns references
to synchronization history, retained remote roots, and recovery data rather
than only a connection tuple.

| Rank | Opportunity | User value / severity | Strategic fit | Effort / risk | Evidence and decision |
| --- | --- | --- | --- | --- | --- |
| 1 | Previewable, reference-aware host retirement | High data/recovery safety and operational clarity | Very high | Medium / medium | Current deletion silently strands managed resources; established stateful CLIs guard in-use removal; selected |
| 2 | Global managed-workspace list and forget commands | Medium-high multi-project visibility | High | Medium-high / medium | Valuable follow-on, but a durable identity catalog and safe removal semantics should land first rather than exposing incomplete legacy records |
| 3 | Recovery-catalog repair | Medium supportability | High | High / high data-integrity risk | Strict diagnosis exists and guessing damaged archive boundaries remains unsafe; defer |
| 4 | Pwn binary inspection/checksec wrapper | Medium convenience | Medium-low | Low / dependency and scope risk | Existing `pb file`, `pb checksec`, and `pb pwninit` preserve upstream tools without duplicating their interfaces; reject |
| 5 | Combined setup/bootstrap wizard | Medium command-count reduction | High | High / high rollback risk | Checked registration already fixes early failure; privileged mutation still needs separate retry semantics; defer |

This cycle implements safe host retirement end to end. It adds no remote
deletion, synchronization action, background inventory, daemon, dependency, or
automatic cleanup policy. Forced removal deliberately preserves referenced
local metadata so re-adding the same host name remains a recovery path.

### Acceptance criteria and implementation plan

1. Replace instant `host remove NAME` with `host remove NAME
   (--dry-run|--yes) [--force] [--json]`. Preview must be offline and
   non-mutating. Confirmation must emit the same bounded report and delete only
   the global host record; default-host removal, bindings, managed workspace
   resources, and unattributed recovery roots block normal removal.
2. Persist canonical local project identity and remote-retention state in a new
   internal workspace-state schema, and canonical project identity in a new
   binding schema. Continue strictly reading schema-one records, mark their
   missing identity as legacy, and write only schema two on the next normal
   save. Validate filenames, IDs, paths, ownership, privacy, size, counts, and
   unknown fields before trusting catalog entries.
3. Inventory all owner-private binding and workspace records plus non-empty
   recovery roots. Report project paths where schema two provides them, stable
   workspace IDs otherwise, active synchronization/runtime markers, retained
   remote roots, recovery presence, default status, and exact blocker reasons.
   Bound every directory and report collection so damaged XDG state cannot
   cause unbounded memory or output.
4. Treat active Pwnbridge session leases as a non-overridable blocker, including
   with `--force`. A corrupt/unsafe binding, workspace, recovery, or relevant
   session record must fail closed. Force may override only known inactive
   references and must leave those references intact, explicitly documenting
   that re-adding the identical name restores management.
5. Correct `clean` lifecycle bookkeeping. A local-only clean must retain an
   inactive catalog record stating that the remote root remains. A confirmed
   remote clean marks the root absent; recovery presence remains independently
   discoverable. State-write failure after remote deletion must conservatively
   retain the old record rather than permit an unsafe host removal.
6. Re-inventory inside the existing serialized global-config transaction before
   confirmation commits, so concurrent CLI bindings/state that appear before
   the final check block normal deletion. Keep malformed project-local TOML,
   SSH, Mutagen, the remote agent, and network availability outside this local
   global operation.
7. Test schema migration, catalog bounds and hostile entries, default/binding/
   workspace/recovery blockers, preview/confirmation grammar, force semantics,
   live-session refusal, stale metadata preservation, malformed-project
   independence, JSON/human/control-safe output, output/save failures, and
   clean retention transitions. Add a realistic local CLI journey and Lima E2E
   assertions without making the shell tests depend on deletion.
8. Update README, CLI/configuration/troubleshooting/security/architecture/
   development guidance and generated help. Measure representative catalog
   inventory, then run repeated focused tests, races, all fuzz targets, full
   verification, vet, Staticcheck, gosec, `govulncheck`, module/shell checks,
   Darwin/agent builds, and an inspected release snapshot.
9. Independently review product, architecture, security, QA, performance, UX,
   operations, and documentation before immediately beginning Cycle 27.

### Risks and mitigations

- Legacy state lacks project paths and old local-only clean operations may have
  left unattributed recovery roots. Identify these by stable workspace ID and
  block normal removal conservatively; require explicit force rather than
  guessing ownership.
- Filesystem inventory can be attacker-shaped by the same local account. Read
  only owner-private regular JSON without following final symlinks, validate
  directory/file grammar and identity hashes, cap entry counts, quote human
  paths, and fail closed on ambiguity.
- Force can intentionally create dangling resources. Never delete bindings,
  workspace state, or recovery data during host removal; report every retained
  reference and the exact same-name re-registration recovery path. Never allow
  force to bypass a live lease.
- A reference can race the preview. Treat dry-run as advisory, but repeat the
  complete local inventory while holding the global mutation lock immediately
  before the durable config write. State created after forced removal remains
  preserved and visible rather than being erased.
- Remembering a remote root after `clean` changes internal state semantics. Use
  an explicit boolean, conservatively interpret schema one as retained, clear
  it only after confirmed remote deletion succeeds, and leave recovery data
  orthogonal.
- Catalog scans are linear in locally managed projects. Cap records, avoid
  hashing recovery contents or contacting Mutagen/SSH, and benchmark a
  representative multi-project catalog.

### Research references

- [Docker context removal and force-in-use semantics](https://docs.docker.com/reference/cli/docker/context/rm/)
- [Docker context inventory and active marker](https://docs.docker.com/reference/cli/docker/context/ls/)
- [Terraform workspace deletion and dangling-resource protection](https://developer.hashicorp.com/terraform/cli/commands/workspace/delete)
- [Terraform workspace state-management model](https://developer.hashicorp.com/terraform/cli/workspaces)
- [Kubernetes context deletion reference](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_config/kubectl_config_delete-context/)

### Completed implementation

- Replaced instant deletion with `host remove NAME (--dry-run|--yes) [--force]
  [--json]`. Preview is local/offline and non-mutating. Confirmation repeats the
  complete inventory inside the serialized global-config update and removes
  only the host record after its guard succeeds.
- Added stable reports for default status, all target bindings, retained
  workspace/sync/runtime/recovery state, unattributed recovery/session state,
  live sessions, exact blocker reasons, and safe/allowed/removed outcomes.
  Human project paths are ASCII-quoted; schema-one JSON keeps arrays non-null.
- Default hosts and inactive references block normal removal. `--force --yes`
  deliberately preserves every binding, workspace record, and recovery copy so
  same-name re-registration is a recovery path. A held session lease is never
  overridable, including with force.
- Added internal workspace-state and binding schema two with canonical project
  identity; workspace state also records the managed remote path and explicit
  remote-retention state. Strict schema-one reads remain supported and are
  conservative when identity is unavailable. Catalog enumeration validates
  owner/private directories and files, names, hashes, IDs, schemas, paths,
  unknown fields, and 4,096-record bounds without following final links.
- `clean` now clears active sync/runtime identifiers but retains lifecycle
  evidence. Local-only clean keeps the remote-retention bit; only successful
  confirmed remote deletion clears it. An uncertain state-save after remote
  deletion attempts to restore the conservative retained marker.
- Added a per-host lifecycle lease shared by confirmed removal, new project
  binding, and session startup. Startup re-reads the durable host under the
  lease before agent lookup or network work, and publishes workspace/session
  evidence before releasing it. This closes the explicit-host launch/removal
  race found during independent review.
- Updated README, CLI, configuration, troubleshooting, architecture, security,
  development, command help/completions, and the Lima E2E journey. No remote
  deletion, SSH/Mutagen operation, agent/protocol change, daemon, dependency,
  background scan, or automatic cleanup policy was added.

### Verification and measurements

- Twenty focused repetitions, focused and full race suites, full tests, `make
  verify`, vet, Staticcheck 2026.1, pinned gosec, `govulncheck` (`No
  vulnerabilities found`), module verification/tidy, ShellCheck 0.11.0,
  `bash -n`, formatting/diff checks, realistic CLI recovery, cross-builds, and
  all thirteen fuzz targets pass.
- Fresh fuzz runs exercised 58,233 portable-bootstrap, 73,382 bootstrap-event,
  16,776 Unicode-view, 8,517 strict-TOML, 7,700 diagnostic, 85,438 protocol,
  324 recovery-archive, 107,296 shell, 12,820 subprocess, 66,323 sync-health,
  23,237 version, 13,191 ignore, and 19,749 workspace cases without a failure.
- CLI coverage is 57.5% and workspace coverage 72.2%. Host command construction
  is 100%, removal integration 87.5%, reference collection 89.1%, active-session
  inventory 75.9%, guard 85.7%, and rendering 77.1%; state load is 100% and
  state/binding/recovery catalogs are 68.6%/69.2%/80.0%.
- Strict inventory of 100 workspace records takes 2.10–2.50 ms, about 540.5
  KiB, and 3,118 allocations on this runner. Work is linear, reads metadata
  only, remains offline, and is repeated only for confirmed removal.
- Final Go 1.25 cross binaries are 8,931,778-byte arm64 client,
  9,423,360-byte amd64 client, and 5,056,481-byte Linux agent. The agent is
  unchanged. Release checksums, archives, standalone/embedded agent equality,
  generated removal flags, and three SBOM-to-SPDX 2.3 conversions pass.

### Independent post-implementation audit

- **Product:** Users can safely discover why an endpoint is still in use and
  retire it without silently losing the route to workspaces or recovery data.
  Force remains an explicit recoverable escape hatch rather than hidden cleanup.
- **Architecture:** The feature composes existing XDG state, strict JSON,
  durable atomic writes, advisory locks, and the global config transaction. The
  schema adds only lifecycle facts needed to make a global decision.
- **Security:** Catalogs are bounded, private, no-follow, identity-checked, and
  fail closed. Human paths are quoted; remote endpoints are never contacted or
  deleted. Live and in-progress use cannot be forced through lifecycle leases.
- **QA:** Default, binding, workspace, recovery, legacy, orphan, corrupt-mode,
  malformed-project, output failure, live lease, force/re-registration,
  migration, remote-root change, races, fuzzing, cross-build, and E2E syntax
  paths have regression evidence.
- **Performance:** A representative 100-workspace scan is a few milliseconds;
  no content hashing, Mutagen query, SSH, or background work was introduced.
- **UX:** Destruction requires preview or explicit confirmation, reports exact
  blockers in human/JSON form, and gives concrete cleanup or same-name recovery
  guidance. An incomplete config write is no longer misreported as a reference
  problem.
- **Operations:** Local-only clean retains remote ownership evidence, remote
  clean clears it only after deletion, confirmed removal rechecks current state,
  and force never erases recovery material. Packages include current help,
  completions, docs, checksums, agent, and SBOMs.
- **Documentation:** Discovery, command grammar, compatibility change, force
  semantics, cleanup transitions, legacy behavior, locking, threat boundary,
  performance, testing, and troubleshooting are documented end to end.

### Residual risk and stopped state

- Schema-one bindings cannot reveal project paths, and previously orphaned
  recovery roots cannot be attributed. Normal removal blocks conservatively;
  force is required rather than guessing. Downgrading to an older binary after
  schema-two state has been written is not supported.
- Preview is advisory. Confirmation serializes cooperating CLI binding/session
  startup and global config writers, but a direct editor or same-account process
  can ignore advisory locks inside the documented local trust boundary.
- Force intentionally permits inactive dangling remote/state references. It
  preserves local evidence but cannot prove that external remote data was
  manually deleted. Catalog scans are capped at 4,096 managed records.
- No live Lima, macOS interaction, or Mutagen 0.18.1 environment is available;
  fake/real-local integration, shell-validated E2E, races, fuzzing, cross-builds,
  and inspected release artifacts are the accessible evidence.
- The user explicitly requested that work stop after Cycle 26. No Cycle 27 was
  started; global workspace inventory/forget UX and legacy recovery attribution
  remain possible future work.
