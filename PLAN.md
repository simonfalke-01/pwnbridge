# pwnbridge — Comprehensive Project Plan

**Status:** Implemented and acceptance-tested
**Last updated:** 2026-07-13
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
- Use mature system primitives—OpenSSH and Mutagen—behind narrow internal interfaces.
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
| Transport | System OpenSSH | Preserves user SSH behavior and avoids reimplementing security-sensitive configuration |
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
brew install <owner>/tap/pwnbridge
pwnbridge host add x86 pwnbox
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

pwnbridge host add NAME DESTINATION
pwnbridge host list
pwnbridge host show NAME [--json]
pwnbridge host use NAME
pwnbridge host remove NAME
pwnbridge host doctor NAME [--json]
pwnbridge host bootstrap NAME [--profile=pwn] [--with-pwndbg]
                              [--dry-run] [--no-sudo]

pwnbridge sync status [--json]
pwnbridge sync flush
pwnbridge sync pause
pwnbridge sync resume
pwnbridge sync conflicts [--json]
pwnbridge sync resolve --prefer local|remote -- PATH...

pwnbridge terminal providers [--json]
pwnbridge terminal test [--provider NAME]

pwnbridge runtime status [--json]
pwnbridge runtime reset

pwnbridge config path
pwnbridge config validate
pwnbridge config show [--effective] [--json]

pwnbridge completion bash|zsh|fish
pwnbridge version [--json]
```

Behavioral rules:

- Bare `pwnbridge` means `pwnbridge shell`.
- The nearest ancestor `.pwnbridge.toml` defines the project; otherwise the current directory is the project root.
- Git roots are not selected implicitly.
- `run` transmits argv structurally. Pipelines require an explicit `bash -lc`.
- `stop` performs a final barrier, closes dependent panes, and pauses synchronization.
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
schema = 1
default_host = "x86"

[hosts.x86]
destination = "pwnbox"
platform = "linux/amd64"
workspace_root = "~/.local/share/pwnbridge/workspaces"
bootstrap_profile = "pwn"

[sync]
engine = "mutagen"
pause_on_idle = true
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
image = "ghcr.io/<owner>/pwnbridge-pwn@sha256:<digest>"
workdir = "/work"
network = "bridge"
```

Project files never contain hostnames, users, SSH keys, local terminal choices, or bearer tokens. `pwnbridge host use` stores the project-to-host binding in local state.

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
        ├─ PTY proxy ◄──────────────────────────── remote Bash/process
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

Use a dedicated pwnbridge-owned control master per active host:

```text
ssh -M -N
    -S <short-private-control-path>
    -o ControlMaster=yes
    -o ControlPersist=no
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
- Main shells and panes use `ssh -S ... -tt -e none` channels.
- Keep the master until the final shell, run, or pane lease exits.
- Cancel forwards and issue `ssh -O exit` on clean shutdown.
- Restore the local terminal immediately if transport fails.
- Let Mutagen maintain its own system-SSH connection rather than coupling it to UI channels.

### 9.2 Agent deployment

Build with `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`. Lookup order is `PWNBRIDGE_AGENT_PATH`, Homebrew libexec, then an adjacent release asset.

Probe OS/architecture, upload to a temporary user-owned path, verify SHA-256 remotely, chmod, and atomically rename into a protocol/content-addressed directory. Reuse exact matches and retain the two newest unused agents. Never use a system path and never run a persistent agent daemon.

### 9.3 Bootstrap profile

The Ubuntu/Debian `pwn` profile verifies or installs:

```text
build-essential cmake file binutils gdb gdbserver gdb-multiarch patchelf checksec
python3 python3-dev python3-venv python3-pip python3-pwntools libssl-dev libffi-dev tmux
strace ltrace socat netcat-openbsd libc6-dbg
```

It creates a user-owned virtual environment with pinned pwntools 4.15.0. The
checksum-verified Pwndbg profile is optional; any existing GEF/PEDA setup stays
user-owned and isolated from it. Bootstrap checks distro, amd64 architecture,
disk/inodes, home/workspace permissions, forwarding, ptrace, GDB, gdbserver,
and any configured container engine. Without sudo it still deploys the agent
and reports exact missing tools.

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

- Implement structured agent protocol, `run`, SSH master, PTY proxy, terminal restoration, resize/signals, Bash markers, paste buffering, and direct-host runtime.

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
- Homebrew depends on `mutagen-io/mutagen/mutagen`.
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
- System OpenSSH is the transport.
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
| PTY lifecycle | Readline, bracketed paste, Ctrl-C/Z/D, job control, alternate-screen bytes, resize, prompt barriers, disconnect restoration, reconnect, and artifact return pass in real PTYs |
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
this plan.
