# Architecture

Pwnbridge keeps the human-facing workspace on macOS and moves only
architecture-sensitive execution to native Linux amd64.

```text
Mac                                              Ubuntu/Debian amd64
───                                              ───────────────────
editor, Git, local tools
        │
local challenge ─── Mutagen two-way-safe ─────► remote workspace
        │                                             │
pwnbridge ───────── dedicated OpenSSH master ───► static agent
        │                                             ├─ host process
        ├─ PTY proxy ◄──── Mosh or SSH PTY ───────────┤
        │                                             └─ container process
        │
        └─ terminal broker ◄── reverse SSH socket ── pwntools-terminal
                  │
                  └─ trusted local provider ── second SSH PTY ── GDB
```

## Ownership model

The Mac is the canonical editing surface, not an unconditional conflict
winner. Mutagen owns synchronization history and both endpoints are treated as
valuable. Pwnbridge will never silently discard a version to make execution
continue.

The client owns:

- strict configuration and XDG state;
- workspace identity, locks, and active-session leases;
- the isolated Mutagen daemon and synchronization barriers;
- a dedicated OpenSSH control master for each active execution session;
- the terminal broker and provider selection;
- the authoritative runtime specification for debugger panes.

The remote static agent owns only per-invocation work:

- structured process execution;
- PTY Bash startup, SSH prompt markers, and Mosh barrier hooks;
- runtime/container creation and command entry;
- the `pwntools-terminal` wrapper and request manifests;
- debugger-pane execution after a Mac-approved request.

There is no persistent Pwnbridge agent daemon. Content-addressed agent binaries
remain cached for fast future invocations.

## Workspace identity and state

A workspace ID hashes the installation-specific machine ID, canonical local
root, and selected host ID. It does not depend on Git remotes and therefore
cannot accidentally adopt an unrelated checkout.

State is split by XDG purpose:

```text
$XDG_CONFIG_HOME/pwnbridge/  machine configuration
$XDG_STATE_HOME/pwnbridge/   bindings, workspace/session state, locks, Mutagen
$XDG_DATA_HOME/pwnbridge/    recovery copies
$XDG_CACHE_HOME/pwnbridge/   disposable provider helpers
```

Configured hosts and `default_host` are machine-wide configuration. A project
override is local XDG state keyed by the canonical project root; it is never
written into the portable project file. Effective host selection is the global
default, then the project binding, then `PWNBRIDGE_HOST`, then the one-shot
`--host` flag.

Private directories are mode 0700; private files and sockets are mode 0600.
State writes use an fsync-plus-rename atomic-write path. A cross-process file
lock serializes barriers and identity initialization.

Remote paths are similarly scoped below the user's home:

```text
~/.local/share/pwnbridge/agents/2/<sha256>/pwnbridge-agent
~/.local/share/pwnbridge/workspaces/<machine-id>/<slug-hash>/
~/.cache/pwnbridge/sessions/<session-id>/
```

## Synchronization correctness

Continuous Mutagen watching reduces latency but is not the correctness
boundary. Before every managed command Pwnbridge:

1. acquires the workspace barrier lock;
2. resumes the exact stored session if needed;
3. runs `mutagen sync flush <identifier>` with a bounded timeout;
4. queries that exact session through the JSON template interface;
5. rejects disconnected, paused, safety-halted, conflicted, excluded-conflict,
   scan-problem, transition-problem, or last-error state;
6. only then releases execution.

Interactive Bash adds a post-command barrier. A generated rcfile emits private
nonce-bearing markers from `PROMPT_COMMAND`. The local PTY parser holds Enter
at a trusted prompt for the pre-command barrier and holds the next prompt for
the post-command barrier. Bytes pass through unchanged while a foreground
program owns the terminal.

This gives two important guarantees:

- save then immediately press Enter: the remote command observes the save;
- generate a core/log/patched binary: the local file exists before the next
  managed prompt is visible.

One-shot `run` performs the same pre/post barriers without prompt markers.

## Mosh terminal and OpenSSH control plane

Interactive host-scope shells default to `shell_transport = "auto"`. When the
local `mosh` client, remote `mosh-server`, and authenticated reverse bridge are
available, Pwnbridge launches Mosh with `--predict=always` and the host's UDP
port/range. This gives local predictive echo while retaining a real remote PTY.
Mosh reuses the private SSH control socket for its initial authentication.

Mosh does not carry arbitrary SSH channels or Pwnbridge's OSC prompt marker.
The generated Mosh Bash rcfile therefore performs pre-command and post-command
barriers through a private agent hardlink and authenticated broker message. A
failed pre-command DEBUG trap returns nonzero under Bash `extdebug`, so Bash
skips the pending command. The broker address, 256-bit token, and session ID
remain private per-session state. SSH is selected when auto prerequisites are
missing; explicit `shell_transport = "mosh"` fails closed.

`pwnbridge run`, synchronization, agent deployment, cleanup, debugger control,
and all noninteractive operations always use OpenSSH.

## OpenSSH transport

Pwnbridge launches a private control master with agent/X11 forwarding disabled,
no persistent control socket, and keepalives:

```text
ssh -M -N -S <short-private-path>
    -o ControlMaster=yes -o ControlPersist=no
    -o ClearAllForwardings=yes -o ExitOnForwardFailure=yes
    -o ForwardAgent=no -o ForwardX11=no
    -o ServerAliveInterval=15 -o ServerAliveCountMax=3
```

The system executable and ordinary SSH configuration remain authoritative.
Startup readiness is checked with `ssh -O check`, not a fixed sleep. Each shell,
process, or debugger pane uses a separate channel through the same master.

The transport prefers reverse stream-local forwarding from the private remote
session socket to the Mac broker socket. If the server disables stream-local
forwarding, it asks OpenSSH for a remote loopback TCP port. When `socat` is
available, that TCP endpoint is re-exposed as the same private Unix socket so a
bridge-network container can still reach it. All fallbacks require an
end-to-end authenticated ping before a host-pane debugger is enabled. If both
forwarding forms are unavailable, Pwnbridge keeps the control master and normal
SSH shell/run channels, omits broker credentials, and reports that host-pane
GDB is unavailable. Auto transport also falls back to SSH because a Mosh shell
could not authenticate its synchronization barriers. Remote tmux/Zellij scope
needs no broker forward and uses SSH for its managed shell.

## Agent protocol and process execution

Client requests are URL-safe base64 JSON passed as one SSH argument. The agent
decodes typed requests and constructs `exec.Cmd` argv arrays. User command
strings are not reconstructed through a shell. The only deliberate shell
commands are fixed bootstrap/housekeeping programs whose variable path values
are single-quoted.

The Linux agent is built with `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`. Deployment
probes the remote platform, uploads to a unique temporary file, verifies SHA-256
remotely, chmods, and atomically places it under a protocol/content-addressed
directory. Reuse verifies the digest again. Old unused agents are pruned while
live process executables are retained.

## PTY behavior

Interactive channels use a local PTY proxy around Mosh or remote
`ssh -tt -e none`:

- local raw mode is restored on every exit path;
- `SIGWINCH` propagates rows and columns;
- Ctrl-C, Ctrl-Z, Ctrl-D, readline, job control, bracketed paste, and alternate
  screens remain byte-oriented;
- the marker parser tolerates every input chunk boundary and never treats a
  marker without the private nonce as trusted;
- transport failure immediately releases the local terminal.

## Pwntools terminal broker

Pwntools finds the injected `pwntools-terminal` before its built-in multiplexer
heuristics. The wrapper discovers its mode-0600 `terminal.json` from its own
session-local executable path, so broker credentials are not exported to the
exploit. It stores pwntools' generated argv, environment, and cwd as base64
fields in a bounded mode-0600 manifest and sends only opaque session/request
IDs to the Mac.

The broker validates protocol version, a random 256-bit session token, IDs,
rate limits, and an eight-pane concurrency cap. It constructs exactly one local
command form:

```text
pwnbridge __pane --record <local-record> --session <id> --request <id>
```

The remote side cannot provide this executable, local argv, provider, local
cwd, or environment. The helper loads the Mac-owned session record, opens a
second SSH PTY, and asks the agent to execute the manifest. Runtime fields in
the container-writable manifest are ignored; the authoritative runtime comes
from the local session record.

Lifecycle is bidirectional. Parent cancellation closes the pane, manual pane
close cancels the wrapper, natural GDB exit reaches pwntools, and session
shutdown terminates all registered handles. Concurrent GDB requests have
independent records and pane handles.

## Terminal providers

Providers implement detect/open/inspect/focus/close. Built-ins cover Zellij,
tmux, WezTerm, Kitty, iTerm2, Terminal.app, and explicit remote tmux/Zellij.
Custom providers exchange versioned JSON over stdin/stdout and receive only the
trusted local helper command.

Host multiplexer variables are never forwarded to the remote process. This is
why a Mac Zellij session creates a Mac Zellij pane without confusing pwntools
into looking for Zellij on Ubuntu.

## Runtime providers

Host runtime resolves the requested executable through the effective remote
PATH and executes it directly in the synchronized workspace. The Pwnbridge
pwntools virtualenv is prepended when installed.

Container runtime detects Podman or Docker and creates one container per active
session. It mounts the workspace at `/work`, private session state at
`/run/pwnbridge`, and the agent wrapper read-only; runs as the remote UID/GID;
adds `SYS_PTRACE` and `seccomp=unconfined`; and never mounts an engine socket.
Python, process, gdbserver, manifest reader, and GDB use that same container ID.

## Shutdown and recovery

An active session record contains its owner PID and has a sibling advisory-lock
lease held for the full session lifetime. The kernel lease is authoritative;
PID existence is only a secondary sanity check, so PID reuse cannot make an
unlocked stale record look live. The atomic record is published only after the
SSH control plane and reverse-broker ping are ready, so other processes never
observe a half-initialized session. Even an old corrupt record is removed only
if its private lease file can be acquired non-blockingly. `stop` signals
validated live owners, waits for cleanup, performs a final barrier, and pauses
only after the final lease exits. Local cancellation takes precedence over
incidental SSH teardown errors and exits deterministically as 130. Container
removal and remote session cleanup use the Mac-owned runtime record.

Deleting a remote root is not interpreted as a request to propagate deletion.
Pwnbridge validates an existing root before resuming; if it vanished or became
a symlink, execution remains blocked until the user verifies local data and
explicitly creates new synchronization history with `clean`.
