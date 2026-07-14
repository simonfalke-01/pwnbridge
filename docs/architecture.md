# Architecture

Pwnbridge keeps the human-facing workspace on macOS and moves only
architecture-sensitive execution to native Linux amd64.

```text
Mac                                              Linux amd64
───                                              ───────────
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

Configuration discovery reads the global file and nearest ancestor project
file through a 1 MiB ceiling. The TOML parser has an explicit nesting guard;
strict typed decoding rejects unknown keys before semantic merging. Errors
preserve the underlying typed decoder error while presenting only a concise
path/position/key summary to the CLI.

Host registration is a machine-global transaction and therefore loads no
project layer. The complete candidate is semantically validated in memory,
duplicate names require explicit replacement, and default selection is resolved
before any optional network probe. Checked registration feeds the existing
read-only inventory into the built-in `pwn` planner and runs the same temporary
forwarding probe as doctor; only a complete healthy report reaches the atomic
global-config write. A failed new or replacement check retains the previous
durable file. The probe runs outside the config lock; commit takes the shared
global mutation lock, reloads the latest file, rechecks duplicate/default
semantics and the checked terminal-scope policy, and performs a short atomic
read-modify-write. A concurrent scope change aborts checked registration;
unrelated changes are retained. Host transport/default/removal, saved recipes,
and bootstrap profile binding use the same transaction, so concurrent CLI
writers do not discard unrelated changes.

Bootstrap is independent of project selection and runtime configuration. A
read-only SSH inventory feeds its typed recipe planner and host doctor. The
client-only Bubble Tea v2 adapter renders a purpose-built inline wizard;
execution uses one ordinary SSH PTY so visible `sudo -v` authentication is
shared by fixed-argv steps.
Complete logs live under XDG state and displayed output is control-sanitized.

Checked registration, project doctor, and host doctor share that same
inventory/planner boundary. Registration evaluates whether missing capabilities
are installable by bootstrap; doctor instead treats selected missing components
as current health failures. Local,
inventory, and reverse-forwarding collectors receive independent derived
contexts and append ordered typed checks to one report. A collector failure is
data (`complete=false`) rather than a reason to discard completed results; only
parent cancellation stops later collectors. Probes run sequentially to avoid
simultaneous authentication/hardware-token prompts. Inventory is read-only,
and the forwarding check owns only a temporary private control master and
ephemeral reverse listener; doctor never deploys the agent.

The support-report path is intentionally separate from logs and raw status.
Each collector populates a typed positive allowlist; broad configuration,
workspace, session, Mutagen, error, and inventory objects are never serialized.
Remote free text maps through closed vocabularies, custom provider names reduce
to their category, and failures reduce to safe error classes. Independent local,
status, and read-only SSH deadlines plus a 1 MiB remote-inventory output cap let
a partial report survive the subsystem being diagnosed. Output goes only to the
requested stdout writer.

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

Workspace and binding schema-two records also store the canonical project root;
workspace state stores the last managed remote path and a remote-retention bit.
Schema-one records remain strictly readable but are treated conservatively as
legacy: their project path is unknown and their remote root is presumed
retained. `clean` clears active sync/runtime identifiers but keeps this catalog;
only successful `clean --remote --yes` clears remote retention. This makes host
retirement an inventory problem instead of an unsafe one-project guess.

`host remove --yes` holds the global configuration lock, reloads current config,
and re-inventories bounded owner-private bindings, workspace records, recovery
roots, and session leases before the atomic write. Normal removal requires no
references. Force can preserve inactive dangling records but cannot override a
live lease. A per-host lifecycle lease also serializes confirmed removal with
new project binding and session startup; startup revalidates the host under that
lease before any network work. Host removal never contacts or mutates the remote
endpoint.

Private directories are mode 0700; private files and sockets are mode 0600.
State writes use an fsync-plus-rename atomic-write path. A cross-process file
lock serializes barriers and identity initialization.

The isolated Mutagen adapter first uses its fast, idempotent `daemon start`
command. If that compatibility path fails, Pwnbridge invokes the documented
`daemon run` entry point in a new session and releases it only after successful
process creation. Cancellation is checked before any state creation, after the
normal attempt, and immediately before fallback launch, so an expired command
does not intentionally create a detached daemon. Fallback stdout/stderr use a
validated descriptor for `mutagen/v0.18/daemon.log` in the real state tree;
socket-length aliases under the temporary directory are never used to resolve
the log path.

Conflict archives use sortable nanosecond UTC directories below the workspace
recovery path. Each new archive has a versioned, atomically replaced manifest
that records independently restorable original paths, endpoint metadata, and a
deterministic SHA-256 content identity.
Inventory also recognizes the older timestamp/winner layout conservatively.
Local backup, recursive removal, and restoration use Go's descriptor-held
`os.Root` operations, exact-length nonblocking regular-file reads, exclusive
destination creation, and file/directory durability syncs. A concurrent path
replacement can cause an operation to fail or affect another object inside the
same root, but cannot redirect it outside the held workspace or recovery root.

When the remote copy loses a conflict, one no-PTY agent process writes a
deterministic, restricted tar stream and waits. The client extracts through a
held recovery root, rejects traversal, duplicate or out-of-order names and
unsupported metadata/types, syncs files and directories, and atomically
records the stream digest. Only then does it acknowledge that digest. The
agent regenerates the archive from the same observed object and removes it
through a held remote workspace root only when the second digest still
matches. Its final result must match the durable local summary. A failure
before acknowledgement preserves the remote copy; a transport failure after
acknowledgement is reported as uncertain together with the durable backup
path.

Remote paths are similarly scoped below the user's home:

```text
~/.local/share/pwnbridge/agents/4/<sha256>/pwnbridge-agent
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

When a conflict blocks that barrier, `sync diff` inspects only exact paths from
the current Mutagen conflict set. Both endpoints are traversed from opened
workspace directory descriptors without following symlinks. The bundled agent
returns at most 1 MiB of regular-file content; the client renders unified
local-to-remote output only for display-safe UTF-8 and emits bounded metadata
for every other type. Inspection does not resume or mutate synchronization.

One-shot `run` performs the same pre/post barriers without prompt markers.

## Predictive inline shell and optional Mosh

Interactive host-scope shells default to `shell_transport = "auto"`. Pwnbridge
runs the ordinary SSH PTY inline and predicts printable prompt input locally.
Matching remote terminal echo is reconciled out of the stream; any mismatch,
control sequence, readline redraw, or program output remains remote-authoritative.
This byte-stream design preserves the surrounding terminal history and avoids
the viewport clear inherent in a screen-state protocol. `shell_transport =
"ssh"` uses the same path with prediction disabled.

`shell_transport = "mosh"` explicitly selects Mosh with `--predict=always` and
the host's UDP port/range. Mosh retains its native full-screen roaming and
reconnection model; it is not used automatically. The PTY proxy removes Mosh's
exact normal-exit banner without buffering earlier output, while connection and
server errors remain visible. Mosh reuses the private SSH control socket for
initial authentication.

Mosh does not carry arbitrary SSH channels or Pwnbridge's OSC prompt marker.
The generated Mosh Bash rcfile therefore performs pre-command and post-command
barriers through a private agent hardlink and authenticated broker message. A
failed pre-command DEBUG trap returns nonzero under Bash `extdebug`, so Bash
skips the pending command. The broker address, 256-bit token, and session ID
remain private per-session state. Explicit `shell_transport = "mosh"` fails
closed when its prerequisites are unavailable.

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
predictive/plain SSH shell and run channels, omits broker credentials, and
reports that host-pane GDB and explicit Mosh are unavailable. Remote
tmux/Zellij scope needs no broker forward and uses SSH for its managed shell.

## Agent protocol and process execution

Client requests are URL-safe base64 JSON passed as one SSH argument. The agent
decodes typed requests and constructs `exec.Cmd` argv arrays. User command
strings are not reconstructed through a shell. The only deliberate shell
commands are fixed bootstrap/housekeeping programs whose variable path values
are single-quoted.

Protocol 3 adds a structured bootstrap request and newline JSON event stream.
The client sends discrete argv/environment fields through one SSH PTY; the
agent emits authentication, start, output, completion, and failure events.
Bubble Tea, Bubbles, and Lip Gloss remain confined to the Darwin client
dependency graph. The adapter uses no alternate screen and includes only the
selection and text-entry models needed by bootstrap. The coordinated renderer
stack is covered by model/program integration and bounded Unicode fuzz tests so
wide/joining grapheme fixes cannot silently regress inline width or input
restoration.

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
An absent image is the only streamed setup operation: terminals receive the
engine's native pull bytes as they arrive, while non-terminals use quiet mode.
Signal-aware setup kills and reaps the engine client before normal signal
handling is restored and the agent replaces itself with the requested process.

Captured local-tool output is classified by contract rather than one global
limit. Fixed identifiers/booleans and runtime management use 64 KiB; custom
provider JSON uses 1 MiB; complete Zellij/WezTerm/Kitty inventories use 4 MiB;
Mutagen management uses 1 MiB; and conflict-bearing Mutagen state uses 16 MiB.
Structured stdout retains a prefix and fails on overflow, while failure
diagnostics retain a 64 KiB tail. All collectors keep draining and inherit the
common context/one-second descriptor shutdown bound. User command, terminal,
bootstrap, and recovery archive streams are not captured by this layer.

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

Conflict recovery is independent of session liveness. `sync recovery list`
reads only the local catalog, and `sync recovery restore` creates a new,
non-existing project-relative target under the workspace lock. It does not
resume or flush Mutagen implicitly, and it retains the source recovery copy.
Cataloged entries are hashed before copying and the new destination is hashed
again before success is reported; older manifest and pre-manifest entries
without a digest remain explicitly unverified for compatibility.

`sync recovery verify` takes the same workspace lock and regenerates each
selected deterministic identity directly from the descriptor-rooted recovery
tree. It is sequential, context-cancelable, and read-only: later entries remain
checkable after an individual mismatch, while a structurally corrupt catalog
fails enumeration rather than guessing recovery boundaries. It never starts
Mutagen or SSH and never records a digest for legacy content. The same archive
reader optionally reports monotonic source bytes/items, so terminal progress
does not require a second traversal or affect deterministic bytes. Progress is
transient stderr state; final human/schema-one JSON reports retain completed
entries and exact checked/total counts if parent cancellation interrupts a
later entry.

`sync recovery prune` aggregates that strict catalog into timestamped whole
resolution archives and retains at least the requested newest count. Preview is
read-only; confirmed pruning holds the workspace lock and stays entirely local.
Each selected archive is renamed through the held recovery root to an exact
random hidden tombstone and the root directory is synced before recursive
reclamation begins. Catalog visibility therefore changes atomically: a crash
leaves either the intact visible archive or an ignored tombstone, never a
visible half-deleted manifest tree. Descriptor-rooted, same-filesystem,
context-checked removal does not follow links or cross mount boundaries. The
next confirmed prune removes valid stale tombstones before selecting new work.
