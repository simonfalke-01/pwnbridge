# Security model

Pwn challenge binaries are untrusted. Pwnbridge is designed to prevent a
remote challenge from turning debugger convenience into arbitrary execution on
the Mac, while protecting synchronized data from accidental loss. It is not a
multi-tenant sandbox and cannot make a compromised remote account trustworthy.

## Trust boundaries

Trusted:

- the local Pwnbridge client and its installation;
- local XDG state owned by the current Mac user;
- the user's system OpenSSH configuration and verified host key;
- the selected terminal provider executable;
- Mutagen 0.18.1 as a separately installed runtime dependency.

Potentially hostile:

- challenge binaries and scripts;
- automatically discovered project configuration before it is validated;
- stdout/stderr, filenames, pane titles, and manifests from the remote runtime;
- the contents of the synchronized project;
- same-container processes;
- a remote account after it has been compromised.

Direct-host mode executes as the configured remote Unix account. A challenge
there can access everything that account can access. Use a dedicated,
unprivileged pwn account without valuable credentials.

Global and nearest-ancestor project TOML is read through a 1 MiB ceiling,
decoded into strict typed layers, and rejected on unknown fields. Parser depth
is bounded at 10,000 nested arrays/inline tables, so a hostile cloned project
cannot turn discovery into unbounded recursion. User-facing decode errors show
only the path, position, key, and parser message—not the offending value or
surrounding configuration text.

Container mode adds a process/filesystem boundary but is not a complete server
trust boundary. Rootless Podman is preferable where available. Kernel bugs,
container-engine bugs, unsafe host mounts, and permissions shared with the
remote account remain relevant.

## Local-command invariant

The terminal broker's decisive invariant is:

> Remote data may request a debugger for an existing opaque session, but may
> not choose a Mac executable, local argv, environment, provider, or arbitrary
> local path.

The remote wrapper sends only authenticated session/request IDs and a sanitized
title. The Mac loads its own mode-0600 session record and constructs the local
helper command. GDB argv/environment/cwd remain in a bounded remote manifest and
are executed only by the Linux agent after a pane is approved.

For container runtime, the manifest is writable by container processes.
Pwnbridge therefore ignores its runtime object. The authoritative runtime
specification—engine, image, container ID, workspace, and session mount—comes
from the Mac-owned session record and is validated again before pane creation
and cleanup.

## Broker transport

Each execution session has:

- a random 128-bit session ID;
- a random 256-bit broker token;
- private mode-0700 local/remote directories;
- mode-0600 Unix sockets and state;
- protocol/session/request identity checks on every frame;
- a 1 MiB frame and manifest limit;
- eight concurrent pane maximum;
- 32 open requests per minute;
- numeric-loopback-only TCP fallback validation.

The preferred transport is an OpenSSH reverse stream-local forward. TCP
fallback binds only remote `127.0.0.1` and local `127.0.0.1`; a private Unix
relay is used for bridge containers when available. Pwnbridge performs an
authenticated end-to-end ping before exposing a managed process.

A same-UID remote process can inspect other same-user state on many Linux
systems. Broker credentials are omitted from the command environment and kept
in a mode-0600 per-session file, but tokens are not presented as isolation from
a compromised remote Unix account. The local-command invariant limits what a
forged valid broker request can cause on macOS.

The isolated local Mutagen fallback log is opened relative to an owner-private
data-directory descriptor. Pwnbridge refuses a linked directory, a final
symbolic link, FIFO/device/socket/directory entries, a different owner, and any
group/other permission before handing the descriptor to Mutagen. Non-blocking
and no-follow opens make hostile special files fail promptly. Logs larger than
5 MiB at fallback startup are descriptor-relatively renamed to
`daemon.log.previous`; source identity is checked before and after the rename.
This is startup rotation, not a hard runtime size cap: the released daemon owns
its output descriptor and can continue writing until its next fallback start.

Doctor does not upload or execute the agent and uses no sudo/package operation.
Its remote inventory is the same bounded read-only script used by bootstrap
planning; reverse-forwarding diagnosis creates only a temporary private control
master and ephemeral loopback listener. Local, inventory, and forwarding work
has independent cancellation budgets. Tiny SSH protocols retain at most 64 KiB
for basic/forwarding output and 1 MiB for agent-probe JSON while draining excess.
All rendered check details/remediation are valid UTF-8, single-line, escape/C0/
format-control stripped, and capped before identical human/JSON reporting.

`host add --check` uses the same read-only inventory and temporary forwarding
boundary before persisting a machine-global candidate. It does not use SCP,
Mutagen, the agent, sudo, package commands, or remote file creation. Missing
installable tools are evaluated through the typed bootstrap plan, while unsafe
platform/resource/ptrace/forwarding or blocked-plan results prevent the atomic
config write. Existing names require `--replace`; a failed checked replacement
leaves the old record durable. Ordinary add remains explicitly local-only. The
network check never holds the global config lock; the final commit reloads and
validates current state under that owner-private advisory lock before the
fsync/rename write.

## SSH posture

Pwnbridge uses the system OpenSSH client and never:

- disables strict host-key checking;
- writes `~/.ssh/config`;
- forwards the SSH authentication agent;
- forwards X11;
- exposes a public custom daemon;
- leaves a control master running indefinitely.

Nearby managed invocations may reuse an owner-private, identity-keyed OpenSSH
master for up to two idle minutes. OpenSSH owns that timeout. Pwnbridge shares
no broker token or remote session state across commands, cancels each exact
reverse forward during cleanup, and explicitly exits the warm master on
`stop`/`clean`. The master never forwards the authentication agent or X11.

Keys, ProxyJump, `Match`, Keychain, FIDO/hardware keys, and host verification
remain OpenSSH's responsibility. Pwnbridge uses structured client argv; remote
maintenance commands single-quote variable paths.

## Agent deployment

The Linux agent is a static amd64 binary installed only below the remote user's
data directory. Deployment:

1. hashes the local asset;
2. verifies any cached copy's remote SHA-256 before executing it;
3. probes that verified executable for Linux/amd64 and protocol compatibility;
4. uploads to a unique mode-private temporary path;
5. verifies SHA-256 remotely;
6. atomically moves into a protocol/content-addressed directory;
7. retains live executables and only prunes older unused versions.

No sudo or system path is used for the agent. Client/agent protocol mismatch is
an explicit error.

## Mosh boundary

Mosh is optional terminal transport, not a replacement for the OpenSSH control
plane. It authenticates through the existing private SSH master, binds a remote
UDP port from the configured range, and encrypts terminal traffic with its
one-time session key. Operators must expose only the chosen UDP range; no
Pwnbridge TCP service listens publicly.

Mosh shells cannot use the local OSC marker parser. Their generated Bash hook
invokes a private hardlink of the deployed agent, which loads mode-private
session state and sends an authenticated `barrier` request over the reverse SSH
bridge. The broker validates protocol, session ID, and the random 256-bit token
before touching synchronization. If that bridge is missing, explicit Mosh
fails closed; the default predictive SSH transport remains available.
Environment filtering prevents broker credentials from being inherited from
the local machine.

## Process and environment handling

Public `run` argv, pwntools debugger argv, and provider commands are represented
as arrays. Arbitrary user commands are not concatenated into a shell. A user
who wants a pipeline must explicitly run `bash -lc` and thereby opts into shell
semantics.

Debugger environment filtering removes:

- `SSH_*` transport metadata;
- `TMUX*` and `ZELLIJ*` host/remote confusion;
- internal `PWNBRIDGE_*` fields;
- `TERM`, `COLORTERM`, `PWD`, `OLDPWD`, and `_` values owned by the new PTY.

Relevant executable/library/locale/pwntools values remain available. Pane
titles strip control characters and are capped at 80 bytes.

## Container posture

The adapter:

- runs as the remote numeric UID/GID (and Podman `keep-id`);
- mounts only the synchronized workspace and owned session directory;
- mounts the agent-wrapper directory read-only;
- never mounts `/var/run/docker.sock`, a Podman socket, SSH keys, or the remote
  home;
- adds `SYS_PTRACE` and `seccomp=unconfined` because native GDB requires them;
- defaults to bridge networking;
- labels containers for exact workspace/session cleanup;
- prefixes all generated names with `pwnbridge-`.

`network = "none"` is recommended for challenges that require no outbound
network. Some pwn targets need network access, so bridge remains the functional
default.

## Synchronization and deletion safety

Pwnbridge treats every local and remote file as potentially valuable:

- Mutagen runs in `two-way-safe` mode;
- execution requires flush plus a complete health validation;
- conflicts have no automatic winner;
- conflict previews use descriptor-relative no-follow traversal, cap each
  endpoint at 1 MiB, and never render binary or terminal-control-bearing bytes;
- resolution backs up the losing endpoint outside the sync root;
- new recovery copies are durably cataloged before loser deletion, remain
  listable in escaped human or structured JSON output, and restore only to an
  explicit non-existing local target;
- deterministic SHA-256 identities bind cataloged content and metadata;
  explicit verification checks stored copies proactively, and restore verifies
  both its source and newly copied destination;
- explicit recovery pruning retains at least one newest whole resolution
  archive, requires dry-run or confirmation, and durably hides an archive before
  descriptor-rooted removal; it never prunes automatically or edits a manifest;
- local backup, restore, recursive loser removal, remote backup streaming, and
  remote loser removal operate relative to held filesystem roots so concurrent
  symlink replacement cannot escape the workspace or recovery directory;
- root deletion and replacement block execution;
- an unhealthy/safety-halted session is never reset automatically;
- `clean` preserves both workspaces;
- remote deletion requires both `--remote` and `--yes`.

The project deliberately does not import `.gitignore`: cores, dumps, libc,
loaders, and generated binaries commonly matter during exploitation.

Recovery digests detect accidental or one-sided modification but are not an
authenticated backup format: the same local account can modify both catalog
and data. Rooted operations also permit access to mount points already present
inside a workspace, matching Go's documented `os.Root` boundary. Remote loser
deletion requires a durable client acknowledgement and a second full source
digest. There remains a narrow interval between the second digest/identity
check and descriptor-rooted removal in which a malicious same-account process
can replace content inside the remote workspace; remote workspaces therefore
remain outside the trust boundary. Replacement cannot redirect removal beyond
the held workspace root.

Recovery verification is strictly read-only and never treats a newly computed
digest as historical evidence. Entries created before digest recording remain
`unverified` and make a requested full check incomplete. Verification reads all
selected bytes under the workspace lock, so it can be expensive, but remains
cancelable and does not contact the remote host or synchronization daemon.
Interactive progress contains only an entry index/count and clamped percentage,
not IDs or original paths; recorded totals are display estimates and never
influence the digest decision. Cancellation emits only fully completed entry
results and retains exit 130.

Pruning is intentionally archive-granular and irreversible. A same-root atomic
rename plus recovery-root sync occurs before deletion, so interruption cannot
expose a partially removed catalog archive. Cleanup checks cancellation between
entries, refuses filesystem/mount crossings, and never follows stored symbolic
links. Exact randomized tombstone grammar allows a later confirmed prune to
finish space reclamation; unrelated hidden directories are ignored. Logical
byte totals are informational and do not claim allocated blocks. The trusted
local account can still replace objects inside the recovery root, but held
descriptors prevent that replacement from redirecting deletion outside it.

Non-interactive SSH management replies are retained at protocol-specific caps:
64 KiB for forwarding/SCP diagnostics, 1 MiB for ordinary setup commands, and
2 MiB for agent management JSON. The larger agent bound admits a maximum 1 MiB
conflict snapshot after JSON base64 expansion. Excess is drained and rejected;
interactive PTY data and recovery archive streams remain deliberately streamed
without these collection caps.

Local and remote-agent tool capture is bounded separately by documented shape:
64 KiB for runtime/pane/version/disk acknowledgements, 1 MiB for custom terminal
provider JSON and Mutagen management, 4 MiB for full terminal pane inventories,
and 16 MiB for conflict-bearing Mutagen state. Structured stdout overflow is an
error; stderr retains a marked 64 KiB tail so an attacker cannot hide the final
failure behind progress noise. Collectors drain discarded bytes and retain
context and inherited-descriptor bounds.

An interactive Docker/Podman image pull is deliberately streamed rather than
captured: it can be arbitrarily long but has no growing Pwnbridge buffer. The
stream exists only on a terminal and is never parsed, persisted, or included in
support output. Non-terminal pulls use official quiet mode plus bounded failure
capture. Temporary signal interception cancels the engine client and is stopped
before the agent executes the requested shell/command/pane.

## Dotfile and package posture

Bootstrap inventories over read-only SSH and passes validated package names as
separate argv through fixed apt, dnf/yum, pacman, zypper, apk, XBPS, Portage,
or Nix adapters. It does not add repositories, accept URLs/hooks/templates, or
collect credentials. One visible `sudo -v` authenticates the ordinary PTY;
planned commands then use `sudo -n`. Docker-group membership requires a warning
and explicit acceptance because it is root-equivalent. The user-owned Python
environment pins pwntools 4.15.0 and runs `pip check`. Optional Pwndbg is a
pinned portable release whose SHA-256 is embedded and verified before
extraction. It is exposed through an isolated `pwndbg -nx` wrapper and neither
edits nor sources a conflicting user `~/.gdbinit`.

Pwnbridge never edits `.bashrc`, `.zshrc`, or GDB configuration. Managed Bash
uses a per-session rcfile and optionally sources the user's `.bashrc` at
runtime.

## Host retirement

Host deletion is local and fail-closed. Preview and confirmation read only
owner-private, size-bounded JSON records without following final symlinks;
catalog filenames, identity hashes, project/remote paths, schemas, record counts,
and live leases are validated. Human paths are ASCII-quoted. A default host,
project binding, retained workspace, recovery root, or active sync/runtime state
blocks normal removal. Unattributed legacy recovery also blocks rather than
being guessed.

`--force --yes` may intentionally remove a global record while preserving known
inactive references, analogous to leaving explicitly accepted dangling state.
It deletes none of those files and no remote data, so re-adding the same name is
the recovery path. A live or unidentifiable session is non-overridable. Preview
is advisory; confirmation repeats inventory while holding the serialized global
configuration transaction immediately before its durable write.
Confirmed removal also owns a per-host lifecycle lease. New bindings and session
startup take the same lease and revalidate the durable host record, closing the
window in which an already-loaded explicit `--host` command could otherwise
create state after removal.

## Known limits

- A malicious remote user can act with that user's full permissions and can
  directly use any configured Docker/Podman privileges.
- Container isolation shares the remote kernel and ptrace capability inside
  the container.
- Terminal.app/iTerm2 window launchers provide weaker handle/close semantics
  than Zellij/tmux.
- Two-way synchronization protects consistency, not confidentiality. Project
  files exist on both endpoints.
- A custom terminal provider is trusted local code. Install it with the same
  care as a shell plugin.
- Pwnbridge has no privilege separation between two processes under the same
  Mac login or remote UID.

## Reporting

Start with `pwnbridge support --local-only` (or add `--json`) and a separately
written, redacted reproduction. The report is built from a positive allowlist
and excludes paths/content, host names and
addresses, workspace/machine/session/runtime IDs, configuration/environment
names and values, commands/images/conflict paths, logs, tokens, raw output, and
raw errors. The report is not uploaded or saved, and output should still be
reviewed before sharing. Add the default read-only remote inventory
only when contacting the configured host is appropriate. Never include broker
tokens, private SSH configuration, challenge flags, or private host addresses.
