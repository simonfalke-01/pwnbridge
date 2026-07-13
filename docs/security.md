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
- stdout/stderr, filenames, pane titles, and manifests from the remote runtime;
- the contents of the synchronized project;
- same-container processes;
- a remote account after it has been compromised.

Direct-host mode executes as the configured remote Unix account. A challenge
there can access everything that account can access. Use a dedicated,
unprivileged pwn account without valuable credentials.

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

## SSH posture

Pwnbridge uses the system OpenSSH client and never:

- disables strict host-key checking;
- writes `~/.ssh/config`;
- forwards the SSH authentication agent;
- forwards X11;
- exposes a public custom daemon;
- persists its control master after session cleanup.

Keys, ProxyJump, `Match`, Keychain, FIDO/hardware keys, and host verification
remain OpenSSH's responsibility. Pwnbridge uses structured client argv; remote
maintenance commands single-quote variable paths.

## Agent deployment

The Linux agent is a static amd64 binary installed only below the remote user's
data directory. Deployment:

1. probes Linux/amd64 through ordinary SSH;
2. hashes the local asset;
3. verifies any cached copy's remote SHA-256 before reuse;
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
before touching synchronization. If that bridge is missing, auto transport
uses SSH and forced Mosh fails closed. Environment filtering prevents broker
credentials from being inherited from the local machine.

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
- resolution backs up the losing endpoint outside the sync root;
- root deletion and replacement block execution;
- an unhealthy/safety-halted session is never reset automatically;
- `clean` preserves both workspaces;
- remote deletion requires both `--remote` and `--yes`.

The project deliberately does not import `.gitignore`: cores, dumps, libc,
loaders, and generated binaries commonly matter during exploitation.

## Dotfile and package posture

Bootstrap prints its apt plan before sudo and only supports Ubuntu/Debian amd64.
The user-owned Python environment pins pwntools 4.15.0. Optional Pwndbg is a
pinned portable release whose SHA-256 is embedded and verified before
extraction. It is exposed through an isolated `pwndbg -nx` wrapper and neither
edits nor sources a conflicting user `~/.gdbinit`.

Pwnbridge never edits `.bashrc`, `.zshrc`, or GDB configuration. Managed Bash
uses a per-session rcfile and optionally sources the user's `.bashrc` at
runtime.

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

When reporting a security issue, include `pwnbridge version --json`, macOS and
remote distro versions, runtime/provider type, and a redacted reproduction. Do
not include broker tokens, private SSH configuration, challenge flags, or
private host addresses.
