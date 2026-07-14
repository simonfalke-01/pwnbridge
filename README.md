# pwnbridge

Pwnbridge makes a native Linux x86-64 pwn environment feel local on an Apple
Silicon Mac. Keep your editor, Git checkout, Zellij session, and challenge
files on macOS; commands, pwntools, GDB, and the inferior run natively on a
remote Linux amd64 host.

```console
$ cd ret2win
$ pwnbridge
[pwnbridge:x86] ~/ret2win $ file ./ret2win
./ret2win: ELF 64-bit LSB executable, x86-64, ...
[pwnbridge:x86] ~/ret2win $ python solve.py
```

There is no repeated `scp`, no manually managed remote directory, and no
required remote login. Before a command starts, Pwnbridge blocks until the
latest local files are safely synchronized. Before the next managed prompt is
shown, remote artifacts are synchronized back to the Mac.

## What it provides

- A bidirectional, conflict-safe workspace powered by external Mutagen 0.18.1.
- An inline SSH PTY with pwnbridge predictive echo for instant typing,
  preserved terminal history, signals, job control, readline, resize, and
  interactive programs; explicit Mosh remains available for roaming sessions.
- Structural argv execution with ordinary remote exit statuses.
- Transparent pwntools `gdb.debug()`, `gdb.attach()`, and `api=True` support.
- First-class local Zellij and tmux panes, plus WezTerm, Kitty, iTerm2,
  Terminal.app, remote multiplexer, and custom-provider fallbacks.
- Direct-host execution by default and an optional Docker/Podman isolation
  runtime in which Python, gdbserver, GDB, and the inferior share one container.
- Strict portable configuration, XDG state, idempotent host bootstrap, and no
  persistent Pwnbridge daemon.

The full rationale, invariants, research record, and acceptance evidence are
in [PLAN.md](PLAN.md).

## Requirements

On the Mac:

- macOS on ARM64 or AMD64
- OpenSSH (`ssh` and `scp`)
- the macOS/POSIX `diff` utility for conflict previews
- Mosh client (only for explicit `shell_transport = "mosh"`)
- Mutagen exactly 0.18.1
- one supported terminal provider; Terminal.app is always the fallback

On the remote:

- Linux amd64 with a supported package-manager adapter or safe container/manual alternative
- an SSH account whose normal OpenSSH configuration already works
- optional `mosh-server` and inbound UDP 60000–61000 for explicit Mosh
- roughly 1 GiB free for bootstrap tools
- optional rootless Podman or Docker for container runtime

Pwnbridge deliberately uses the system `ssh` executable. Existing aliases,
ProxyJump, keys, Keychain, hardware tokens, and host-key verification continue
to work. It never edits SSH, shell, or GDB dotfiles.

## Install

Install the native Mac client, bundled Linux amd64 agent, Mutagen, optional
Mosh transport, and shell completions in one command:

```console
brew install simonfalke-01/pwnbridge/pwnbridge
pwnbridge --version
```

Or build from source:

```console
git clone https://github.com/simonfalke-01/pwnbridge.git
cd pwnbridge
make build
install -m 0755 bin/pwnbridge ~/.local/bin/pwnbridge
ln -sf pwnbridge ~/.local/bin/pb
install -m 0755 bin/pwnbridge-agent-linux-amd64 \
  ~/.local/bin/pwnbridge-agent-linux-amd64
```

For a source build, keep the Linux agent adjacent to the client, or set
`PWNBRIDGE_AGENT_PATH=/absolute/path/pwnbridge-agent-linux-amd64`. Release
archives place it adjacent automatically. Homebrew installs it in formula
`libexec`, where Pwnbridge finds it automatically.

Source builds require Mutagen 0.18.1. Install Mosh as well if you want the
explicit roaming transport:

```console
brew install mutagen-io/mutagen/mutagen mosh
mutagen version
```

See [installation.md](docs/installation.md) for completions, release assets,
and source-layout details.

## Five-minute setup

First make ordinary non-interactive SSH work. An alias keeps machine details
out of project configuration:

```sshconfig
Host pwnbox
    HostName 203.0.113.10
    User pwner
    IdentityFile ~/.ssh/id_ed25519
```

Then register and prepare it:

```console
pwnbridge host add x86 pwnbox --check
pwnbridge host bootstrap x86
```

Checked registration validates the global record, ordinary SSH, Linux amd64,
home capacity and permissions, ptrace policy, bootstrap-plan feasibility, and
required reverse forwarding before it saves anything. The first host becomes
the machine default automatically. The check uses separate 20-second inventory
and 15-second forwarding budgets and never deploys the agent, invokes sudo, or
changes the remote. `--json` emits the complete/partial report for automation.
Adding without `--check` remains a fast local-only operation.

`host doctor` is the later read-only health check: unlike registration, it also
reports whether every selected tool is installed and healthy. Bootstrap is the
explicit mutation step and performs its own postflight verification.

On a terminal, `host bootstrap` opens an inline wizard after a read-only host
inventory. The default `pwn` recipe installs the complete build/debug set and
Mosh; Pwndbg, Docker, and Podman are opt-in. Automation uses the same
deterministic plan with `--interactive=never --yes`. `--dry-run` performs only
the inventory and prints the exact plan, while `--no-sudo` reports all missing
privileged prerequisites before changing the user-owned environment. Open UDP
60000–61000 on the host firewall/security group only when using explicit Mosh.
The default `shell_transport = "auto"` uses pwnbridge predictive echo over an
inline SSH PTY; one-shot `run` always uses SSH.

Select plain SSH or explicit Mosh, or narrow Mosh's UDP range, without editing
TOML:

```console
pwnbridge host transport x86 mosh --mosh-port 60000:60100
pwnbridge host transport x86 ssh
pwnbridge host transport x86 auto
```

### What gets installed remotely

There is no remote Pwnbridge service to install or keep running. On first use,
the Mac client hashes its bundled static Linux amd64 agent, uploads it over
your existing SSH connection, verifies the hash on Linux, and atomically
caches it under:

```text
~/.local/share/pwnbridge/agents/4/<sha256>/pwnbridge-agent
```

`host bootstrap` detects apt, dnf/yum, pacman, zypper, apk, XBPS, Portage, or
Nix and uses fixed package mappings. Unsupported or immutable hosts receive a
container/manual alternative rather than an unsafe mutation. It then creates
the pinned pwntools environment at `~/.local/share/pwnbridge/envs/pwn-v1`. It
may use `sudo` only for system packages and an explicitly accepted Docker
setup; the agent, Python environment, workspaces, and session state remain
owned by the SSH user. Bootstrap is idempotent, and future client upgrades
deploy a new content-addressed agent automatically—no `scp`, remote login,
system-wide Pwnbridge binary, or persistent daemon is required.

The host registry and default are machine-wide. `host default NAME` changes the
fallback used by projects without an override. Project selection is local
state, so change into the challenge directory before `host use NAME`; use
`host use --default` to remove that override. `host list` marks the machine
default with `*` and the current project's effective host with `>`. No
per-challenge config file is required:

```console
cd /path/to/challenge
pwnbridge host use x86
pwnbridge doctor
pwnbridge support --local-only    # privacy-allowlisted issue report
pwnbridge                         # managed interactive Bash
pwnbridge run -- pwninit          # one command (explicit form)
pb pwninit                        # one command (concise form)
pwnbridge run -- ./chall          # one command
pwnbridge run -- python solve.py
pwnbridge run --tty=always -- gdb ./chall
```

Retire a host from any directory with a local, offline preview first:

```console
pwnbridge host remove x86 --dry-run
pwnbridge host remove x86 --yes
```

Normal removal is blocked while the name is the default or is referenced by a
project binding, retained remote workspace, synchronization/runtime state, or
recovery data. Active sessions can never be overridden. `--force --yes` removes
only the global host record and deliberately preserves every inactive reference;
re-adding the same name restores management. No removal mode contacts or deletes
anything on the remote host.

Use `pwnbridge init` only when the project needs ignores, environment values,
or container runtime settings. The nearest ancestor `.pwnbridge.toml` defines
the project root.

## Pwntools and GDB

Inside a managed shell or `pwnbridge run`, Pwnbridge injects a private
`pwntools-terminal` executable. Pwntools discovers it automatically, so the
usual exploit stays unchanged:

```python
from pwn import *

io = gdb.debug("./chall", gdbscript="break main\ncontinue")
# or: gdb.attach(io)
```

If an existing exploit hard-codes a terminal, remove that setting or use:

```python
context.terminal = ["pwntools-terminal"]
```

Pwnbridge opens a host-side pane whose helper creates a second SSH PTY. GDB and
the inferior still run on the same remote x86-64 host or in the same container;
only the pane is local.

Optional Pwndbg is installed as a pinned, checksum-verified portable release:

```console
pwnbridge host bootstrap x86 --with-pwndbg
```

It is exposed as `pwndbg` without replacing `gdb` and runs with `-nx`, so an
existing GEF/PEDA setup is not loaded into the same debugger. Select it in an
exploit with `context.gdb_binary = "pwndbg"`.

See [pwntools.md](docs/pwntools.md) for lifecycle details and `api=True` notes.

## Zellij, tmux, and other terminals

Provider selection is automatic: local Zellij, local tmux, the current
supported terminal application, then Terminal.app. Zellij is first-class but
not required.

```console
pwnbridge terminal providers
pwnbridge terminal test --provider zellij --placement right
```

Global configuration can make the choice explicit:

```toml
[terminal]
provider = "zellij"
scope = "host"
placement = "right"
size = "50%"
focus = true
close_on_success = true
hold_on_failure = true
```

Supported host providers are Zellij, tmux, WezTerm, Kitty, iTerm2,
Terminal.app, and `custom:NAME`. Explicit `scope = "remote"` supports remote
tmux or Zellij for headless/fallback use, at the cost of a nested multiplexer.
See [terminal-providers.md](docs/terminal-providers.md).

## Synchronization safety

Pwnbridge uses one isolated Mutagen `two-way-safe` session per local
project/host identity. Every execution barrier performs a blocking flush and
then validates the complete session state. A successful Mutagen flush alone is
not considered safe.

Conflicts and endpoint errors block execution instead of choosing a winner:

```console
pwnbridge sync conflicts
pwnbridge sync diff -- solve.py
pwnbridge sync resolve --prefer local -- solve.py
# or
pwnbridge sync resolve --prefer remote -- generated.txt
pwnbridge sync recovery list
pwnbridge sync recovery verify
pwnbridge sync recovery restore RECOVERY_ID --to recovered/generated.txt
pwnbridge sync recovery prune --keep-last 5 --dry-run
pwnbridge sync recovery prune --keep-last 5 --yes
```

The losing version is copied to an XDG recovery directory outside the
synchronized tree before resolution. Remote losers travel through an
acknowledged agent stream: the client validates, syncs, hashes, and catalogs
the backup before permitting removal, and the agent re-hashes the source before
deleting it. Recovery IDs and SHA-256 digests remain discoverable later;
restoration verifies cataloged content, requires a new project-relative
destination, and never overwrites existing content. Restore changes only the
local workspace, so use `pwnbridge sync flush` when you want an explicit
propagation check. Root deletion, safety halts, permissions, disk errors, and
disconnected endpoints also block execution. Pwnbridge never resets
synchronization history automatically.

Run `pwnbridge sync recovery verify` periodically to read and hash every
cataloged copy, or pass exact recovery IDs to check only selected entries.
Verification is local and read-only; damaged or pre-digest legacy entries make
the command return nonzero. Interactive human runs show delayed, path-free
byte/item progress without an extra scan. `--json` stays a single quiet document
and adds `checked`/`total` counters to the structured per-entry results. Ctrl-C
prints completed checks with `complete=false` before retaining exit 130.

Recovery storage is finite, so explicit pruning operates on complete
conflict-resolution archives rather than individual entries. It always keeps at
least the requested number of newest archives, requires either `--dry-run` or
`--yes`, and reports logical bytes rather than promising exact allocated disk
space. Pruning is local, offline, irreversible, and never changes either
synchronized workspace. If cancellation interrupts physical cleanup after an
archive is durably hidden, the next confirmed prune safely resumes that cleanup.

`pwnbridge stop` performs a final barrier, terminates dependent panes, and
pauses synchronization. `pwnbridge clean` terminates Mutagen metadata and
preserves both workspaces; a small local lifecycle record remains so host
retirement cannot forget the retained remote root. Remote deletion requires the
explicit `pwnbridge clean --remote --yes` form.

## Container runtime

For hostile challenges, build or publish the provided amd64 image and pin it by
digest:

```toml
[runtime]
kind = "container"

[runtime.container]
engine = "auto" # podman or docker
image = "ghcr.io/OWNER/pwnbridge-pwn@sha256:..."
workdir = "/work"
network = "bridge"
```

Pwnbridge creates one unprivileged, long-lived container per active session,
adds only the ptrace capability/security adjustment needed by GDB, does not
mount the engine socket, and removes the container during cleanup. Container
mode materially reduces exposure but is not a complete server trust boundary.
When an uncached image is needed, an interactive shell/run/pane streams native
Docker or Podman pull progress immediately; redirected/non-terminal commands
use quiet pull mode and keep stdout/stderr automation clean. Ctrl-C cancels and
reaps the engine client, while management replies remain bounded.
See [container-runtime.md](docs/container-runtime.md).

## Diagnostics and automation

Start troubleshooting with:

```console
pwnbridge doctor
pwnbridge support --local-only
pwnbridge status
pwnbridge sync status
pwnbridge terminal providers
pwnbridge config validate
```

Commands with `--json` return a stable envelope:

```json
{"schema":1,"data":{}}
```

Both doctor forms keep completed checks when another probe fails or times out.
Their JSON data includes stable `ok`, `complete`, and ordered `checks` fields;
human output ends with the same complete/incomplete result. Project doctor
uses 10-second local, 20-second read-only inventory, and 15-second temporary
reverse-forwarding budgets. It does not upload an agent, invoke sudo, install
software, or persist remote diagnostic files. A failed check or incomplete
report returns nonzero after output; Ctrl-C emits accumulated checks and
retains exit status 130.

`pwnbridge support` prints a copy/pasteable report built from a positive
privacy allowlist. It includes versions, safe effective behavior, capability
availability, coarse sync/recovery state, and a read-only remote inventory, but
never logs, paths, host names or destinations, IDs, config/environment values,
commands, images, conflict names, tokens, raw errors, or command output. Use
`--local-only` to skip SSH and `--json` for structured output. Nothing is
uploaded or saved; review the report before sharing it.

Exit status `4` means synchronization safety blocked execution, `130` means
cancellation, and ordinary remote statuses are preserved. Other Pwnbridge
errors return `1`.

The complete command reference is in [cli.md](docs/cli.md), configuration in
[configuration.md](docs/configuration.md), and recovery guidance in
[troubleshooting.md](docs/troubleshooting.md).

## Security boundary

The remote broker can request a debugger for an opaque, locally registered
session. It cannot choose a Mac executable, local argv, environment, provider,
or arbitrary local path. Broker transport is a private reverse Unix socket,
with authenticated loopback TCP fallback. Frames are capped, requests are
rate-limited, and concurrent panes are capped.

Direct-host mode gives challenge code the permissions of the remote account.
Use a dedicated account and container mode when appropriate. Pwnbridge never
forwards the SSH agent or X11, disables host-key checking, exposes a public
listener, or mounts a Docker/Podman control socket. Read the complete
[security model](docs/security.md).

## Development

```console
make verify       # formatting, module, unit, vet, and cross-build checks
make test-race
make fuzz-smoke
make security
make snapshot     # local GoReleaser snapshot
```

The real end-to-end suite targets an amd64 Ubuntu Lima VM and covers the
current `ret2win` ELF, save/run barriers, remote artifacts, conflicts, root
deletion, PTY semantics, stable and 5-dev pwntools, Zellij/tmux, remote tmux,
host/container GDB, and shutdown. See [development.md](docs/development.md).

Pwnbridge is MIT licensed. Mutagen remains a separately installed external
dependency under its own license and is not linked, bundled, or redistributed.
