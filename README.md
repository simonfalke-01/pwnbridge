# pwnbridge

Pwnbridge makes a native Ubuntu x86-64 pwn environment feel local on an Apple
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
- A real PTY over the user's system OpenSSH, including signals, job control,
  readline, resize, and interactive programs.
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
- Mutagen exactly 0.18.1
- one supported terminal provider; Terminal.app is always the fallback

On the remote:

- Ubuntu or Debian Linux amd64
- an SSH account whose normal OpenSSH configuration already works
- roughly 1 GiB free for bootstrap tools
- optional rootless Podman or Docker for container runtime

Pwnbridge deliberately uses the system `ssh` executable. Existing aliases,
ProxyJump, keys, Keychain, hardware tokens, and host-key verification continue
to work. It never edits SSH, shell, or GDB dotfiles.

## Install

Install the native Mac client, bundled Linux amd64 agent, Mutagen dependency,
and shell completions in one command:

```console
brew install simonfalke-01/pwnbridge/pwnbridge
```

Or build from source:

```console
git clone https://github.com/simonfalke-01/pwnbridge.git
cd pwnbridge
make build
install -m 0755 bin/pwnbridge ~/.local/bin/pwnbridge
install -m 0755 bin/pwnbridge-agent-linux-amd64 \
  ~/.local/bin/pwnbridge-agent-linux-amd64
```

For a source build, keep the Linux agent adjacent to the client, or set
`PWNBRIDGE_AGENT_PATH=/absolute/path/pwnbridge-agent-linux-amd64`. Release
archives place it adjacent automatically. Homebrew installs it in formula
`libexec`, where Pwnbridge finds it automatically.

Source builds also require Mutagen 0.18.1:

```console
brew install mutagen-io/mutagen/mutagen
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
pwnbridge host add x86 pwnbox
pwnbridge host doctor x86
pwnbridge host bootstrap x86 --profile pwn
pwnbridge host use x86
pwnbridge doctor
```

`host bootstrap` prints its package plan before invoking sudo. It is
idempotent, installs a user-owned pwntools 4.15 environment, supports
`--dry-run`, and can validate an already-prepared host with `--no-sudo`.
It also checks reverse forwarding; if the server forbids it, ordinary shell/run
still work and remote tmux/Zellij scope remains available.

### What gets installed remotely

There is no remote Pwnbridge service to install or keep running. On first use,
the Mac client hashes its bundled static Linux amd64 agent, uploads it over
your existing SSH connection, verifies the hash on Ubuntu, and atomically
caches it under:

```text
~/.local/share/pwnbridge/agents/1/<sha256>/pwnbridge-agent
```

`host bootstrap` separately installs the ordinary Ubuntu/Debian debugger and
build packages through `apt`, then creates the pinned pwntools environment at
`~/.local/share/pwnbridge/envs/pwn-v1`. It may use `sudo` only for system
packages; the agent, Python environment, workspaces, and session state remain
owned by the SSH user. Bootstrap is idempotent, and future client upgrades
deploy a new content-addressed agent automatically—no `scp`, remote login,
system-wide Pwnbridge binary, or persistent daemon is required.

No per-challenge config is required. From any challenge directory:

```console
pwnbridge                         # managed interactive Bash
pwnbridge run -- ./chall          # one command
pwnbridge run -- python solve.py
pwnbridge run --tty=always -- gdb ./chall
```

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
pwnbridge sync resolve --prefer local -- solve.py
# or
pwnbridge sync resolve --prefer remote -- generated.txt
```

The losing version is copied to an XDG recovery directory outside the
synchronized tree before resolution. Root deletion, safety halts, permissions,
disk errors, and disconnected endpoints also block execution. Pwnbridge never
resets synchronization history automatically.

`pwnbridge stop` performs a final barrier, terminates dependent panes, and
pauses synchronization. `pwnbridge clean` removes Pwnbridge/Mutagen metadata
but preserves both workspaces. Remote deletion requires the explicit
`pwnbridge clean --remote --yes` form.

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
See [container-runtime.md](docs/container-runtime.md).

## Diagnostics and automation

Start troubleshooting with:

```console
pwnbridge doctor
pwnbridge status
pwnbridge sync status
pwnbridge terminal providers
pwnbridge config validate
```

Commands with `--json` return a stable envelope:

```json
{"schema":1,"data":{}}
```

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
