# Configuration

Pwnbridge separates machine-private settings from portable project intent.
Both formats are strict TOML with `schema = 1`; an unknown key, unsupported
schema, unsafe value, or invalid combination is an error.

Inspect exactly what is active with:

```console
pwnbridge config path
pwnbridge config validate
pwnbridge config show
pwnbridge config show --effective --json
```

## Precedence

Values are layered in this order:

```text
built-in defaults
→ global machine configuration
→ nearest ancestor project configuration
→ documented PWNBRIDGE_* environment overrides
→ command flags
```

False, empty, and zero-like values are represented with typed pointer layers,
so an explicit `false` is not mistaken for an omitted setting.

## Global configuration

The global path is `$XDG_CONFIG_HOME/pwnbridge/config.toml`, falling back to
`~/.config/pwnbridge/config.toml`. `pwnbridge host add` creates it safely; users
normally do not need to write it first.

```toml
schema = 1
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
mode = "two-way-safe"
watch_mode = "portable"
symlink_mode = "portable"
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

[runtime]
kind = "host"

[runtime.container]
engine = "auto"
workdir = "/work"
network = "bridge"
```

### Hosts

`destination` is passed as one argument to the system `ssh`/`scp`; an OpenSSH
alias is recommended. It may also be a conventional `user@host` destination.
Hostnames, users, ports, ProxyJump, and identity files belong in SSH config,
not in portable `.pwnbridge.toml` files.

Only `linux/amd64` is supported. Workspace roots default below the remote
user's home. Host names are 1-64 ASCII letters, digits, dots, underscores, or
hyphens; SSH destination aliases may be more descriptive.

Use these commands rather than hand-editing host records:

```console
pwnbridge host add NAME DESTINATION [--shell-transport auto|mosh|ssh]
                                     [--mosh-port PORT[:PORT]]
pwnbridge host list
pwnbridge host show NAME
pwnbridge host transport NAME auto|mosh|ssh [--mosh-port PORT[:PORT]]
pwnbridge host default NAME
pwnbridge host use NAME
pwnbridge host use --default
pwnbridge host remove NAME
```

`host default` changes the machine-wide fallback. `host use NAME` stores a
local project-to-host binding under XDG state, while `host use --default`
removes that override. None of these commands put a machine name into the
project checkout. `host list` marks the machine default with `*` and the
current project's effective host with `>`.

Host selection specifically follows this precedence, from lowest to highest:

```text
global default_host
→ local project binding
→ PWNBRIDGE_HOST
→ --host NAME
```

`workspace_root` accepts a safe path below the remote home (the portable
default) or an absolute server-local path such as `/srv/pwnbridge/workspaces`.
Pwnbridge always appends its installation and workspace identity beneath it.

`shell_transport` is host-local network policy: `auto` prefers predictive Mosh
and falls back to SSH, `mosh` requires it, and `ssh` disables it. `mosh_port`
is one UDP port or an inclusive ascending range passed to Mosh. The default is
`60000:61000`; open the same range on the remote firewall/security group.
Mosh is used only for the interactive PTY. Authentication, file barriers,
debugger control, one-shot commands, and cleanup remain on OpenSSH. Explicit
`terminal.scope = "remote"` uses SSH because its nested multiplexer control is
not compatible with the Mosh path.

### Synchronization

The supported engine/mode/watch combination is intentionally fixed:

- `engine = "mutagen"`
- `mode = "two-way-safe"`
- `watch_mode = "portable"`
- `symlink_mode = "portable"` or advanced `"posix-raw"`

`portable` symlinks are safest across macOS/Linux. `posix-raw` is available for
projects that explicitly need raw symlink semantics and understand the
cross-platform risk.

`barrier_timeout` is any positive Go duration such as `30s`, `2m`, or `5m`.
It applies to synchronization barriers, not the lifetime of a remote command.
The default `pause_on_idle = false` keeps Mutagen's lightweight synchronization
session warm between commands, which makes repeated launches faster. When it is
true, the final session lease flushes and pauses Mutagen; `pwnbridge stop`
always provides an explicit flush-and-pause operation.

### Terminal

Host scope accepts:

```text
auto zellij tmux wezterm kitty iterm2 terminal-app custom:NAME
```

Remote scope accepts `auto`, `tmux`, `zellij`, `remote-tmux`, or
`remote-zellij`, and supports only right/down placement. Remote scope cannot be
combined with container runtime.

Valid placements are `right`, `down`, `tab`, `floating`, and `window`, subject
to provider capability. Sizes are percentages from `1%` through `99%`.

Provider-specific Zellij/tmux sections override the general right/down and size
selection whenever that provider is selected, explicitly or by `auto`. See
[terminal-providers.md](terminal-providers.md).

### Global runtime defaults

Global `[runtime]` and `[runtime.container]` values are the base layer for every
project. A project may override individual container fields without repeating
them all.

Container `engine` is `auto`, `docker`, or `podman`; `image` is preferably a
digest reference; `workdir` is `/work` or a directory beneath it; and `network`
is one Docker/Podman network-mode argument. At container creation, a configured
tag is resolved to the engine's immutable 64-hex-character SHA-256 image ID;
later debugger panes reuse that session container. Values beginning with a dash,
containing whitespace/control characters, or exceeding bounds are rejected.

## Project configuration

`.pwnbridge.toml` is optional. Pwnbridge walks from the current directory to
the filesystem root and uses the nearest file. A Git root is never selected
implicitly.

`pwnbridge init` creates this portable host-runtime template without
overwriting an existing file:

```toml
schema = 1
target = "linux/amd64"

[workspace]
root = "."
ignore = []

[environment]
profile = "pwn"
set = {}

[shell]
command = "bash"
source_user_rc = true

[runtime]
kind = "host"
```

### Workspace root and ignores

`workspace.root` is relative to the directory containing `.pwnbridge.toml` and
must remain inside it. This lets a repository keep configuration at its root
while synchronizing only a subdirectory.

`workspace.ignore` and line-oriented `.pwnbridgeignore` extend conservative
built-ins:

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

Blank lines and `#` comments in `.pwnbridgeignore` are ignored. `.gitignore` is
not imported automatically. Challenge binaries, libc/loaders, cores, dumps,
logs, patched files, and exploit artifacts are deliberately not ignored.

### Environment

`profile = "pwn"` prepends the user-owned bootstrap virtualenv when it exists.
Project environment values are passed structurally:

```toml
[environment]
profile = "pwn"

[environment.set]
PWNLIB_NOTERM = "0"
LC_ALL = "C.UTF-8"
```

Keys must be POSIX-style environment names (`[A-Za-z_][A-Za-z0-9_]*`), are
limited to 128 bytes, and may not use the reserved `PWNBRIDGE_` prefix. Values
are limited to 64 KiB and cannot contain NUL. These checks keep project config
portable and prevent it from replacing session/broker authority.

Transport-owned `SSH_*`, local `TMUX`/`ZELLIJ`, terminal metadata, and internal
Pwnbridge values are not restored into debugger panes. Relevant `PATH`,
`VIRTUAL_ENV`, `LD_*`, locale, `PWNLIB_*`, and debugger variables are retained.

### Shell

Managed interactive shell currently requires Bash. With `source_user_rc =
true`, the generated private rcfile sources `~/.bashrc` before installing its
hooks. Pwnbridge does not edit `.bashrc`. SSH shells use authenticated prompt
markers in the local PTY proxy. Mosh shells use a private remote Bash DEBUG and
prompt hook that calls the authenticated synchronization broker before and
after each command; a failed pre-command barrier skips execution.

One-shot `pwnbridge run` does not depend on the user's login shell. User argv is
sent structurally. To intentionally request shell parsing, make it explicit:

```console
pwnbridge run -- bash -lc 'make && ./chall | tee run.log'
```

### Container project

```toml
schema = 1
target = "linux/amd64"

[runtime]
kind = "container"

[runtime.container]
engine = "auto"
image = "ghcr.io/OWNER/pwnbridge-pwn@sha256:..."
workdir = "/work"
network = "bridge"
```

See [container-runtime.md](container-runtime.md) for lifecycle and isolation
details.

## Environment overrides

Only these variables are configuration overrides:

| Variable | Effect |
|---|---|
| `PWNBRIDGE_CONFIG` | absolute alternate global config path |
| `PWNBRIDGE_HOST` | selected host ID |
| `PWNBRIDGE_LOG` | log level value |
| `PWNBRIDGE_MUTAGEN_PATH` | Mutagen executable path |
| `PWNBRIDGE_AGENT_PATH` | local Linux agent asset path |
| `PWNBRIDGE_RUNTIME` | `host` or `container` |

Standard absolute `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_DATA_HOME`, and
`XDG_CACHE_HOME` values relocate their corresponding Pwnbridge directories.
Relative XDG values are ignored in favor of platform fallbacks.

The `PWNBRIDGE_` prefix is reserved. Broker/session credentials are kept in a
private per-session `terminal.json` beside the injected wrapper and are not
exported into the managed command environment.

## Portable configuration rules

Do not commit any of the following to `.pwnbridge.toml`:

- destination hostname, user, key path, or SSH options;
- bearer tokens or session IDs;
- a local terminal application/provider preference;
- absolute paths tied to one Mac;
- mutable production image tags when a digest is available.

The portable file should describe the target and project intent. Machine
identity and personal preference stay in global config or local state.
