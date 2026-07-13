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

[sync]
engine = "mutagen"
mode = "two-way-safe"
watch_mode = "portable"
symlink_mode = "portable"
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
user's home. Host names may not contain whitespace or path separators.

Use these commands rather than hand-editing host records:

```console
pwnbridge host add NAME DESTINATION
pwnbridge host list
pwnbridge host show NAME
pwnbridge host use NAME
pwnbridge host remove NAME
```

`host use` stores a local project-to-host binding under XDG state; it does not
put a machine name into the project checkout.

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
When `pause_on_idle` is true, the final session lease flushes and pauses the
Mutagen session.

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
selection when that provider is explicit. See
[terminal-providers.md](terminal-providers.md).

### Global runtime defaults

Global `[runtime]` and `[runtime.container]` values are the base layer for every
project. A project may override individual container fields without repeating
them all.

Container `engine` is `auto`, `docker`, or `podman`; `image` is a tag or,
preferably, digest reference; `workdir` must be absolute; and `network` is a
single Docker/Podman network-mode argument. Values beginning with a dash,
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

Transport-owned `SSH_*`, local `TMUX`/`ZELLIJ`, terminal metadata, and internal
Pwnbridge values are not restored into debugger panes. Relevant `PATH`,
`VIRTUAL_ENV`, `LD_*`, locale, `PWNLIB_*`, and debugger variables are retained.

### Shell

Managed interactive shell currently requires Bash. With `source_user_rc =
true`, the generated private rcfile sources `~/.bashrc` before installing its
marker hooks. Pwnbridge does not edit `.bashrc`.

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

Internal `PWNBRIDGE_BROKER*`, `PWNBRIDGE_SESSION*`, and `PWNBRIDGE_RUNTIME`
values visible inside a managed process are session protocol data, not public
configuration knobs.

## Portable configuration rules

Do not commit any of the following to `.pwnbridge.toml`:

- destination hostname, user, key path, or SSH options;
- bearer tokens or session IDs;
- a local terminal application/provider preference;
- absolute paths tied to one Mac;
- mutable production image tags when a digest is available.

The portable file should describe the target and project intent. Machine
identity and personal preference stay in global config or local state.
