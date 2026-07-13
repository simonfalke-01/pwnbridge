# CLI reference

## Daily commands

### `pwnbridge` / `pwnbridge shell`

Open managed interactive Bash in the synchronized remote workspace. Bare
`pwnbridge` is identical. Pre-command Enter and post-command prompt are guarded
by synchronization barriers.

The installed `pb` executable is the concise one-shot interface. `pb COMMAND
[ARG...]` is equivalent to `pwnbridge run -- COMMAND [ARG...]` with automatic
PTY selection. It deliberately needs no `--`: `pb pwninit` runs `pwninit` and
returns without opening a shell.

### `pwnbridge run [--tty=auto|always|never] -- COMMAND [ARG...]`

Run structural argv in the active remote runtime. `auto` allocates a PTY when
local stdin is a terminal; `always` forces it; `never` uses ordinary streams.
Remote exit codes are preserved.

Use `--` before commands with flags. Pipelines require explicit `bash -lc`.

### `pwnbridge status [--json]`

Show project root, selected host, remote path, sync state, and active session
IDs. It does not create a workspace.

### `pwnbridge doctor [--json]`

Check local platform/OpenSSH/Mutagen and, when a host is selected, deploy the
diagnostic agent and check platform, distro, disk/inodes, writable home,
ptrace, pwntools, and required tools.

### `pwnbridge stop`

Signal live Pwnbridge clients for this workspace, wait for pane/runtime cleanup,
perform a final barrier, and pause Mutagen.

### `pwnbridge clean [--remote --yes]`

Stop clients and terminate Pwnbridge synchronization metadata. Local and remote
roots remain by default. Both `--remote` and `--yes` are required to delete the
remote workspace.

### `pwnbridge init`

Create `.pwnbridge.toml` and `.pwnbridgeignore` templates in the current
directory. Existing files are never overwritten. Configuration is optional.

## Host commands

```text
pwnbridge host add NAME DESTINATION
pwnbridge host list
pwnbridge host show NAME [--json]
pwnbridge host default NAME
pwnbridge host use NAME
pwnbridge host use --default
pwnbridge host remove NAME
pwnbridge host doctor NAME [--json]
pwnbridge host bootstrap NAME [--profile pwn]
                              [--with-pwndbg]
                              [--dry-run]
                              [--no-sudo]
```

`add` writes machine-private global config. The first host becomes the default.
Host names are 1–64 ASCII letters, digits, `.`, `_`, or `-`; the destination is
an ordinary OpenSSH alias or `user@host` and cannot begin with an option.
`default` changes the machine-wide fallback. `use NAME` writes an override for
the current project only, and `use --default` removes that override. In `host
list`, `*` marks the machine default and `>` marks the current project's
effective host. `bootstrap --dry-run` does not deploy or mutate; `--no-sudo`
skips apt and reports missing prerequisites; the only profile is `pwn`.
Doctor/bootstrap probe reverse forwarding; unavailable forwarding is fatal to
host-pane diagnostics but not to shell/run or explicit remote-multiplexer
scope.

## Synchronization commands

```text
pwnbridge sync status [--json]
pwnbridge sync flush
pwnbridge sync pause
pwnbridge sync resume
pwnbridge sync conflicts [--json]
pwnbridge sync resolve --prefer local|remote -- PATH...
```

`flush` is a full safety barrier, not merely a watch trigger. `resolve` accepts
only exact current conflict paths, rejects duplicates/escapes, backs up each
loser, and requires the entire session to become healthy.

## Terminal commands

```text
pwnbridge terminal providers [--json]
pwnbridge terminal test [--provider NAME]
                        [--placement right|down|tab|floating|window]
                        [--size PERCENT]
```

`test` opens the trusted local version helper through a provider. It requires no
remote host and is useful before debugging.

## Runtime commands

```text
pwnbridge runtime status [--json]
pwnbridge runtime reset
```

`status` reports effective project runtime configuration. `reset` applies only
to container projects, stops active clients, and removes labeled containers for
the current workspace while preserving synchronized files.

## Configuration commands

```text
pwnbridge config path
pwnbridge config validate
pwnbridge config show [--effective] [--json]
```

Without `--effective`, `show` prints global configuration. Effective output
includes defaults, global/project layers, environment overrides, resolved root,
selected host, and executable paths.

## Miscellaneous

```text
pwnbridge completion bash|zsh|fish
pwnbridge --version
pwnbridge version [--json]
```

`--version` (or `-v`) prints the human-readable product version, commit, and
build date. The `version` command prints the same line and additionally accepts
`--json`; version JSON includes the agent protocol, config schema, and required
Mutagen version.

Every project-aware command accepts global `--host NAME` as a non-persistent
selection override.

## JSON contract

Machine-readable commands emit:

```json
{
  "schema": 1,
  "data": {}
}
```

Field content varies by command; the envelope schema is independent from the
agent protocol and product SemVer. Errors go to stderr and never wrap a partial
success as valid data.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | success / remote command returned zero |
| `1` | configuration, transport, provider, runtime, or other Pwnbridge failure |
| `4` | synchronization safety/health blocked execution |
| `1..255` | ordinary nonzero remote command status, preserved when applicable |
| `130` | cancellation / interrupted managed command |

A remote status may numerically overlap a reserved diagnostic status. Scripts
that need to distinguish context should inspect stderr or call `sync status
--json` after code 4.
