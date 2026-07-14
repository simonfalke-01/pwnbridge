# CLI reference

## Daily commands

### `pwnbridge` / `pwnbridge shell`

Open managed interactive Bash in the synchronized remote workspace. Bare
`pwnbridge` is identical. Pre-command Enter and post-command prompt are guarded
by synchronization barriers. The default `auto` transport adds pwnbridge local
echo prediction to the normal inline SSH stream, so typing appears immediately
without clearing the screen or losing shell history. `ssh` disables prediction.
`mosh` is an explicit opt-in for users who prefer roaming and reconnection; it
uses Mosh's full-screen terminal model. Pwnbridge suppresses Mosh's normal exit
banner while leaving connection and server errors visible.

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

Check local platform/OpenSSH/Mutagen and configured transport prerequisites.
When a host is selected, run the bounded read-only bootstrap inventory and
evaluate the selected bootstrap recipe, configured Mosh/container requirements,
and temporary reverse-forwarding capability. The command never deploys an
agent, invokes sudo, installs software, or persists remote diagnostic files.

Local, inventory, and forwarding probes have independent 10, 20, and 15 second
budgets. A failed or timed-out inventory does not suppress the forwarding
result; parent cancellation stops new probes. Human and JSON output retain every
completed check and state whether the overall evaluation was `complete`. JSON
data has stable `ok`, `complete`, and ordered `checks` fields. Missing
capabilities are complete failures; an unavailable required collector is an
incomplete failure. Either returns nonzero after output, while Ctrl-C preserves
exit 130. `pwnbridge host doctor NAME` uses the same remote collector and
selected host recipe without the project-local checks.

### `pwnbridge support [--json] [--local-only]`

Print a support report constructed from a positive privacy allowlist. The
report remains available when configuration, Mutagen state, recovery inventory,
or SSH collection fails; unavailable collectors expose only a category such as
`invalid`, `timeout`, `permission`, or `unavailable`, never their raw error.

Default output is concise line-oriented Markdown for issue text. `--json` wraps
the same typed fields in the standard schema-one envelope. With a selected host,
the default command runs the existing ordinary read-only SSH inventory; it does
not deploy the agent, use sudo, install/refresh anything, or write remotely.
`--local-only` performs no SSH operation.

Included fields cover client/build/protocol/schema/required-Mutagen and Go
platform versions, safe effective sync/runtime/terminal behavior, capability
booleans, counts, coarse synchronization/recovery state, and allowlisted remote
platform/capability data. Paths, contents, host names/destinations/addresses,
IDs, config/environment names or values, shell commands, container images,
conflict/recovery paths, logs, tokens, command output, and raw errors are never
serialized. Custom provider and user-defined container-network names collapse
to `custom`. The report is not uploaded or saved; review output before sharing
it.

### `pwnbridge stop`

Signal live Pwnbridge clients for this workspace, wait for pane/runtime cleanup,
perform a final barrier, pause Mutagen, and close the bounded warm OpenSSH
master.

### `pwnbridge clean [--remote --yes]`

Stop clients and terminate Pwnbridge synchronization metadata. Local and remote
roots remain by default. A private local lifecycle record remembers the retained
remote root for safe host retirement. Both `--remote` and `--yes` are required
to delete the remote workspace; only a successful remote deletion clears that
retention marker. The warm OpenSSH master is closed in either mode.
Conflict-recovery copies remain separately cataloged.

### `pwnbridge init`

Create `.pwnbridge.toml` and `.pwnbridgeignore` templates in the current
directory. Existing files are never overwritten. Configuration is optional.

## Host commands

```text
pwnbridge host add NAME DESTINATION [--check] [--replace] [--default] [--json]
                                     [--shell-transport auto|mosh|ssh]
                                     [--mosh-port PORT[:PORT]]
pwnbridge host list
pwnbridge host show NAME [--json]
pwnbridge host transport NAME auto|mosh|ssh [--mosh-port PORT[:PORT]]
pwnbridge host default NAME
pwnbridge host use NAME
pwnbridge host use --default
pwnbridge host remove NAME (--dry-run|--yes) [--force] [--json]
pwnbridge host doctor NAME [--json]
pwnbridge host bootstrap NAME [--interactive auto|always|never]
                              [--profile NAME | --recipe-file FILE]
                              [--with COMPONENT]... [--without COMPONENT]...
                              [--apt-package PACKAGE]... [--pip-package REQUIREMENT]...
                              [--save-profile NAME] [--with-pwndbg]
                              [--no-sudo] [--dry-run] [--yes]
                              [--accept-docker-root-risk]
                              [--accessible] [--verbose] [--json]
```

`add` writes machine-private global config and never depends on project-local
configuration. The first host becomes the default; `--default` explicitly
changes the default when other hosts already exist. An existing name is refused
unless `--replace` is present. Host names are 1–64 ASCII letters, digits, `.`,
`_`, or `-`; the destination is an ordinary OpenSSH alias or `user@host` and
cannot begin with an option.

`add --check` first runs bounded read-only inventory and reverse-forwarding
probes. It saves only after the candidate is Linux amd64, has a writable home
with at least 1 GiB and 1000 inodes, permits same-user ptrace, and has an
executable built-in `pwn` bootstrap plan plus forwarding required by the global
terminal scope. Missing installable tools are pending bootstrap work, not check
failures. Human output is control-safe; `--json` returns the candidate,
persisted/replaced/default state, and complete check report. A failed check or
checked replacement leaves the previous durable record unchanged. The check
does not deploy, copy, install, invoke sudo, Mutagen, or write remotely.
If global terminal scope changes while the probes run, commit stops and asks for
a retry rather than applying a stale forwarding decision.

`remove --dry-run` is an offline, non-mutating inventory of the machine default,
all project bindings, managed workspace records, non-empty recovery roots, and
active session leases. `remove --yes` repeats that inventory inside the global
configuration transaction, then removes only an unreferenced host record.
Default and inactive references require cleanup or explicit `--force --yes`;
force leaves those local records untouched so re-adding the same host name can
manage them again. A live or unidentifiable session is never overridable.
Unsafe/corrupt XDG catalogs fail closed. Human paths are quoted and `--json`
provides stable `safe`, `allowed`, `removed`, blocker, binding, workspace, and
unattributed-reference fields. None of these modes uses SSH, Mutagen, the agent,
or remote deletion.

`default` changes the machine-wide fallback. `use NAME` writes an override for
the current project only, and `use --default` removes that override. In `host
list`, `*` marks the machine default and `>` marks the current project's
effective host. `bootstrap --dry-run` performs a read-only SSH inventory and
never deploys the agent, invokes sudo, refreshes repositories, installs, or
writes recipes. Non-interactive application requires `--yes`; JSON implies
non-interactive and reserves stdout for one result envelope. `--with-pwndbg`
aliases `--with pwndbg`. Explicit component and `--no-sudo` constraints are
locked in the wizard. Recipe precedence is component/package flags, recipe
file, explicit profile, host-bound profile, then built-in `pwn`.

Recipe commands are `config bootstrap list`, `show NAME [--json]`, `import
FILE [--name NAME] [--replace]`, `export NAME [--output FILE|-]`, and `remove
NAME`.

`auto` is the default interactive transport and uses pwnbridge predictive echo
over an inline SSH PTY. `ssh` uses the same PTY without prediction. `mosh`
explicitly selects Mosh and requires the local client, remote `mosh-server`,
reverse sync bridge, compatible host terminal scope, and configured UDP path.
One-shot `run`, sync, cleanup, and broker control always use the private SSH
master.
`host transport` updates only the named machine-wide host record; it does not
change the machine default or the current project's host binding.

## Synchronization commands

```text
pwnbridge sync status [--json]
pwnbridge sync flush
pwnbridge sync pause
pwnbridge sync resume
pwnbridge sync conflicts [--json]
pwnbridge sync diff -- PATH...
pwnbridge sync resolve --prefer local|remote -- PATH...
pwnbridge sync recovery list [--json]
pwnbridge sync recovery verify [ID...] [--json]
pwnbridge sync recovery restore ID --to PATH
pwnbridge sync recovery prune --keep-last N (--dry-run|--yes) [--json]
```

`flush` is a full safety barrier, not merely a watch trigger. `diff` accepts
only exact current conflict paths and prints a unified local-to-remote preview
for display-safe UTF-8 regular files up to 1 MiB per endpoint. It reports
bounded metadata for larger, binary/control-bearing, symlink, directory,
special-file, and missing-endpoint conflicts. Previewing never chooses a
winner or changes synchronized content. `resolve` applies the same exact-path
validation, backs up each loser, and requires the entire session to become
healthy. `recovery list` is offline and does not inspect or resume Mutagen. It
prints stable quoted IDs, creation time, losing endpoint, kind, aggregate byte
and item counts, mode, SHA-256 identity, and original path. Entries created
before digest recording print `sha256=unverified`. JSON returns the same fields
in an `entries` array inside the standard envelope.

`recovery restore` requires an exact listed ID and an explicit canonical path
relative to the current project. The target and its final object must not
already exist; regular files, directory trees, and links are restored without
following stored links. A failure removes the partially created target tree.
Cataloged digests are checked before copying and against the completed target;
legacy entries without a digest retain their compatibility behavior.
The command only changes the local workspace and never resumes a paused or
unhealthy session; run `pwnbridge sync flush` separately to verify propagation.
Pre-manifest recovery directories remain visible as conservative, individually
restorable leaf entries marked `legacy=true`.

`recovery verify` is an offline, read-only full-content check. With no IDs it
checks every listed entry newest-first; otherwise each argument must be an exact
listed ID and results retain argument order. It regenerates the deterministic
descriptor-rooted archive identity and compares SHA-256, kind, mode, byte count,
and item count without changing recovery data or synchronization state. Checks
are sequential and hold the workspace lock, so runtime is proportional to all
selected content and concurrent workspace operations wait. On an interactive
human terminal, a delayed transient line reports selected entry/count and
byte-derived percentage (item-derived for zero-byte trees); it is throttled,
contains no recovery path, and adds no preliminary counting pass. Human output
quotes IDs and reports each completed entry as `verified`, `failed`, or
`unverified`; `--json` emits no progress and returns the same entries plus
aggregate `checked`, `total`, and `complete` fields in one document. Ctrl-C
prints the completed subset with `complete=false` and then returns 130. Failed
or pre-digest entries make a completed command return nonzero. Verification
never repairs, deletes, or implicitly enrolls a legacy digest.

`recovery prune` is the supported way to reclaim local recovery storage. One
archive contains every losing copy recorded by a single conflict-resolution
invocation; retention and deletion always use that complete archive boundary.
`--keep-last N` must be at least one and retains the newest N archives.
`--dry-run` previews exact quoted archive IDs, entry/item counts, and logical
bytes without mutation; `--yes` performs the irreversible deletion. Exactly one
of those flags is required. `--json` returns the same ordered archive results
and `kept`, `selected`, `pruned`, `pending_cleanup`, `not_run`,
`logical_bytes`, `dry_run`, and `complete` totals.

Pruning holds the workspace lock but is otherwise local and offline: it never
runs SSH or Mutagen, changes sync state, or touches either workspace. A selected
archive is atomically and durably hidden before its tree is removed. Cancellation
or a filesystem error after that point reports `pending-cleanup`; its copy is no
longer restorable through the catalog but may still consume space. The next
confirmed prune first resumes cleanup of exact Pwnbridge tombstones. Logical
bytes describe stored content and link targets, not allocated filesystem blocks.
Slow terminal cleanup shows one delayed path-free transient status line; JSON
and redirected operation remain quiet until the report.

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

Container creation occurs lazily on the first `shell`, `run`, or debugger-pane
request. If its image is absent, a terminal streams the engine's pull progress
on stderr. Redirected and non-terminal requests use Docker/Podman quiet mode and
emit no successful pull output. Interrupting setup cancels the engine client;
the original managed command does not start and Pwnbridge returns 130.

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
