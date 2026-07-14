# Troubleshooting

Start with read-only diagnostics:

```console
pwnbridge doctor
pwnbridge status
pwnbridge sync status
pwnbridge sync conflicts
pwnbridge terminal providers
pwnbridge config validate
pwnbridge support --local-only
```

Use `--json` where supported when collecting structured diagnostics. JSON is
always wrapped as `{"schema":1,"data":...}`.

Doctor is deliberately partial-result: local prerequisites, read-only remote
inventory, and reverse forwarding have independent 10/20/15-second budgets.
One failure does not discard earlier checks, and an inventory failure still
allows the forwarding probe unless you cancel the command. `complete=false`
means at least one required collector could not determine its downstream
capabilities; `complete=true, ok=false` means all probes finished and found a
real missing or unhealthy prerequisite. Both conditions return nonzero after
printing the report. Ctrl-C prints accumulated checks and returns 130.

Doctor output is bounded and control-safe but can contain local paths and
remote error details. Use the positive-allowlist `support` report—not raw doctor
output—when pasting into a public issue. Doctor does not deploy the agent or
persist remote files; `host bootstrap` and normal execution are the explicit
paths that install or refresh the content-addressed agent and tool environment.

For a first public support exchange, prefer `pwnbridge support`. It gathers a
safe allowlist rather than copying the raw commands above and tells you exactly
which data classes it omitted. By default it also attempts the read-only remote
inventory through ordinary SSH; use `--local-only` when authentication is the
problem or no network connection should be attempted. Collection failures are
reported as categories while the rest of the report remains usable. Pwnbridge
does not upload or save the report—review it and paste it where appropriate.
Private bootstrap and Mutagen logs remain local and are not support-report
inputs.

## Configuration is rejected

Run validation from the directory whose project you intend to use:

```console
pwnbridge config path
pwnbridge config validate
```

Decode failures use `FILE:LINE:COLUMN` and name the configuration key when the
parser can identify it. Unknown keys remain errors; remove the misspelling
rather than expecting it to be ignored. Pwnbridge never includes the offending
value or surrounding TOML in this message. Files over 1 MiB and values nested
more than 10,000 array/inline-table levels are rejected deliberately. If the
reported project path is surprising, Pwnbridge found `.pwnbridge.toml` in an
ancestor; run `config path` before changing either file.

## The wrong host is selected

Inspect both selection scopes from the project directory:

```console
pwnbridge status
pwnbridge host list
```

In `host list`, `*` marks the machine-wide default and `>` marks the current
project's effective host. Change the intended scope explicitly:

```console
pwnbridge host default remote-x86  # machine-wide fallback
pwnbridge host use remote-x86      # current project override
pwnbridge host use --default       # remove the project override
```

`PWNBRIDGE_HOST` overrides both stored selections, and `--host NAME` overrides
the environment for one invocation. If the displayed project root is not the
directory you expected, check for a `.pwnbridge.toml` in an ancestor; its
workspace root determines which local binding applies.

## Mutagen is missing or the version is wrong

Pwnbridge requires exactly Mutagen 0.18.1 because CLI templates and health
parsing are version-sensitive.

```console
brew install mutagen-io/mutagen/mutagen
mutagen version
```

If another executable shadows it, set an absolute
`PWNBRIDGE_MUTAGEN_PATH` or fix PATH. Pwnbridge runs an isolated daemon under
its XDG state directory, so stopping your global Mutagen daemon does not repair
Pwnbridge state. `doctor` reports the path and exact version it sees.

If the ordinary Mutagen background launcher is unavailable, Pwnbridge falls
back to the documented foreground daemon entry point and detaches it only after
successful process creation. Cancelling or timing out startup before that point
does not launch the fallback. Its private output is
`$XDG_STATE_HOME/pwnbridge/mutagen/v0.18/daemon.log`; on fallback startup a log
larger than 5 MiB moves to `daemon.log.previous`. This is a startup threshold,
not a live cap while the daemon is running.

An `owner-private directory`, `owner-private regular file`, `changed while it
was being opened`, or rotation error means the state entry is unsafe or was
modified concurrently. Stop Pwnbridge commands, inspect the named entry without
following links, and move the unexpected entry outside the Pwnbridge state tree
before retrying. Do not replace it with a FIFO, device, socket, directory, or
symbolic link; Pwnbridge deliberately refuses those rather than hanging or
redirecting daemon output.

## SSH fails

Make the registered destination work through ordinary OpenSSH first:

```console
ssh pwnbox true
ssh -G pwnbox | less
```

For a new record, obtain the same bounded readiness result before saving:

```console
pwnbridge host add x86 pwnbox --check
pwnbridge host add x86 pwnbox --check --json
```

`complete=false` distinguishes a timed-out/cancelled inventory or required
forwarding collector from a fully evaluated incompatible host. A check also
fails for non-Linux-amd64, unknown/low home capacity, unwritable home, ptrace
scope 3, a blocked `pwn` bootstrap plan, or unavailable forwarding required by
host terminal scope. It never installs the missing tools. If the name already
exists, inspect it with `host show` and pass `--replace` only when replacement
is intentional; a failed checked replacement keeps the old record. Omit
`--check` only for an intentionally offline local registration.

Pwnbridge does not bypass host-key prompts, key passphrases, hardware-token
touch, `ProxyJump`, or `Match` rules. Resolve interactive authentication before
expecting unattended `pwnbridge run`.

If a control master fails, inspect server policy for TCP/stream-local
forwarding. Normal non-GDB commands need SSH but not broker forwarding. Use
explicit remote multiplexer scope if all reverse forwarding is prohibited.

## Explicit Mosh cannot connect

Inspect both ends and the selected host record:

```console
command -v mosh
ssh pwnbox command -v mosh-server
pwnbridge host show x86
pwnbridge doctor
```

The default `shell_transport = "auto"` does not use Mosh: it provides immediate
local typing over an inline SSH PTY. Run `pwnbridge host transport x86 mosh` to
opt into Mosh; missing local Mosh, `mosh-server`, the authenticated reverse
synchronization bridge, or a compatible host terminal scope then produces an
explicit startup error. `terminal.scope = "remote"` is intentionally
incompatible with Mosh.

If Mosh starts but never connects, allow the configured `mosh_port` UDP range
(default 60000–61000) through the Ubuntu firewall and any cloud security group.
This is UDP, not TCP. Narrowing the range in global host config and opening the
same range is often easier. SSH must still work because Mosh authenticates and
starts `mosh-server` through SSH.

## The Linux agent is not found

Source builds need the Linux asset adjacent to the client:

```console
make build
ls -l bin/pwnbridge bin/pwnbridge-agent-linux-amd64
export PWNBRIDGE_AGENT_PATH="$PWD/bin/pwnbridge-agent-linux-amd64"
```

Release archives already contain the adjacent asset, and Homebrew installs it
under the formula libexec directory. Deployment verifies SHA-256 and platform;
an ARM or non-Linux remote is rejected.

## Bootstrap fails

Preview before retrying:

```console
pwnbridge host bootstrap x86 --dry-run
pwnbridge host doctor x86
```

Bootstrap supports Linux amd64 with apt, dnf/yum, pacman, zypper, apk, XBPS,
Portage, or Nix, a writable home, at least 1 GiB free, and 1000 inodes.
Immutable or incompatible hosts receive a safe container/manual alternative.
`--no-sudo` names every missing privileged component before any user-owned
mutation. Complete mode-0600 logs are under the XDG state directory; rerun the
same recipe to resume because healthy steps are skipped.

It is idempotent. Fix the reported package-manager/network/permission problem and rerun the
same command. A failed Pwndbg download leaves only a private temporary directory
which the command trap removes; the active version changes only after checksum
verification and complete extraction.

## Synchronization is unhealthy

Exit code `4` means a safety barrier stopped execution. Inspect:

```console
pwnbridge sync status
pwnbridge sync conflicts --json
```

Possible causes include a file conflict, excluded conflict, scan/transition
problem, disconnected endpoint, safety halt, permissions, disk full, or a
deleted root. Fix endpoint/disk/permission problems outside Pwnbridge, then run:

```console
pwnbridge sync resume
pwnbridge sync flush
```

Pwnbridge does not reset Mutagen history automatically.

## Resolve a conflict

Choose explicitly after inspecting both copies:

```console
pwnbridge sync diff -- solve.py
pwnbridge sync resolve --prefer local -- solve.py
pwnbridge sync diff -- core.1234
pwnbridge sync resolve --prefer remote -- core.1234
```

`sync diff` shows display-safe text as a unified local-to-remote diff. It never
prints terminal control bytes: binary/control-bearing or larger-than-1-MiB
content is summarized by type, size, mode, and a digest when content was small
enough to capture. Links show quoted targets, and directories/special files
show metadata. The preview is read-only; rerun it if either endpoint may have
changed before resolving.

Only current conflict paths are accepted, including paths with spaces. The
losing endpoint is backed up under `$XDG_DATA_HOME/pwnbridge/recovery/` before
removal. The command reports the exact backup path. Resolution is not complete
until a full healthy barrier succeeds.

For a remote loser, the agent keeps the source until the client has durably
extracted and cataloged a validated stream and acknowledged its SHA-256. It
then re-reads the source and refuses removal if anything changed. An error that
says the outcome is uncertain means acknowledgement succeeded but the final
agent result was lost; the message identifies the durable backup. Inspect both
endpoints before retrying.

Recovery copies remain available after that output scrolls away:

```console
pwnbridge sync recovery list
pwnbridge sync recovery list --json
pwnbridge sync recovery verify
pwnbridge sync recovery restore \
  '20260714T123456.000000000Z/local-winner/solve.py' \
  --to recovered/solve.py
pwnbridge sync flush
```

Copy the ID exactly from `list`; human output quotes control and non-ASCII
characters safely, while JSON exposes the original string. Restore refuses an
existing target, verifies recorded SHA-256 content before and after copying,
and never replaces the current winner. It is deliberately a
local, offline operation: the recovered copy remains in the catalog, paused
synchronization stays paused, and a separate `sync flush` is the explicit
remote propagation check. Older recovery directories without a manifest are
listed as `legacy=true` leaf artifacts because their original directory
boundaries cannot be reconstructed reliably.
These older entries show `sha256=unverified`; new entries include a digest in
both human and JSON inventory.

Use `sync recovery verify` before an urgent restore or periodically after disk
or filesystem trouble. It reads every byte of each selected cataloged copy and
does not contact the host, run Mutagen, repair content, or change a digest. Pass
one or more exact IDs to limit the scan; otherwise all entries are checked.
`failed` means current content or metadata did not match (or could not be read),
while `unverified` means an older entry has no historical digest to compare.
Either condition returns nonzero; JSON output is still written with per-entry
results plus `checked`, `total`, and `complete` counts. Interactive human scans
show delayed path-free progress; redirected output and `--json` remain quiet
until the final report. Ctrl-C stops the read, prints completed checks with
`complete=false`, returns 130, and writes no recovery state. Re-run to verify
the unchecked remainder (or pass exact IDs from `recovery list`).

To reclaim recovery storage, preview whole-archive retention first:

```console
pwnbridge sync recovery prune --keep-last 5 --dry-run
pwnbridge sync recovery prune --keep-last 5 --dry-run --json
pwnbridge sync recovery prune --keep-last 5 --yes
```

An archive groups every loser from one resolution, so pruning never rewrites a
manifest to delete only one entry. At least one newest archive must remain and
the command has no automatic age/size policy. The reported byte total is logical
content size rather than exact disk allocation. `--yes` is irreversible: verify
or restore anything valuable before confirming. Pruning is local/offline and
does not delete current local or remote challenge files.

`pending_cleanup` means the selected archive was durably removed from the
catalog, but interrupted physical deletion may still occupy disk. Re-run the
same confirmed prune after fixing permissions or filesystem errors; it cleans
only exact randomized Pwnbridge tombstones before evaluating new archives. A
corrupt catalog blocks pruning rather than guessing retention boundaries.

If the session is unhealthy but contains no file conflict, `resolve` refuses;
repair the endpoint problem instead.

## The remote root was deleted

Pwnbridge intentionally blocks rather than recreating it and risking local
deletion propagation. Verify the local challenge directory first. Then create
new synchronization history explicitly:

```console
pwnbridge clean
pwnbridge run -- true
```

`clean` terminates only metadata and preserves the local directory. The next
run creates a fresh remote root/session. Do not use `clean --remote --yes` as a
generic repair command; that explicitly requests remote deletion.

## GDB does not open a pane

Check provider detection before debugging:

```console
pwnbridge terminal providers
pwnbridge terminal test --provider auto
```

Common fixes:

- select `terminal-app` for a zero-configuration window fallback;
- run inside Zellij/tmux if selecting that provider;
- remove hard-coded pwntools `context.terminal` or set it to
  `["pwntools-terminal"]`;
- run `pwnbridge host bootstrap x86` for GDB/gdbserver/pwntools/socat;
- verify reverse forwarding, or configure remote tmux/Zellij scope;
- do not combine remote terminal scope with container runtime.

When `hold_on_failure = true`, read the failing pane before pressing Enter to
close it.

## `gdb.attach()` hangs

Run a small baseline first:

```python
from pwn import *
io = process("./chall")
gdb.attach(io, gdbscript="continue")
io.interactive()
```

Check Yama/ptrace in `host doctor`. Ubuntu's ordinary same-user child debugging
works with the bootstrap profile; hardened servers may prohibit it. Container
runtime adds `SYS_PTRACE` and its required seccomp adjustment.

For `api=True`, keep the returned bridge object alive and close it normally:

```python
_, bridge = gdb.attach(io, api=True)
bridge.continue_nowait()
# ...
bridge.quit()
```

## Pwndbg conflicts with GEF/PEDA

Pwnbridge never replaces default `gdb`. Optional Pwndbg is exposed separately
and its wrapper passes `-nx`:

```python
context.gdb_binary = "pwndbg"
```

If `gdb` still resolves to Pwndbg after upgrading from an experimental build,
rerun `pwnbridge host bootstrap x86 --with-pwndbg`; it removes only a Pwnbridge-
owned `gdb` symlink and leaves unrelated user executables alone.

## Container runtime fails

On the remote host:

```console
podman info          # or docker info
podman pull IMAGE
```

The configured image must be Linux amd64 and contain Bash, Python/pwntools,
GDB, and gdbserver. Prefer a digest. A bridge-network container needs the
normal stream-local broker or the `socat` loopback fallback supplied by
bootstrap.

On the first uncached interactive run, native Docker/Podman pull progress should
appear before the command starts. Redirected or non-terminal runs intentionally
use `--quiet`; inspect stderr only when the command fails. Ctrl-C cancels the
engine client and returns 130. If setup reports a 65536-byte limit, the engine
or a wrapper emitted more data than the fixed management contract permits;
run the equivalent `podman image inspect`/`docker image inspect` manually and
check aliases, wrappers, daemon health, and plugins rather than increasing an
unrelated Pwnbridge timeout.

Reset only Pwnbridge-labeled containers for this workspace:

```console
pwnbridge runtime status
pwnbridge runtime reset
```

This stops active Pwnbridge sessions and preserves synchronized files.

## The local terminal looks broken

Pwnbridge restores termios on all normal error/cancellation paths. If the whole
parent terminal was killed ungracefully, repair it with:

```console
stty sane
reset
```

Then run `pwnbridge status` and `pwnbridge stop` to clear any remaining owned
session. Do not manually delete XDG session files while a client is live.

## Stop versus clean

- `pwnbridge stop`: signal active clients, close panes, final flush, pause sync.
- `pwnbridge clean`: stop clients, terminate Mutagen metadata, keep both roots
  and a private remote-retention catalog marker.
- `pwnbridge clean --remote --yes`: additionally delete the remote workspace.
- `pwnbridge runtime reset`: remove labeled containers, keep workspace/sync.

All destructive scope is explicit. If a cleanup command fails due to network
loss, neither workspace is treated as disposable; reconnect and rerun it.

Before deleting a configured endpoint, run `pwnbridge host remove NAME
--dry-run`. If it reports the machine default, select another with `host
default`. Visit listed projects to run `stop`, `clean`, or `clean --remote --yes`
as appropriate and clear explicit bindings with `host use --default`. Recovery
copies intentionally keep the host referenced. `--force --yes` preserves
inactive dangling metadata and is recoverable by re-adding the same name; it
cannot override a live session and never deletes remote data.
