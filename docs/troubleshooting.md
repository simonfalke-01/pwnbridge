# Troubleshooting

Start with read-only diagnostics:

```console
pwnbridge doctor
pwnbridge status
pwnbridge sync status
pwnbridge sync conflicts
pwnbridge terminal providers
pwnbridge config validate
```

Use `--json` where supported when collecting structured diagnostics. JSON is
always wrapped as `{"schema":1,"data":...}`.

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

## SSH fails

Make the registered destination work through ordinary OpenSSH first:

```console
ssh pwnbox true
ssh -G pwnbox | less
```

Pwnbridge does not bypass host-key prompts, key passphrases, hardware-token
touch, `ProxyJump`, or `Match` rules. Resolve interactive authentication before
expecting unattended `pwnbridge run`.

If a control master fails, inspect server policy for TCP/stream-local
forwarding. Normal non-GDB commands need SSH but not broker forwarding. Use
explicit remote multiplexer scope if all reverse forwarding is prohibited.

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

Bootstrap supports Ubuntu/Debian amd64, a writable home, at least 1 GiB free,
at least 1000 inodes, and apt/sudo unless `--no-sudo` is used. `--no-sudo`
checks and names every missing executable rather than partly succeeding.

It is idempotent. Fix the reported apt/network/permission problem and rerun the
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
pwnbridge sync resolve --prefer local -- solve.py
pwnbridge sync resolve --prefer remote -- core.1234
```

Only current conflict paths are accepted, including paths with spaces. The
losing endpoint is backed up under `$XDG_DATA_HOME/pwnbridge/recovery/` before
removal. The command reports the exact backup path. Resolution is not complete
until a full healthy barrier succeeds.

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
- `pwnbridge clean`: stop clients, terminate Mutagen metadata, keep both roots.
- `pwnbridge clean --remote --yes`: additionally delete the remote workspace.
- `pwnbridge runtime reset`: remove labeled containers, keep workspace/sync.

All destructive scope is explicit. If a cleanup command fails due to network
loss, neither workspace is treated as disposable; reconnect and rerun it.
