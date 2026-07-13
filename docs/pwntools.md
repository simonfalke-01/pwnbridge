# Pwntools and GDB integration

Pwnbridge is designed for unchanged pwntools process and GDB workflows. The
exploit executes on Ubuntu, so `process()` is already native x86-64; the pane
broker exists only to satisfy pwntools' requirement that GDB start in a
separate terminal.

## Discovery

Every managed session creates a private hardlink/copy of the static agent named
`pwntools-terminal` and prepends its directory to remote PATH. Pwntools 4.15 and
current 5-dev check for this executable before their built-in terminal
heuristics.

Normally use no terminal setting:

```python
from pwn import *

context.binary = elf = ELF("./chall")
io = process(elf.path)
```

If a shared template insists on one:

```python
context.terminal = ["pwntools-terminal"]
```

Do not point `context.terminal` at local Zellij/tmux. The exploit is remote and
cannot safely construct the Mac pane itself.

## `gdb.debug`

```python
io = gdb.debug(
    "./chall",
    gdbscript="""
        break main
        continue
    """,
)
io.interactive()
```

Pwntools starts gdbserver in the active remote runtime. Its temporary GDB
script and generated Python launcher become the wrapper manifest argv. The Mac
opens a provider pane, and a second SSH channel starts GDB in the same runtime.

## `gdb.attach`

```python
io = process("./chall")
gdb.attach(io, gdbscript="continue")
io.interactive()
```

The attached PID belongs to the Ubuntu host or the long-lived container. The
GDB pane uses the authoritative session runtime, so it sees the same PID
namespace. Pwnbridge never starts GDB locally on macOS.

## Python GDB API

Pwntools' `api=True` bridge works through its usual Unix socket/temp files:

```python
io = process("./chall")
_, debugger = gdb.attach(io, api=True)
debugger.continue_nowait()
io.sendline(b"input")
debugger.quit()
```

Keep the returned object alive until the API session is finished. The
Pwnbridge wrapper remains alive with its pane and propagates GDB exit status
back to pwntools.

## Environment fidelity

Pwnbridge preserves debugger-relevant values including PATH, VIRTUAL_ENV,
`LD_PRELOAD`, `LD_LIBRARY_PATH`, locale, `PWNLIB_*`, and debugger variables.
It strips transport, local multiplexer, terminal, cwd, and internal broker
fields before launching GDB in a fresh PTY.

The exploit itself receives no internal `PWNBRIDGE_*` variables. The injected
wrapper locates private mode-0600 session metadata relative to its executable,
which keeps broker credentials out of ordinary child environments.

Arguments and environment entries are individually base64 encoded. Spaces,
Unicode, and byte-oriented argv are not re-tokenized by a shell. Manifests are
mode 0600 and limited to 1 MiB.

## Pane lifecycle

The wrapper and pane are linked:

- normal GDB exit notifies pwntools and optionally closes the pane;
- parent SIGTERM/SIGINT/HUP sends an idempotent cancel request;
- manual provider-pane close cancels the wrapper;
- broker/session shutdown closes every registered handle;
- failure can remain visible when `hold_on_failure = true`;
- multiple simultaneous requests have separate IDs and handles.

A pre-open synchronization barrier runs before every pane is approved. This
ensures GDB reads the same newly saved binary/script state as the command that
requested it.

## Pwndbg

Install the pinned optional portable build:

```console
pwnbridge host bootstrap x86 --with-pwndbg
```

Pwnbridge verifies release 2026.02.18 with SHA-256, installs it under its own
remote data directory, and exposes a `pwndbg` wrapper in the pwn environment.
It does not replace `gdb` or edit `~/.gdbinit`. The wrapper adds `-nx`, avoiding
simultaneous loading of an existing GEF/PEDA plugin.

Select it explicitly:

```python
context.gdb_binary = "pwndbg"
io = gdb.debug("./chall", gdbscript="continue")
```

Default `gdb` continues to honor the user's normal GDB configuration.

## Remote multiplexer mode

With `terminal.scope = "remote"`, `pwntools-terminal` directly invokes remote
tmux/Zellij splits. This is useful where reverse forwarding is disabled but is
not compatible with container runtime and may nest inside the host
multiplexer. Remote tmux uses a per-session server so existing tmux sessions
cannot override the managed Python environment. Host scope is recommended.

## Compatibility evidence

The end-to-end suite covers:

- pwntools 4.15.0;
- pinned current 5-dev commit used by the acceptance suite;
- `gdb.debug()`;
- process `gdb.attach()`;
- `api=True`;
- two concurrent debugger requests;
- local Zellij 0.44.3 and tmux 3.6a;
- explicit remote tmux;
- direct-host and same-container GDB.

See [development.md](development.md) for reproducible commands.
