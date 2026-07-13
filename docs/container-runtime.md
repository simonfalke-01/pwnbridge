# Container runtime

Container runtime is optional isolation for hostile challenge code. The Mac
workflow and synchronization model remain unchanged; execution is one level
deeper on the remote amd64 host.

## Image

The supplied `packaging/container/Dockerfile` uses Ubuntu 24.04 and includes
Bash, build tools, binutils, GDB/gdbserver, patchelf, checksec, Python, pinned
pwntools 4.15.0, tracing tools, socat, netcat, and libc debug symbols.

Build on the remote amd64 host or with an amd64 build platform:

```console
docker build --platform linux/amd64 \
  -t ghcr.io/OWNER/pwnbridge-pwn:VERSION packaging/container
docker push ghcr.io/OWNER/pwnbridge-pwn:VERSION
docker inspect --format '{{index .RepoDigests 0}}' \
  ghcr.io/OWNER/pwnbridge-pwn:VERSION
```

Use the resulting digest, not a mutable tag, in portable configuration.

## Configuration

```toml
[runtime]
kind = "container"

[runtime.container]
engine = "auto"
image = "ghcr.io/OWNER/pwnbridge-pwn@sha256:..."
workdir = "/work"
network = "bridge"
```

`auto` prefers Podman, then Docker. An explicit engine fails clearly when its
executable is missing. Valid networking is passed as one validated engine
argument; choose `none` for offline challenges when possible.

## Lifecycle

Each active Pwnbridge session creates one named container:

```text
pwnbridge-<session-id>
```

It is labeled with the session and workspace IDs. The adapter reuses it while
running, removes a dead same-name container before recreation, and removes it
during session cleanup. `pwnbridge runtime reset` stops active clients and
removes all Pwnbridge-labeled containers for the current workspace without
deleting files.

## Mounts and identity

The adapter mounts:

```text
remote synchronized workspace  → /work
owned session directory        → /run/pwnbridge
agent wrapper directory        → /run/pwnbridge/bin (read-only)
```

It runs with the remote UID/GID; Podman additionally uses `--userns keep-id`.
HOME is an isolated `/tmp/pwnbridge-home`, created inside the container. The
remote home, SSH directory, and container-engine socket are not mounted.

## Debugging

The container gets `SYS_PTRACE` and `seccomp=unconfined`, the standard minimal
adjustments required for GDB on typical Docker/Podman systems. `process()`,
gdbserver, GDB, debugger scripts, and the inferior all execute through the same
container ID and PID namespace.

The Mac session record is authoritative for the runtime. Container-writable
manifest/runtime JSON cannot redirect a pane to a host process, another
container, image, workspace, or engine.

## Broker networking

Reverse stream-local forwarding produces a Unix socket in the mounted session
directory, visible as `/run/pwnbridge/broker.sock`. If the SSH server rejects
stream-local forwarding, Pwnbridge obtains a remote loopback TCP port and uses
remote `socat` to expose it as that same Unix socket. The bootstrap profile
installs socat.

If neither forward is possible, host/container commands still work but host
provider debugger panes fail before execution with an actionable error.

## Security tradeoffs

Container mode reduces access to the remote account's home and tools, but:

- it shares the remote kernel;
- ptrace capability is intentionally present inside the container;
- the synchronized workspace is writable;
- bridge networking permits outbound traffic;
- Docker group membership can be equivalent to remote root outside this
  container;
- engine and kernel vulnerabilities remain in scope.

Prefer rootless Podman, a dedicated remote account, `network = "none"` when
possible, digest-pinned images, and a disposable remote host for genuinely
hostile binaries.

## Custom images

A compatible image needs:

- Linux amd64 userland;
- `sh`, Bash, and `sleep`;
- Python plus the desired pwntools version;
- GDB and gdbserver;
- the dynamic loader/libraries required by the challenge;
- writable `/tmp` for the isolated home.

Do not bake personal SSH keys, challenge flags, or registry credentials into
the image. Pwnbridge supplies the agent wrapper through a read-only session
mount.
