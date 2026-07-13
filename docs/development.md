# Development and verification

## Toolchain

Pwnbridge's module language version is Go 1.25. CI runs the current supported
Go 1.25 and 1.26 patch lines on macOS and Ubuntu. The client is tested on
Darwin ARM64; the remote agent is a static Linux amd64 cross-build.

```console
make verify
make test-race
```

`verify` checks formatting, module integrity, unit tests, vet, Darwin
ARM64/AMD64 clients, and Linux amd64 agent builds.

## Fuzz and security

```console
make fuzz-smoke FUZZTIME=15s
make security
```

Fuzz targets cover strict TOML, framed JSON protocol, PTY prompt markers, and
Mutagen health JSON. CI runs each target independently.

Security checks use pinned govulncheck and gosec versions. Gosec exclusions are
limited to categories that are architectural false positives here: structured
subprocess launch, caller-selected trusted state/config paths, cleanup-close
errors, 0700 directory/executable modes, and the Pwndbg checksum misclassified
as a credential. Broker-address taint and frame conversion are validated in
code and documented with narrow `#nosec` annotations.

## Unit and fake integration tests

Package tests include:

- strict config precedence/schema/value validation;
- workspace identity, state, locks, and safe recovery copies;
- Mutagen version/argv/health/conflict parsing with captured 0.18.1 fixtures;
- OpenSSH/scp argv, agent deployment, stream-local and TCP/socat fallback;
- PTY marker chunk boundaries and terminal restoration;
- broker authentication, rate/pane limits, lifecycle, and runtime authority;
- fake Zellij/tmux/WezTerm/Kitty/iTerm/Terminal/custom provider lifecycle;
- Docker/Podman command construction and same-runtime cwd/environment;
- hostile IDs, path escapes, frame caps, and broker-address validation.

## Lima end-to-end environment

The real suite expects a running native amd64 Ubuntu Lima VM and an SSH config
file containing alias `lima-pwn`:

```console
export PWNBRIDGE_E2E_SSH_CONFIG="$HOME/.lima/pwn/ssh.config"
make build
make e2e-lima
```

The wrapper executables in `test/e2e/bin` add that SSH config without changing
production transport behavior.

Individual scenarios:

| Script | Coverage |
|---|---|
| `lima.sh` | real ret2win, x86-64, artifacts, conflicts/spaces, root deletion |
| `lima-shell.sh` | save-before-Enter, prompt artifacts, Ctrl-C/Z/D, readline, resize |
| `lima-gdb.sh` | debug, attach, API, concurrent panes, selectable host provider |
| `lima-pwntools-dev.sh` | pinned current pwntools 5-dev behavior |
| `lima-pwndbg.sh` | isolated optional Pwndbg executable |
| `lima-container.sh` | basic Podman runtime and artifact sync |
| `lima-container-gdb.sh` | debug/attach/API in one container namespace |
| `lima-remote-mux.sh` | explicit visible remote tmux pane |
| `lima-stop.sh` | live-process signal, exit 130, final flush/pause |

The full container GDB test expects an image tagged
`localhost/pwnbridge-pwn:e2e` on the VM. Build it from the supplied Dockerfile
with Podman before running the aggregate target.

Run the GDB suite through real host Zellij from a Zellij pane:

```console
PWNBRIDGE_E2E_PROVIDER=zellij test/e2e/lima-gdb.sh
```

Run it from a tmux pane with `PWNBRIDGE_E2E_PROVIDER=tmux`. The custom `e2e`
provider is the deterministic headless default and records pane helper output.

## Release verification

GoReleaser is pinned in workflows and Makefile:

```console
make snapshot
```

A snapshot must contain two Darwin client archives, the Linux amd64 agent
archive, the Linux agent adjacent inside each client archive, README/PLAN/docs,
three completions, checksums, and archive SBOMs. Build timestamps use the commit
timestamp and Go builds use `-trimpath` with version/commit/date ldflags.

The release workflow creates draft GitHub releases and attestations. A separate
workflow publishes an amd64 container image with BuildKit provenance, SBOM, and
registry attestation.

## Code conventions

- Prefer standard library and small dependencies.
- Keep OpenSSH and Mutagen behind narrow adapters; do not embed them.
- Represent commands as argv until a remote fixed housekeeping shell is
  unavoidable, then single-quote every variable path.
- Make every data-loss decision explicit.
- Preserve unrelated user files and dirty worktrees.
- Add a fake-executable test for every provider/transport argv change.
- Add an amd64 end-to-end case for changes to PTY, broker, runtime, or sync
  ordering.
- Keep client/agent/provider/config protocols independently versioned.

## Repository layout

```text
cmd/                    client and Linux agent entrypoints
internal/cli/           orchestration and public commands
internal/config/        strict typed TOML and precedence
internal/workspace/     identity, locks, state, bindings
internal/syncer/        Mutagen 0.18.1 adapter and health model
internal/transport/     OpenSSH master/forwarding/agent deployment
internal/shell/         marker parser and PTY proxy
internal/broker/        authenticated debugger lifecycle broker
internal/terminal/      host provider implementations
internal/runtime/       host and Docker/Podman adapters
internal/agent/         Linux execution, wrapper, pane, bootstrap probes
packaging/              container, Homebrew, and release helpers
test/e2e/               real amd64 acceptance scenarios
```
