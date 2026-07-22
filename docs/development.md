# Development and verification

## Toolchain

Pwnbridge's module language version is Go 1.25. CI runs patched Go 1.25.12 and
Go 1.26.5 on macOS and Ubuntu. The client is tested on
Darwin ARM64; the remote agent is a static Linux amd64 cross-build.

Do not build with Go 1.26.0 through 1.26.4. Those releases are affected by
CVE-2026-39822 in reachable `os.Root` operations; both Pwnbridge binaries fail
closed at startup when compiled by a known-affected toolchain.

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

Thirteen fuzz targets cover strict TOML, framed JSON protocol, PTY prompt
markers, bounded subprocess prefix/tail retention, Mutagen health JSON, ignore
parsing, workspace slug generation, bootstrap/event data, recovery archives,
diagnostic text, build metadata, and bounded Unicode wizard rendering. The
wizard target checks real no-color view width and selection invariants across
CJK, combining/joining, emoji, and RTL seeds, with a per-render deadline that
catches renderer loops. CI runs each target independently.

Security checks use pinned govulncheck and gosec versions. Gosec exclusions are
limited to categories that are architectural false positives here: structured
subprocess launch, caller-selected trusted state/config paths, cleanup-close
errors, 0700 directory/executable modes, and the Pwndbg checksum misclassified
as a credential. Broker-address taint and frame conversion are validated in
code and documented with narrow `#nosec` annotations.

## Unit and fake integration tests

Package tests include:

- strict config precedence/schema/value validation;
- bounded pathological TOML nesting, positioned/keyed decode errors, strict
  error wrapping, Unicode wizard widths, pipe/disabled input, and renderer
  deadline behavior;
- workspace identity, schema-one migration, bounded global lifecycle catalogs,
  safe host-retirement previews/confirmation, state, locks, descriptor-rooted recovery copies,
  deterministic archives, durable digest manifests, legacy inventory,
  context-cancelable proactive integrity checks, verified exclusive
  restoration, whole-archive retention/pruning, durable tombstone rollback and
  retry, mount/link containment, and hostile-stream rejection;
- descriptor-rooted local/remote conflict snapshots and control-safe unified
  previews;
- subprocess-level remote recovery streaming, durable acknowledgement, source
  change detection, strict result decoding, and bounded diagnostics;
- privacy-allowlisted support reports, narrow build-metadata grammar fuzzing,
  invalid-config partial output, hostile remote text rejection, local-only
  network exclusion, and forbidden-value sentinels across Markdown and JSON;
- Mutagen version/argv/health/conflict parsing with captured 0.18.1 fixtures;
- isolated Mutagen startup cancellation, long-path alias validation, private
  descriptor logging, special-file rejection, oversized-log rotation, 16 MiB
  structured-state acceptance, and bounded final diagnostics;
- read-only partial-result doctor collection, independent timeout/cancellation,
  recipe parity, configured runtime/transport checks, control-safe bounded
  reports, write failure, and small-protocol SSH output floods;
- transactional checked host registration, duplicate/replace/default semantics,
  project-config independence, installable-versus-blocked plans, required and
  optional forwarding, serialized fresh-read global commits, no-write failure,
  cancellation, and forbidden remote mutation transcripts;
- monotonic deterministic-archive byte/item progress, TTY-only throttled
  recovery status, partial cancellation reports, checked/total JSON, maximum
  snapshot responses, and bounded SSH management/forwarding/SCP floods;
- OpenSSH/scp and Mosh argv, bounded shared-master reuse/explicit shutdown,
  exact forward cancellation, fused verified agent preparation, stream-local
  and TCP/socat fallback;
- PTY marker and bracketed-paste chunk boundaries, paste redisplay authority,
  multiline paste submission barriers, and terminal restoration;
- broker authentication, shell barriers, rate/pane limits, lifecycle, and runtime authority;
- fake Zellij/tmux/WezTerm/Kitty/iTerm/Terminal/custom provider lifecycle,
  exact inventory/protocol limits, output floods, and final diagnostic tails;
- Docker/Podman command construction, same-runtime cwd/environment, terminal
  pull streaming, non-terminal quiet mode, signal reaping, and bounded replies;
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
| `lima.sh` | checked host registration, real ret2win, x86-64, artifacts, conflict previews/resolution/recovery/pruning/spaces, root deletion |
| `lima-shell.sh` | warm-master reuse/shutdown, SSH save-before-Enter, single-render bracketed paste, prompt artifacts, Ctrl-C/Z/D, readline, resize |
| `lima-mosh.sh` | explicit roaming Mosh, no exit banner, remote pre/post barriers, artifacts, resize |
| `lima-disconnect.sh` | forced SSH-master loss, terminal restoration, reconnect, preserved data |
| `lima-gdb.sh` | debug, attach, API, concurrent panes, selectable host provider |
| `lima-gdb-tui.sh` | real GDB TUI PTY and 30x90 to 45x120 resize propagation |
| `lima-pwntools-dev.sh` | pinned current pwntools 5-dev behavior |
| `lima-pwndbg.sh` | isolated optional Pwndbg executable |
| `lima-container.sh` | basic Podman runtime, quiet non-terminal setup, and artifact sync |
| `lima-container-gdb.sh` | debug/attach/API in one container namespace |
| `lima-remote-mux.sh` | explicit visible remote tmux pane |
| `lima-no-forward.sh` | ordinary fallback plus remote-mux GDB when reverse forwarding is prohibited |
| `lima-stop.sh` | publication-readiness race, live-process signal, deterministic exit 130, final flush/pause |

The full container GDB test expects an image tagged
`localhost/pwnbridge-pwn:e2e` on the VM. Build it from the supplied Dockerfile
with Podman before running the aggregate target.

The Mosh case requires `mosh-server` in the guest and local `mosh`/`socat`.
When Lima uses QEMU user networking, the script temporarily forwards UDP 60000
through the VM's private QMP socket and removes the forward during cleanup.

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
three completions, checksums, and archive SBOMs. Go outputs use `-trimpath` and
fixed file mtimes; archive entries use the same non-zero epoch so even a local
checkout without a configured Git remote produces byte-identical tarballs.
Tagged builds still embed their real version, commit, and date through ldflags.

The release workflow creates draft GitHub releases and attestations. A separate
workflow publishes an amd64 container image with BuildKit provenance, SBOM, and
registry attestation.

## Code conventions

- Prefer standard library and small dependencies.
- Keep OpenSSH, Mosh, and Mutagen behind narrow adapters; do not embed them.
- Represent commands as argv until a remote fixed housekeeping shell is
  unavoidable, then single-quote every variable path.
- Make every data-loss decision explicit.
- Preserve unrelated user files and dirty worktrees.
- Add a fake-executable test for every provider/transport argv change.
- Add an amd64 end-to-end case for changes to PTY, broker, runtime, or sync
  ordering.
- Keep client/agent/provider/config protocols independently versioned.
- Upgrade the coordinated Bubble Tea/Bubbles/Lip Gloss/x-ansi stack together;
  review upstream renderer behavior, transitive graph, Unicode fuzzing, and
  Darwin package size before accepting it.

## Repository layout

```text
cmd/                    client and Linux agent entrypoints
internal/cli/           orchestration and public commands
internal/config/        strict typed TOML and precedence
internal/workspace/     identity, locks, state, bindings
internal/syncer/        Mutagen 0.18.1 adapter and health model
internal/transport/     OpenSSH control/forwarding, Mosh PTY, agent deployment
internal/shell/         marker parser and PTY proxy
internal/broker/        authenticated debugger lifecycle broker
internal/terminal/      host provider implementations
internal/runtime/       host and Docker/Podman adapters
internal/bootstrap/     typed recipes, inventory, distro adapters, planner/executor
internal/bootstrap/ui/  client-only inline Bubble Tea v2 wizard
internal/agent/         Linux execution, wrapper, pane, structured protocol
packaging/              container, Homebrew, and release helpers
test/e2e/               real amd64 acceptance scenarios
```
