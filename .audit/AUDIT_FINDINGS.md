# Audit Findings

## Full Audit 1 — 2026-07-22T22:59:40+08:00

### Big rocks

The three highest-impact things the tool is currently missing or getting wrong are:

1. **SSH master startup suppresses the diagnostic needed to recover from authentication and configuration failures.** Both master paths capture bounded stderr but pass OpenSSH `-q`; a failing regression proved the resulting error contains only `exit status 255`, not `Permission denied (publickey).` This violates the charter's actionable-failure principle and is tracked as PWB-001.
2. **Source builds can run with a known-vulnerable Go patch release despite the module's safe minimum.** The local Go 1.26.3 build reaches vulnerable `os.Root` operations in recovery code under GO-2026-4970 / CVE-2026-39822. CI and releases use Go 1.26.5, but direct `go build` accepts 1.26.0–1.26.4 because those versions are newer than the safe `go 1.25.12` module floor. This threatens descriptor-rooted recovery confinement and is tracked as PWB-002.
3. **Container cwd translation confuses a valid host path under `/work` with a container-native path.** Because translation checks the configured container workdir before the mounted host workspace, a host workspace such as `/workspaces/chal` maps to a nonexistent container path instead of `/work`. This breaks container commands for a supported absolute remote workspace root and is tracked as PWB-003.

### Security

- `gosec` completed without findings under the repository's explicit exclusions.
- `govulncheck` under Go 1.26.3 found one reachable standard-library vulnerability: GO-2026-4970 / CVE-2026-39822, fixed in Go 1.25.12 and Go 1.26.5. Reachable traces include `os.Root.Open`, `OpenFile`, `OpenRoot`, and `rootFS.ReadDir` from recovery operations.
- The same scan found four module advisories with no called vulnerable symbols; retained as open question PWB-Q001 rather than speculative dependency churn.
- High-risk paths use structural argv, bounded output, strict JSON/TOML decoding, private state directories, content-addressed agent verification, and descriptor-rooted recovery operations. No new injection, secret-in-repository, or unsafe-deserialization finding was reproduced in this pass.

### Correctness and robustness

- Baseline `make verify` failed because the pre-existing shared-master diagnostic edit left a brittle argument-count assertion matching `" -M"`; this is being reconciled as part of PWB-001.
- A new failing regression reproduced the loss of SSH startup stderr on the session-scoped master.
- Container cwd translation order has a concrete collision for host workspaces under `/work`; PWB-003 records the reproducer.
- Cancellation and bounded-output handling are broadly covered across subprocess, transport, runtime, doctor, recovery, and synchronization paths.

### CLI UX and documentation

- Root, `pb`, host, synchronization, recovery, terminal-provider, doctor, support, version, JSON, and completion surfaces are documented and represented in command help.
- README, CLI reference, architecture, security, installation, troubleshooting, and container-runtime documentation align on the local-macOS/remote-linux-amd64 model and explicit safety barriers.
- SSH startup failure detail is the most material UX gap found because it blocks user recovery from a complete inability to connect.

### Testing

- Package coverage sampled with `go test ./... -cover`; most trust-boundary packages are around 69–98%, while `internal/agent` is 37.2%. The percentage is recorded as PWB-Q002, not promoted without a reproduced user-visible failure.
- Fuzz targets exist for protocol decoding, strict configuration, recovery archives, shell markers, bounded output, synchronization JSON, and workspace slugs.
- Full race and cross-build verification remain required before each cycle commit.

### Performance

- No performance item filed: no profile or benchmark demonstrated a current hotspot.

### Architecture, dependencies, and portability

- Package boundaries separate CLI orchestration, transport, protocol, broker, synchronization, runtime, recovery, configuration, and filesystem safety.
- Dependencies are focused on Cobra, terminal UI/provider support, TOML, PTY, and Go system primitives; no new dependency is justified by this audit.
- CI covers macOS and Linux with fixed Go 1.25.12 and 1.26.5, plus race, fuzz-smoke, security, container, and release-snapshot jobs.
