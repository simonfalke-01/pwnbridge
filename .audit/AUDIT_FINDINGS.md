# Audit Findings

## Full Audit 1 — 2026-07-22T22:59:40+08:00

### Big rocks

The three highest-impact things the tool is currently missing or getting wrong are:

1. **SSH master startup suppresses the diagnostic needed to recover from authentication and configuration failures.** Both master paths capture bounded stderr but pass OpenSSH `-q`; a failing regression proved the resulting error contains only `exit status 255`, not `Permission denied (publickey).` This violates the charter's actionable-failure principle and is tracked as PWB-001.
2. **Source builds can run with a known-vulnerable Go patch release despite the module's safe minimum.** The local Go 1.26.3 build reaches vulnerable `os.Root` operations in recovery code under GO-2026-4970 / CVE-2026-39822. CI and releases use Go 1.26.5, but direct `go build` accepts 1.26.0–1.26.4 because those versions are newer than the safe `go 1.25.12` module floor. This threatens descriptor-rooted recovery confinement and is tracked as PWB-002.
3. **Container cwd translation confuses a valid host path under `/work` with a container-native path.** Because translation checks the configured container workdir before the mounted host workspace, a host workspace such as `/work/chal` maps to a nonexistent container path instead of `/work`. This breaks container commands for a supported absolute remote workspace root and is tracked as PWB-003.

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

## Full Audit 2 — 2026-07-22T23:12:12+08:00

### Big rocks

The three highest-impact things the tool is currently missing or getting wrong are:

1. **Recipe export silently overwrites an existing output file.** `config bootstrap export --output FILE` calls the replacing `fsutil.AtomicWrite` primitive directly, with no confirmation or `--force`. A user can lose an edited recipe simply by repeating an export. This violates the charter's no-silent-data-loss rule and is the directly reproducible half of PWB-004.
2. **`pwnbridge init` does not enforce its non-destructive promise atomically.** It checks `.pwnbridge.toml` and `.pwnbridgeignore` before calling a rename-based replacement primitive. A file created by an editor or concurrent generator after the check is silently replaced. The same exclusive atomic-create primitive needed by export closes this TOCTOU window under PWB-004.
3. **The real remote execution stack was not end-to-end reverified in this environment.** Unit/fake integration, race, Darwin/Linux cross-build, security, and all fuzz-smoke targets are green, but no configured Lima amd64 VM/SSH file was available. This is recorded as PWB-Q003 rather than pretending an unevidenced code change can replace external acceptance testing.

### Security

- `make security` is green under Go 1.26.5 after PWB-002; no reachable dependency or standard-library advisory remains in the supported verification toolchain.
- Re-reviewed broker authentication/connection bounds, structural provider commands, remote agent quoting/deployment, descriptor-rooted snapshots/recovery, private state catalogs, and strict protocol/config decoders. No new reproducible injection, traversal, unsafe deserialization, or privilege-boundary defect was found.
- Known same-account remote compromise and same-container processes remain explicit scope boundaries, not defects that can be fixed by cosmetic hardening.

### Correctness and robustness

- `config bootstrap export` has a direct replacing write and no overwrite opt-in; PWB-004 will begin with a failing preservation test.
- `init`'s pre-check plus replace sequence has the same structural no-overwrite gap; a shared exclusive create primitive is required instead of another path-based pre-check.
- Exit-code precedence, cancellation, container cleanup, session leases, remote recovery acknowledgement, and provider lifecycle were re-read. No additional user-visible failure was reproduced.

### CLI UX and documentation

- CLI help and reference remain complete for daily, host, sync/recovery, runtime, support, provider, bootstrap-recipe, and version commands.
- Export's current silent replacement is inconsistent with the tool's explicit confirmation posture elsewhere and is the leading CLI/data-safety defect.

### Testing and tooling

- All 13 five-second fuzz-smoke targets passed, including strict TOML, protocol frames, recovery archives, diagnostics, bounded output, synchronization JSON, ignore parsing, and workspace slugging.
- `actionlint` passed. ShellCheck reported only SC2012 for `ls -di` on a fixed private control-socket path in one E2E assertion; filed as PWB-J001, not promoted.
- Real Lima E2E remains PWB-Q003 because the required external VM configuration is unavailable.

### Performance

- No performance work filed: no profile or before/after benchmark demonstrated a hotspot.

### Architecture, dependencies, and portability

- The repeated need for create-only durable output is a real missing filesystem capability; solving it once in `fsutil` avoids separate TOCTOU-prone CLI checks.
- No new dependency is required. Same-directory temporary-file linking can provide portable atomic no-replace semantics on the supported macOS client filesystems.
