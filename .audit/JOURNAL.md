# Audit Journal

Append-only record of completed substantive cycles.

## Cycle 1 — 2026-07-22T23:01:37+08:00
- Item:        [PWB-001] Preserve actionable OpenSSH diagnostics when control-master startup fails       Tier: HIGH   Dimension: ROBUSTNESS
- Why it mattered: Users whose SSH authentication or configuration fails received only exit status 255, hiding the diagnostic required to restore all remote workflows.
- Evidence:    `TestControlMasterReportsSSHStartupFailure` failed before the fix with `SSH control master exited during startup: exit status 255` instead of retaining `Permission denied (publickey).`
- Change:      Removed OpenSSH quiet mode only from both bounded master-startup commands, retained it for expected probes/shutdown, added regressions for both startup paths, and made the concurrent-start assertion independent of a leading flag.
- Verification: build=pass tests=pass lint=pass cli-run=pass  regression-test=`TestControlMasterReportsSSHStartupFailure`, `TestSharedControlMasterReportsSSHStartupFailure`
- Senior-review self-check: worth doing because SSH startup failure disables every remote workflow, and exposing the bounded root-cause diagnostic turns an opaque failure into an actionable one without weakening transport safety.
- Commit:      c10f12dc5713e8c134e4634041674d70760ec2da "fix(transport): retain SSH master startup diagnostics"     Pushed: origin/main @ c10f12dc5713e8c134e4634041674d70760ec2da

## Cycle 2 — 2026-07-22T23:05:06+08:00
- Item:        [PWB-002] Refuse binaries built with Go releases affected by CVE-2026-39822       Tier: HIGH   Dimension: SECURITY
- Why it mattered: A source build made with Go 1.26.0–1.26.4 could execute reachable vulnerable `os.Root` code and escape recovery's intended filesystem boundary.
- Evidence:    `make security` under Go 1.26.3 reported GO-2026-4970 traces from recovery operations; after the fix, a real `GOTOOLCHAIN=local go run ./cmd/pwnbridge --version` build using Go 1.26.3 exits with explicit CVE guidance.
- Change:      Added a shared official-toolchain range check at the start of both binaries, retained the fixed Go 1.25.12 floor, covered affected and fixed releases including 1.27 prereleases, and documented patch-level source-build requirements.
- Verification: build=pass tests=pass lint=pass cli-run=pass  regression-test=`TestCheckToolchainRejectsCVE202639822`, `TestCheckToolchainAcceptsFixedReleases`
- Senior-review self-check: worth doing because the vulnerable standard-library calls sit directly in the data-recovery confinement boundary, and a module minimum alone cannot reject the later affected Go 1.26 patch range.
- Commit:      a087efe4b667cacbd430a2e5ac7b1a7d0ea69a1d "security(toolchain): reject CVE-2026-39822 builds"     Pushed: origin/main @ a087efe4b667cacbd430a2e5ac7b1a7d0ea69a1d
