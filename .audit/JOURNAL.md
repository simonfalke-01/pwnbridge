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

## Cycle 3 — 2026-07-22T23:07:39+08:00
- Item:        [PWB-003] Correct container cwd translation for host workspaces under /work       Tier: MEDIUM   Dimension: CORRECTNESS
- Why it mattered: Users with a supported absolute remote workspace beneath `/work` received a nonexistent container cwd, so every container command from that workspace failed before execution.
- Evidence:    `TestContainerCommandTranslatesHostWorkspaceUnderContainerWorkdirPrefix` failed before the fix with `-w /work/chal/sub` instead of the mounted `/work/sub`.
- Change:      Prioritized translation through the authoritative host workspace mount before recognizing already-container-native workdir paths; retained the existing debugger cwd behavior outside that mount.
- Verification: build=pass tests=pass lint=pass cli-run=pass  regression-test=`TestContainerCommandTranslatesHostWorkspaceUnderContainerWorkdirPrefix`, `TestContainerCommandPreservesContainerCwd`
- Senior-review self-check: worth doing because an explicitly supported remote workspace root could make the entire optional container runtime unusable, and the fix resolves the namespace ambiguity with the authoritative mount mapping.
- Commit:      5b4484dde9b6ebf3a94131e9816f6ce28e0ddb46 "fix(runtime): map host workspace cwd before container paths"     Pushed: origin/main @ 5b4484dde9b6ebf3a94131e9816f6ce28e0ddb46

## Cycle 4 — 2026-07-22T23:16:46+08:00
- Item:        [PWB-004] Make create-only CLI outputs atomically refuse overwrite       Tier: HIGH   Dimension: DATA SAFETY
- Why it mattered: Repeating a recipe export silently destroyed the existing file, and `init` could replace content created between its path check and commit despite promising non-destructive creation.
- Evidence:    `TestBootstrapRecipeCRUD` failed before the fix because a second export returned success and replaced `valuable local edit`; the deterministic `TestAtomicCreateRefusesConcurrentTargetWithoutChangingIt` covers the check/commit race.
- Change:      Added durable same-directory exclusive publication, migrated init templates and recipe exports, preserved explicit existing-file errors, documented no-overwrite behavior, and tested successful content/mode publication plus racing and ordinary existing targets.
- Verification: build=pass tests=pass lint=pass cli-run=pass  regression-test=`TestBootstrapRecipeCRUD`, `TestAtomicCreateRefusesConcurrentTargetWithoutChangingIt`, `TestAtomicCreatePublishesCompleteFile`
- Senior-review self-check: worth doing because silent replacement contradicts the project's central data-preservation guarantee, and the shared primitive removes the TOCTOU class instead of patching one call site superficially.
- Commit:      873c00ca46a5c8e772667999459f5d2f21b0ed67 "fix(cli): refuse overwriting create-only outputs"     Pushed: origin/main @ 873c00ca46a5c8e772667999459f5d2f21b0ed67

## Cycle 5 — 2026-07-22T23:20:42+08:00
- Item:        [PWB-005] Bound broker health-check I/O so lifecycle commands cannot hang       Tier: HIGH   Dimension: ROBUSTNESS
- Why it mattered: A live but wedged local broker could make session startup and stop/cleanup discovery wait forever with no diagnostic or recovery path.
- Evidence:    `TestPingTimesOutWhenBrokerAcceptsWithoutResponding` exceeded two seconds before the fix even though the documented connection budget was one second.
- Change:      Applied the one-second broker ping budget as a connection-wide deadline covering authenticated encode/decode I/O, with a nonresponding listener regression and retained authentication/spoof checks.
- Verification: build=pass tests=pass lint=pass cli-run=pass  regression-test=`TestPingTimesOutWhenBrokerAcceptsWithoutResponding`, `TestBrokerAuthenticationAndPing`, `TestPingRejectsSpoofedResponseIdentity`
- Senior-review self-check: worth doing because an indefinite hang in the lifecycle discovery path blocks both new work and cleanup, while a bounded health error lets the user identify and terminate the wedged owner process.
- Commit:      ecc0c58fa545578a52beb0c9f9038dca49ff2df8 "fix(broker): bound session health-check I/O"     Pushed: origin/main @ ecc0c58fa545578a52beb0c9f9038dca49ff2df8
