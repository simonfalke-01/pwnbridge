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
