# Audit Backlog

## IN PROGRESS

- [PWB-002] [HIGH] [SECURITY] Refuse source-built binaries compiled by Go toolchain releases affected by CVE-2026-39822. Evidence: `make security` under local Go 1.26.3 reports reachable GO-2026-4970 traces in recovery root operations; `go.mod` permits fixed Go 1.25.12 but cannot exclude the later vulnerable 1.26.0–1.26.4 range.

## SUBSTANTIVE

- [PWB-003] [MEDIUM] [CORRECTNESS] Translate host workspace paths before treating `/work/...` as an already-container-native cwd. Evidence: code-level reproducer is `RuntimeSpec{Workspace: "/workspaces/chal", Workdir: "/work"}` with host cwd `/workspaces/chal/sub`; current translation incorrectly returns `/workspaces/chal/sub` instead of `/work/sub`, so container execution fails when the remote workspace root is under `/work`.

## JANITORIAL

- [PWB-001] [HIGH] [ROBUSTNESS] Preserve actionable OpenSSH authentication/configuration diagnostics when either control-master startup path fails. Shipped in `c10f12dc5713e8c134e4634041674d70760ec2da` with `TestControlMasterReportsSSHStartupFailure` and `TestSharedControlMasterReportsSSHStartupFailure`.

## DONE

- None.

## OPEN QUESTIONS

- [PWB-Q001] [SECURITY] Four dependency advisories are present in required modules but `govulncheck` found no reachable symbols. Re-evaluate when dependency updates or new call paths land; no substantive change is justified by current evidence.
- [PWB-Q002] [TESTING] The remote agent package has 37.2% statement coverage, but coverage percentage alone does not establish a user-visible defect. Add only targeted tests that reproduce a substantive failure.
