# Audit Backlog

## IN PROGRESS

- [PWB-004] [HIGH] [DATA SAFETY] Make create-only CLI outputs atomically refuse overwrite. `config bootstrap export --output` currently replaces an existing file without warning, and `init` separates its existence check from a replacing rename; both can destroy user-created content despite the charter's no-silent-data-loss rule. Evidence: direct `fsutil.AtomicWrite` call sites in `internal/cli/root.go`; failing CLI overwrite regression required before implementation.

## SUBSTANTIVE

- None.

## JANITORIAL

- [PWB-001] [HIGH] [ROBUSTNESS] Preserve actionable OpenSSH authentication/configuration diagnostics when either control-master startup path fails. Shipped in `c10f12dc5713e8c134e4634041674d70760ec2da` with `TestControlMasterReportsSSHStartupFailure` and `TestSharedControlMasterReportsSSHStartupFailure`.
- [PWB-002] [HIGH] [SECURITY] Refuse source-built binaries compiled by Go toolchain releases affected by CVE-2026-39822. Shipped in `a087efe4b667cacbd430a2e5ac7b1a7d0ea69a1d` with affected/fixed toolchain matrix tests and a real Go 1.26.3 startup refusal.
- [PWB-003] [MEDIUM] [CORRECTNESS] Translate host workspace paths before treating `/work/...` as an already-container-native cwd. Shipped in `5b4484dde9b6ebf3a94131e9816f6ce28e0ddb46` with `TestContainerCommandTranslatesHostWorkspaceUnderContainerWorkdirPrefix` while retaining the container-native debugger cwd regression.

## DONE

- [PWB-J001] [LOW] [TESTING] Replace or narrowly suppress ShellCheck SC2012 in `test/e2e/lima-shell.sh` fixed control-socket inode checks; informational only and not a standalone cycle while substantive work exists.

## OPEN QUESTIONS

- [PWB-Q001] [SECURITY] Four dependency advisories are present in required modules but `govulncheck` found no reachable symbols. Re-evaluate when dependency updates or new call paths land; no substantive change is justified by current evidence.
- [PWB-Q002] [TESTING] The remote agent package has 37.2% statement coverage, but coverage percentage alone does not establish a user-visible defect. Add only targeted tests that reproduce a substantive failure.
- [PWB-Q003] [TESTING] Full audit 2 could not rerun the real Linux amd64 Lima suite because no configured `PWNBRIDGE_E2E_SSH_CONFIG`/VM was available. Keep the fake/unit/race/cross-build evidence green and rerun Lima when the external environment exists.
