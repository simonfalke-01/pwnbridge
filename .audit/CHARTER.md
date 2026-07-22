# Pwnbridge Charter

## Purpose

Pwnbridge makes a remote Linux amd64 pwn environment behave like a local workspace on macOS. It synchronizes challenge files safely, executes commands and interactive shells on the target architecture, and keeps debugger panes and generated artifacts integrated with the local terminal workflow.

## User

The primary user is a macOS security researcher or CTF player who edits locally but needs faithful Linux amd64 execution, pwntools, GDB, and optional container isolation without repeatedly copying files or managing remote paths.

## Principles

1. **Never execute stale or conflicted state.** Synchronization barriers must complete and validate health before execution; conflicts block instead of choosing a winner.
2. **Preserve user data and make recovery explicit.** Neither endpoint silently wins, cleanup preserves workspaces by default, and destructive operations require narrow confirmation and durable recovery evidence.
3. **Feel local with minimal setup.** Normal use is one command, ordinary argv and exit statuses are preserved, and diagnostics—not routine workflows—carry operational complexity.
4. **Reuse mature trust boundaries.** System OpenSSH, Mutagen, Mosh, and container engines remain authoritative behind structural argv and bounded interfaces; no custom public daemon is introduced.
5. **Fail loudly, safely, and actionably.** Errors, cancellation, protocol mismatches, unhealthy synchronization, and unsupported configurations must be explicit and recoverable.
6. **Keep configuration strict and portable.** Defaults are zero-config where possible; project configuration is small, validated, inspectable, and free of implicit shell evaluation.

## Scope Boundaries

- Pwnbridge is not a general remote-development IDE, file server, or replacement for SSH configuration.
- It does not edit SSH, shell, debugger, or editor dotfiles.
- It does not provide a publicly listening service or require a persistent Pwnbridge daemon.
- It does not silently resolve synchronization conflicts, automatically delete workspaces, or import `.gitignore` as a deletion policy.
- It targets a macOS client and Linux amd64 execution host; general multi-platform orchestration is outside scope.
- Containers are an optional execution boundary for pwn tooling, not a general container-management product or a claim that hostile same-account remote hosts are trusted.
