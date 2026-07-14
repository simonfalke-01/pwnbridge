# Paste rendering and repeated-command latency plan

Status: implemented and verified

## Problem statement

Two normal workflows currently violate Pwnbridge's "feel local" goal:

1. Readline bracketed paste can appear twice in the predictive inline shell,
   even though the remote shell receives the bytes only once.
2. Every `pb` invocation constructs and destroys the complete SSH, Mutagen,
   agent, and debugger control plane. Correct barriers are required for every
   command, but repeated transport handshakes and discovery probes are not.

The solution must preserve argv fidelity, conflict blocking, save-before-run,
artifact-before-return, host-key policy, agent integrity verification, debugger
support, concurrent invocations, and explicit `stop` semantics.

## Research and architectural decision

Bracketed-paste terminals send `ESC [ 200 ~`, the pasted bytes, then
`ESC [ 201 ~`. GNU Readline consumes that region as one insertion and may
redisplay it with active-region terminal attributes. Pwnbridge's current input
predictor strips the delimiters, predicts the printable body, then abandons
echo reconciliation when Readline's authoritative redisplay begins with a
control sequence. Both the prediction and redisplay consequently remain on
screen. Pasted regions should therefore be remote-authoritative; ordinary
typing remains predicted.

OpenSSH already provides the lifecycle primitive needed for repeated commands:
`ControlMaster` shares one authenticated connection and a finite
`ControlPersist` interval backgrounds it only while idle. This is preferable to
a custom local daemon, a persistent remote agent, shell integration, or a
long-lived remote command runner. A short-lived, owner-private OpenSSH master
retains the user's normal SSH configuration and automatically expires.

Mutagen's daemon and synchronization session are already persistent. The hot
path does not need to repeat version gating, daemon startup, readiness polling,
and an extra status query before the real barrier. It does still need to resume,
flush, and inspect the exact session's complete health before execution. A
missing stored session may be recreated; a conflict or unhealthy session must
never be replaced or bypassed.

The deployed agent remains content-addressed, but the existing hot path spends
three SSH channels on a basic probe, digest check, and agent probe. A single
fixed remote preflight can verify the expected SHA-256 and execute that exact
agent's structured probe. Cache absence falls back to the existing atomic
deployment path. The preflight is independent of Mutagen's barrier and can run
beside it after the shared SSH connection is ready.

Primary references:

- [OpenSSH client configuration: ControlMaster, ControlPath, and ControlPersist](https://man.openbsd.org/ssh_config#ControlMaster)
- [OpenSSH multiplex control commands and remote forwarding](https://man.openbsd.org/ssh#O)
- [XTerm bracketed-paste control sequences](https://www.invisible-island.net/xterm/ctlseqs/ctlseqs.html#h2-Bracketed-Paste-Mode)
- [GNU Readline bracketed-paste behavior](https://www.gnu.org/software/bash/manual/html_node/Commands-For-Text.html)
- [Mutagen daemon lifecycle](https://mutagen.io/documentation/introduction/daemon/)
- [Mutagen synchronization sessions and flush](https://mutagen.io/documentation/synchronization)

## Rejected approaches

- Do not disable local prediction wholesale: ordinary high-latency typing is a
  deliberate product feature, and bracketed paste has an exact protocol
  boundary that can be handled narrowly.
- Do not teach output reconciliation to discard arbitrary ANSI redraws: that
  risks hiding legitimate program output and contradicts the remote-authority
  rule on mismatches.
- Do not skip, debounce, or asynchronously complete execution barriers: that
  would permit stale input or return before remote artifacts are local.
- Do not add a persistent Pwnbridge client/agent daemon or command server: it
  expands protocol, authentication, upgrade, crash-recovery, and process-
  ownership surfaces merely to duplicate OpenSSH multiplexing.
- Do not trust a cached remote agent without re-verifying its digest: the
  remote cache is user-writable and integrity verification is an existing
  security invariant.
- Do not reuse debugger forwards without a live owning broker: broker tokens,
  local sockets, session records, and forwards remain per invocation.

## Implementation sequence

1. Add a streaming bracketed-paste state machine to the echo predictor. It
   must recognize delimiters across arbitrary input chunks, avoid predicting
   every byte inside the region, resume prediction immediately afterward, and
   preserve all input bytes sent to the PTY.
2. Add predictor regression tests for a Readline styled redisplay, split
   delimiters, multiline paste, and ordinary input immediately before/after a
   paste.
3. Add a bounded shared-control-master API in `internal/transport`:
   - stable identity-keyed socket in an owner-private cache directory;
   - serialized startup and stale-socket handling;
   - `ControlPersist=2m`, keepalives, no agent/X11 forwarding, and the existing
     user's SSH/host-key configuration;
   - exact per-session reverse-forward tracking and cancellation;
   - explicit master shutdown for `stop`/`clean`;
   - unchanged ephemeral masters for doctor and recovery operations.
4. Switch managed shell/run sessions to the shared master. Keep session IDs,
   broker tokens, records, leases, runtime directories, remote cleanup, and
   final barriers per invocation. Derive the master identity from the local
   installation, workspace/host, destination, and SSH executable so unrelated
   targets cannot share a socket.
5. Add a Mutagen `Prepare` operation. On a matching stored fingerprint it must
   perform the existing resume/flush/full-health barrier directly. Only a
   definite missing-session result may clear state and enter the full creation
   path. Configuration changes retain the existing safe barrier-before-replace
   behavior.
6. Fuse cached-agent digest verification and structured probing into one fixed
   SSH preflight, with bounded output and the existing deployment fallback.
   Run agent preparation concurrently with workspace synchronization only after
   the authenticated master is ready; always join/cancel both branches.
7. Update architecture, security, CLI, troubleshooting/development guidance,
   and the canonical plan to describe bounded warm transport and paste
   authority accurately.
8. Verify with focused package tests, race tests for touched packages, the full
   Go test suite, `go vet`, formatting, cross-builds, and the shell E2E tests
   available in this environment. Review the final diff against every item in
   this document and mark this plan complete.

## Acceptance criteria

- A bracketed paste is displayed once and delivered byte-for-byte once.
- Ordinary typed prompt input remains locally predicted.
- The first `pb` command creates a normal authenticated connection; subsequent
  commands inside the two-minute idle window reuse it without reauthentication.
- Concurrent `pb` commands cannot race master creation or cancel each other's
  debugger forwards.
- Each command still blocks on a pre-execution full-health barrier and a final
  artifact-return barrier.
- Agent SHA-256 and protocol/platform validation still occur on every command.
- `pwnbridge stop` and `clean` close the warm connection; otherwise OpenSSH
  expires it after the bounded idle interval.
- No Pwnbridge daemon, persistent remote agent, public listener, new config
  schema, or user SSH configuration modification is introduced.

## Verification record

Completed on 2026-07-14 with Go 1.25.12:

- `make verify` passed formatting, module verification, the full test suite,
  `go vet`, Darwin ARM64/AMD64 client builds, and the Linux AMD64 agent build.
- Race-enabled tests passed for `internal/shell`, `internal/syncer`,
  `internal/transport`, and `internal/cli`.
- Fake OpenSSH integration verifies concurrent single-master startup, the
  two-minute persist option, explicit shutdown, and exact forward cancellation.
- PTY/controller tests verify split paste delimiters, one authoritative
  Readline redisplay, unchanged bytes, multiline paste, and one final barrier.
- Mutagen tests verify the three-operation hot path, missing-session recovery,
  and fail-closed unhealthy state even when a conflict path says "not found".
- The Lima shell scenario now checks real control-socket reuse/removal and
  exact-once paste rendering. It requires the documented macOS/Lima environment
  and was not runnable in this Linux workspace, which has neither that guest nor
  `expect`; `sh -n test/e2e/lima-shell.sh` passed here.
