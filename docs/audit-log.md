# Continuous audit log

This append-only log records maintenance cycles performed after the acceptance
record in [PLAN.md](../PLAN.md). Each entry captures the evidence used to
prioritize work, the resulting change, verification, residual risk, and the
next audit targets. It does not replace release notes or claim that future
maintenance is complete.

## 2026-07-14 — Bound broker connection resources

### Scope and evidence

- Re-read `prompt.md` and the complete `PLAN.md`, inspected the worktree and
  trust-boundary packages, and ran the repository's test, race, fuzz, vet,
  cross-build, and security gates.
- Audited both broker listeners and found that every accepted Unix or
  reverse-TCP connection spawned a goroutine whose first frame read had no
  deadline. The existing pane and request-rate limits applied only after a
  peer supplied a complete authenticated frame, so silent unauthenticated
  peers could retain unbounded local file descriptors and goroutines.
- MITRE's [CWE-770](https://cwe.mitre.org/data/definitions/770.html) recommends
  limiting or throttling allocations such as connections. Go's
  [`net.Conn` contract](https://pkg.go.dev/net#Conn) specifies that a read
  deadline unblocks current and future reads and can be cleared with a zero
  time. The [Go vulnerability guidance](https://go.dev/doc/security/vuln/)
  confirms that `govulncheck` uses call reachability to reduce scanner noise.
- The audit used Go 1.25.12 from the checksum-pinned official archive. Go's
  [release history](https://go.dev/doc/devel/release) identifies 1.25.12 as the
  supported July 2026 security patch.

### Plan

1. Cap concurrent broker connections across both listeners with enough
   headroom for every supported wrapper/pane pair and short control requests.
2. Bound only the unauthenticated first-frame read.
3. Clear the deadline immediately after authentication so an interactive GDB
   pane can remain idle indefinitely.
4. Prove overflow rejection, slot reuse, handshake timeout, and authenticated
   longevity, then rerun every repository gate.

### Completed change

- Added a shared 32-connection admission limit. A full broker closes newly
  accepted connections without allocating handler goroutines.
- Added a five-second first-frame deadline and clears it after protocol,
  session, and token validation.
- Added regression tests covering connection saturation, deterministic
  overflow rejection, slot release/reuse, silent-handshake expiry, and a
  long-lived authenticated pane.

### Verification and measurements

- New broker tests passed 50 consecutive runs in 6.349 seconds.
- `go test ./internal/broker` and `go test -race ./internal/broker` passed.
- `make verify` passed: formatting, module checks, all unit tests, `go vet`,
  Darwin arm64/amd64 clients, Linux amd64 agent, size cap, and agent dependency
  isolation.
- `make test-race` passed across every package.
- `make security` passed gosec and reported `No vulnerabilities found` from
  `govulncheck` against the canonical Go vulnerability database.
- `FUZZTIME=3s make fuzz-smoke` passed all eight fuzz targets.
- Real macOS-to-Linux transport acceptance was not rerun in this Linux audit
  environment; the change is isolated to listener admission before broker
  message dispatch.

### Residual risk and next targets

- The plan intentionally does not treat same-UID remote processes as isolated;
  an authenticated peer can still occupy the bounded pool. The cap turns that
  case into per-session denial of service rather than unbounded host resource
  consumption.
- Audit broker/session record file trust and path validation, protocol payload
  strictness, provider subprocess timeouts, cancellation cleanup, and atomic
  state durability next.
- Profile hot interactive paths only after a realistic PTY/transport workload
  is available; avoid speculative micro-optimization.

## 2026-07-14 — Fail closed on unsafe session records

### Scope and evidence

- Re-read `prompt.md` and `PLAN.md`, then mapped session publication, pane
  loading, stop discovery, lease validation, stale cleanup, and deletion.
- Session records contain the local broker token, executable, SSH destination,
  control socket, remote agent, and runtime identity. `LoadSession` used an
  unbounded, non-strict `os.ReadFile`, followed final symbolic links, accepted
  non-private modes, and did not bind the filename to the record ID.
- Go documents that [`Lstat`](https://pkg.go.dev/os#Lstat) does not follow the
  final link and [`SameFile`](https://pkg.go.dev/os#SameFile) compares the
  underlying file identity. MITRE documents link-check/open races as
  [CWE-363](https://cwe.mitre.org/data/definitions/363.html).
- The Linux/POSIX [`open(2)` contract](https://man7.org/linux/man-pages/man2/open.2.html)
  confirms that `O_NOFOLLOW` rejects a final symbolic link, `O_NONBLOCK`
  prevents a FIFO open from waiting, and `O_CLOEXEC` atomically prevents
  descriptor inheritance. The existing `golang.org/x/sys/unix` dependency
  exposes those flags on the supported Linux and Darwin targets.

### Plan

1. Open the record descriptor without following its final path component and
   without blocking on a non-regular file.
2. Require a current-user-owned regular file with no group/other permissions,
   and verify the pathname still identifies the opened descriptor.
3. Decode from that descriptor with the existing 1 MiB metadata ceiling,
   reject unknown fields, and require `<session-id>.json`.
4. Cover each rejected state plus normal compatibility, then run every gate and
   both supported cross-build targets.

### Completed change

- Added `fsutil.ReadPrivateJSONLimit`, using
  `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, descriptor ownership/mode/type
  validation, pathname/descriptor identity comparison, and strict bounded
  decoding.
- Switched broker session loading to the private loader with
  `protocol.MaxFrame` and bound the record filename to its validated ID.
- Removed an avoidable byte-slice-to-string copy from bounded JSON decoding.
- Added regression coverage for group-readable records, symbolic links,
  nonblocking FIFO rejection, wrong filenames, unknown fields, oversized
  records, and valid round trips.

### Verification and measurements

- The five original negative cases all reproduced before implementation.
- Focused broker/fsutil tests passed 25 consecutive runs in 0.216 seconds
  combined; focused race tests passed.
- `make verify`, `make test-race`, `make security`, and
  `FUZZTIME=3s make fuzz-smoke` all passed. This includes vet, gosec,
  `govulncheck` (`No vulnerabilities found`), all eight fuzz targets, both
  Darwin client architectures, and the Linux amd64 agent.

### Residual risk and next targets

- `O_NOFOLLOW` applies to the final component; earlier path components may
  still be links. Normal operation places records below Pwnbridge-owned XDG
  roots that `Paths.Ensure` chmods to 0700. A future generalized rooted-state
  API could remove that remaining assumption without duplicating path logic.
- Same-UID mutation of an already-open regular file is not an isolation
  boundary in the product threat model. Atomic Pwnbridge writers never mutate
  records in place.
- Audit the analogous remote manifest and terminal-state loaders, protocol
  payload strictness, provider subprocess deadlines, and cancellation cleanup
  next.

## 2026-07-14 — Make broker protocol failures unambiguous

### Scope and evidence

- Re-read `prompt.md` and `PLAN.md`, inventoried JSON decoders, and followed
  framed messages through the remote wrapper, local broker, and pane helper.
- `protocol.Decode` called `json.Valid` and then parsed the same bytes again
  with `json.Unmarshal`, which silently ignored unknown object members.
  `ParsePayload` did the same permissive unmarshal for typed payloads.
- Broker and wrapper exit handlers explicitly discarded payload errors. A
  missing payload, `{"code":"success"}`, or a payload with unknown fields
  therefore produced `ExitPayload{Code: 0}` and reported debugger success.
- Go's [`encoding/json` documentation](https://pkg.go.dev/encoding/json#Decoder.DisallowUnknownFields)
  states that unknown struct fields are ignored by default and documents
  `DisallowUnknownFields` as the strict alternative. MITRE's
  [input-validation guidance](https://cwe.mitre.org/data/definitions/20.html)
  recommends rejecting data that does not conform in length, type, syntax,
  and extra fields.

### Plan

1. Decode each frame once with a strict decoder and reject trailing values.
2. Apply the same contract to typed payloads while preserving intentionally
   optional empty payloads such as an `open` request's default title.
3. Require debugger exit/error payloads and convert malformed exits to an
   explicit nonzero failure at both broker and wrapper boundaries.
4. Reproduce missing, wrong-type, and unknown-field false-success cases; add a
   stable decoder benchmark and run every gate.

### Completed change

- Replaced `json.Valid` plus permissive unmarshal with one strict decoder for
  protocol frames and payloads.
- Broker exit processing now emits status 1 and `invalid debugger exit
  payload` when the pane response is absent or malformed.
- The remote terminal wrapper independently rejects missing, malformed, and
  empty error payloads instead of returning success or a blank error.
- Added protocol, broker, and real Unix-socket wrapper regressions plus an
  in-tree representative-frame benchmark.

### Verification and measurements

- All five strictness/false-success regressions failed before the patch and
  passed afterward; focused tests passed 25 consecutive runs and focused race
  tests passed.
- The strict decoder measured approximately 4.6–5.2 microseconds, 1,424 bytes,
  and 19 allocations per representative frame. A temporary apples-to-apples
  benchmark of the old double-parse path measured approximately 4.5–5.9
  microseconds, 648 bytes, and 14 allocations. Latency was comparable while
  strictness cost 776 bytes and five allocations per control message.
- This protocol carries command, barrier, and pane control messages rather
  than terminal bytes; the measured allocation cost is bounded and outside
  the PTY byte path. `BenchmarkDecodeMessage` remains to detect regressions.
- `make verify`, `make test-race`, `make security`, and all eight fuzz-smoke
  targets passed, including both Darwin clients and the Linux agent.

### Residual risk and next targets

- Unknown fields now require a protocol-version increment, matching the
  existing explicit version contract. Duplicate JSON object keys still follow
  `encoding/json` compatibility behavior; no security decision depends on a
  duplicated field before post-decode identity validation.
- Audit terminal config/manifest file opening with the new private loader,
  provider subprocess deadlines, broker shutdown of pre-auth connections, and
  workspace/binding state bounds next.

## 2026-07-14 — Bound terminal-provider work and broker shutdown

### Scope and evidence

- Re-read `prompt.md` and `PLAN.md`, then mapped every broker call into terminal
  provider detection, opening, and cleanup, including normal exit, cancellation,
  late-open cleanup, and broker shutdown.
- Every call used `context.Background()`. A provider open could therefore outlive
  the broker indefinitely, while `Broker.Close` invoked provider cleanup with no
  deadline while holding the request mutex and before closing peer connections.
- The original regression reproduced the open leak: after the custom provider
  signaled that `Open` had begun, `Broker.Close` returned but the handler did not
  unwind within 500 milliseconds and failed with `broker close did not cancel
  provider open`.
- Go documents that [`CommandContext`](https://pkg.go.dev/os/exec#CommandContext)
  kills the direct process when its context ends but leaves `WaitDelay` unset.
  The [`Cmd.WaitDelay` contract](https://pkg.go.dev/os/exec#Cmd.WaitDelay) explains
  that a zero value can still wait indefinitely when an orphaned subprocess
  retains an output pipe, while a nonzero value bounds both process exit and I/O
  pipe closure.

### Plan

1. Tie sync barriers and provider opens to a broker-owned lifecycle context,
   and add an independent finite open deadline.
2. Cancel that lifecycle first during shutdown, snapshot and remove requests
   under the mutex, then close peer connections before bounded provider cleanup.
3. Bound every provider subprocess's post-cancellation process/I/O wait, not just
   the direct command.
4. Prove open cancellation, open expiry, prompt peer closure, mutex availability,
   cleanup expiry, and concurrent `Close` safety, then rerun every project gate.

### Completed change

- Added a broker lifecycle context, a 30-second provider-open budget, and a
  five-second provider-cleanup budget. Normal and shutdown cleanup use fresh
  contexts so cancelling in-flight opens does not suppress best-effort pane
  removal.
- Reworked shutdown to cancel active work, atomically detach the request set,
  release the mutex, close wrapper/pane connections immediately, and share one
  cleanup deadline across all remaining handles.
- Made `Broker.Close` safe for simultaneous callers with `sync.Once`.
- Routed all bundled terminal-provider commands through one command constructor
  with a one-second `WaitDelay`, covering Zellij, tmux, WezTerm, Kitty, macOS
  application launch, and the custom-provider protocol.
- Added regressions for lifecycle cancellation, the independent open deadline,
  cleanup deadline/mutex/peer ordering, 32 simultaneous close callers, and a
  successful custom-provider process whose orphan retains its output pipe.

### Verification and measurements

- The four timing regressions passed ten consecutive runs: broker coverage in
  3.241 seconds and provider pipe coverage in 10.042 seconds. The open timeout
  was configured to 50 milliseconds, cleanup to 250 milliseconds, and orphaned
  output was cut off at approximately one second.
- The focused race suite passed, and the concurrent-close/lifecycle tests passed
  25 race-enabled runs in 7.824 seconds.
- `make verify`, `make test-race`, and `make security` passed on the final code.
  This includes all tests, vet, both Darwin client builds, the Linux amd64 agent,
  gosec, and `govulncheck` (`No vulnerabilities found`).
- `FUZZTIME=3s make fuzz-smoke` passed all eight targets; the final workspace
  target was also rerun independently and passed.
- No microbenchmark was added: the changed hot spots execute external terminal
  processes, and the deterministic deadline tests measure the relevant behavior
  without pretending subprocess latency is a useful nanosecond-scale benchmark.

### Residual risk and next targets

- A parent wrapper that disconnects while synchronous provider opening is in
  progress is noticed when opening returns or reaches the 30-second deadline;
  broker shutdown cancels it immediately. Detecting peer EOF concurrently would
  require a more involved single-reader protocol state machine, but the leak is
  now bounded.
- The internal provider interface remains context-cooperative. Every registered
  built-in and custom executable path honors cancellation through
  `CommandContext`; an out-of-tree Go implementation that ignores its context
  could exceed the broker's synchronous cleanup deadline.
- Real macOS terminal applications and live multiplexer CLIs were not exercised
  on this Linux audit host; supported Darwin binaries cross-built successfully.
- Audit active pre-authenticated connection shutdown, private loading of other
  security-relevant state, atomic state durability, and workspace/binding bounds
  next.

## 2026-07-14 — Drain accepted broker connections on shutdown

### Scope and evidence

- Re-read `prompt.md` and `PLAN.md`, then traced ownership from both listener
  accept loops through admission slots, first-frame authentication, wrapper/pane
  handlers, and broker shutdown.
- `Broker.Close` stopped listeners and known debugger requests but did not retain
  accepted connections. A silent pre-authenticated connection therefore kept its
  descriptor, handler goroutine, and admission slot until the five-second
  handshake deadline even after `Close` returned.
- The pre-fix regression failed deterministically in 0.007 seconds with
  `broker close left 1 connection handler(s) running`.
- Go's [`net.Conn` contract](https://pkg.go.dev/net#Conn) guarantees that `Close`
  unblocks pending reads and writes. The [`sync.WaitGroup` contract](https://pkg.go.dev/sync#WaitGroup.Add)
  requires a positive add at a zero count to happen before a wait; this shaped a
  single-lock transition that prevents connection registration after shutdown
  begins.

### Plan

1. Register each admitted Unix/TCP connection under the broker mutex before
   launching its handler and remove it only when the handler releases its slot.
2. Under the same mutex, mark the broker closing and snapshot every connection
   before listener teardown, preventing an accept-vs-close gap.
3. Close all accepted sockets to unblock I/O and wait for registered handlers
   after no further wait-group additions are possible.
4. Reproduce post-close resource retention, stress accept against shutdown under
   the race detector, and rerun every repository gate.

### Completed change

- Added a bounded active-connection registry shared by both broker listeners and
  a handler wait group coupled to the existing admission limit.
- Shutdown now marks admission closed before closing listeners, rejects any
  already-accepted connection that reaches registration late, closes every
  registered socket, releases all handler slots, and waits for handler return.
- `Start` now rejects reuse after `Close` instead of creating listeners on an
  irreversibly cancelled broker.
- Added regressions proving that a silent accepted socket receives EOF and no
  handler/slot survives `Close`, plus a 25-iteration, eight-dialer accept/close
  race test.

### Verification and measurements

- The connection/handshake/shutdown set passed 25 consecutive runs in 3.217
  seconds and ten race-enabled runs in 2.351 seconds.
- The accept-vs-close stress test passed 20 race-enabled repetitions in 1.385
  seconds; the complete broker package passed ten runs in 4.686 seconds.
- `make verify`, `make test-race`, and `make security` passed, including all
  tests, vet, Darwin arm64/amd64 client builds, the Linux amd64 agent, gosec, and
  `govulncheck` (`No vulnerabilities found`).
- `FUZZTIME=3s make fuzz-smoke` passed all eight fuzz targets; the final workspace
  target was independently rerun and passed.
- No throughput benchmark was added. Registration adds one map insertion and one
  deletion per accepted control connection, never touches PTY bytes, and the map
  is capped by the existing 32-connection admission channel.

### Residual risk and next targets

- `Close` now deliberately waits for handlers. All production handler work uses
  closed sockets, lifecycle cancellation, configured sync-barrier deadlines, and
  bounded provider commands; a future internal `BeforeOpen` callback that ignores
  its context could violate that shutdown assumption.
- Concurrent `Start` and `Close` are not a supported lifecycle. Sequential reuse
  is now rejected explicitly, and simultaneous `Close` calls remain safe.
- Audit private/strict loading for other security-relevant state, atomic state
  durability, workspace/binding size limits, and cancellation of non-provider
  subprocess pipes next.

## 2026-07-14 — Bound and authenticate persisted file inputs

### Scope and evidence

- Re-read `prompt.md` and `PLAN.md`, inventoried every whole-file reader, and
  classified files by whether symlinks are intentional user behavior or whether
  the file is private Pwnbridge-owned state that influences execution, cleanup,
  synchronization identity, or credentials.
- Workspace state and bindings used the old unbounded permissive JSON reader;
  machine identity used unbounded `os.ReadFile`; debugger manifests used a
  link-following open before executing their argv/environment; configuration and
  recipe syntax limits were applied only after reading the entire file.
- Six pre-fix regressions reproduced: workspace state through a symbolic link,
  mode 0640 state, unknown state fields, a `--help` Mutagen identifier, a FIFO
  machine identity, and a valid global config padded beyond 1 MiB were all
  accepted.
- Linux [`open(2)`](https://man7.org/linux/man-pages/man2/open.2.html) and Apple's
  [`open(2)` manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/open.2.html)
  document `O_NONBLOCK` and `O_NOFOLLOW`; the Linux contract also documents
  atomic close-on-exec and that nonblocking mode does not alter regular-file
  semantics.

### Plan

1. Build one descriptor-first bounded regular-file reader that allows symlinks
   for explicit user inputs and a private variant that rejects the final link,
   non-current ownership, or group/other permissions.
2. Reject oversized files from descriptor metadata before allocation, retain a
   second read limit for growth races, and decode JSON strictly from those bytes.
3. Migrate every production whole-file input and remove the old permissive JSON
   API; validate persisted values before they become command arguments.
4. Preserve symlinked config/recipe compatibility, measure overhead, and rerun
   every repository gate.

### Completed change

- Added `ReadFileLimit` and `ReadPrivateFileLimit`. Both use
  `O_RDONLY|O_CLOEXEC|O_NONBLOCK`, require a regular descriptor, reject size
  before allocation, and retain a `maximum+1` read ceiling. The private variant
  adds `O_NOFOLLOW`, current-user ownership, private mode, and pathname/descriptor
  identity checks.
- Routed strict bounded JSON through those readers and removed the unbounded,
  permissive `ReadJSON` helper.
- Migrated workspace state, host bindings, machine identity, terminal session
  credentials, debugger manifests, global/project config, bootstrap recipes,
  synchronization ignores, system probe metadata, and local agent assets.
- Preserved final symlinks for user-selected config, recipes, ignores, and agent
  assets while rejecting FIFOs and other special files without blocking.
- Added a 1 MiB config/state/recipe/ignore ceiling, existing 1 MiB terminal and
  manifest ceiling, 64-byte machine ID and ptrace ceilings, 64 KiB os-release
  ceiling, and 16 MiB agent ceiling. Cross-build now enforces the agent ceiling.
- Workspace state now validates Mutagen identifiers (`sync_` plus 32–123
  alphanumerics), SHA-256 fingerprints, runtime IDs, and binding host IDs before
  persistence/use; Mutagen output extraction uses the matching identifier cap.

### Verification and measurements

- The six original regressions failed before implementation and pass afterward.
  Focused file/state/config/agent tests passed 25 consecutive runs, and every
  affected package passed under the race detector.
- A retained 1 KiB reader benchmark measured `os.ReadFile` at approximately
  6.4–8.3 microseconds, 1,528 bytes, and five allocations; the pre-sized bounded
  regular reader at 5.9–7.5 microseconds, 1,984 bytes, and seven allocations; and
  private validation at 8.5–9.0 microseconds, 2,256 bytes, and nine allocations.
  Reads occur at command/session boundaries, not in PTY or protocol byte paths.
- `make verify`, `make test-race`, and `make security` passed, including vet,
  Darwin arm64/amd64 clients, the bounded Linux amd64 agent, gosec, and
  `govulncheck` (`No vulnerabilities found`).
- All eight fuzz-smoke targets passed; the final CLI and workspace targets were
  independently rerun after truncated command output and passed.

### Residual risk and next targets

- `O_NOFOLLOW` protects the final component. Private state remains beneath XDG
  roots secured to mode 0700; fully descriptor-rooted traversal would remove the
  remaining earlier-component assumption at substantially greater complexity.
- Symlink targets for explicit user inputs may change between invocations by
  design. Each invocation parses the single descriptor it opened, so replacement
  cannot splice content into that read.
- Agent deployment hashes bounded bytes and later gives the path to `scp`; the
  remote install verifies that exact digest and therefore fails closed on
  replacement, though a replacement special file could delay `scp` until its
  command context is cancelled.
- `AtomicWrite` syncs file contents before rename but not the containing directory;
  the [`fsync(2)` contract](https://www.man7.org/linux/man-pages/man2/fsync.2.html)
  says directory synchronization is separately required for crash durability.
  Audit and patch that durability boundary next, then review non-provider command
  cancellation and streamed-log special-file handling.

## 2026-07-14 — Make atomic writes durable after rename

### Scope and evidence

- Re-read `prompt.md` and `PLAN.md`, mapped all `AtomicWrite`/`WriteJSON` callers,
  and compared the implementation with the architecture's documented
  fsync-plus-rename guarantee.
- The temporary file's data and mode were synced before atomic replacement, but
  the target directory was never synced. Newly created workspace/session
  directories could also be missing from their own parents after a crash.
- Linux [`fsync(2)`](https://www.man7.org/linux/man-pages/man2/fsync.2.html)
  explicitly states that syncing a file does not necessarily persist its
  directory entry and requires a separate directory descriptor sync. Linux
  [`rename(2)`](https://man7.org/linux/man-pages/man2/rename.2.html) documents
  atomic replacement of an existing target.
- Apple's [`fsync(2)` manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsync.2.html)
  warns that ordinary fsync may not flush device caches across power loss and
  points durability-sensitive applications to `F_FULLFSYNC`; Apple's
  [`fcntl(2)` contract](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fcntl.2.html)
  defines that operation.

### Plan

1. Record the nearest existing ancestor before creating missing parent
   directories.
2. Sync mode/data, close, rename, then sync the target parent and each newly
   created ancestor up to that original boundary.
3. Request `F_FULLFSYNC` on Darwin with an ordinary-fsync fallback for
   unsupported filesystems; use `File.Sync` on Linux.
4. Inject each failure boundary to prove old/new target semantics and temp
   cleanup, benchmark the added syscall, and rerun every gate.

### Completed change

- `AtomicWrite` now discovers the existing durability root, creates parents,
  durably syncs the temporary file, atomically renames it, and syncs directories
  from the target parent through every newly created ancestor.
- Darwin requests `F_FULLFSYNC` for files/directories and falls back to
  `File.Sync` on `EINVAL`, `ENOTSUP`, or `ENOTTY`; other supported builds use
  `File.Sync` directly.
- Temporary cleanup is now conditional on rename failure. A successful rename
  no longer leaves a deferred removal that could delete an unrelated file
  recreated under the old randomized temporary name.
- Added injected tests proving exact `sync file -> rename -> sync directories`
  order, old-target preservation on pre-commit failures, new-target visibility
  on post-rename sync failure, no leaked temporary files, committed mode, and
  deepest-to-oldest synchronization of new ancestor directories.

### Verification and measurements

- Durability/ordering tests passed 100 consecutive runs in 0.105 seconds; the
  complete fsutil package passed 25 race-enabled runs in 1.120 seconds.
- The Linux 1 KiB write benchmark measured approximately 31.1–33.9 microseconds,
  1,223 bytes, and 15 allocations before directory syncing, versus 32.7–36.3
  microseconds, 1,423 bytes, and 17 allocations afterward. The few-microsecond
  cost applies to low-frequency state publication, not PTY traffic.
- The Darwin arm64 fsutil test binary cross-compiled directly, and `make verify`
  passed both Darwin clients plus the Linux agent and its size bound.
- `make test-race` and `make security` passed; gosec was clean and
  `govulncheck` reported `No vulnerabilities found`.
- One three-second Syncer fuzz invocation ended with a Go fuzz-harness
  `context deadline exceeded`. The same target then passed a ten-second run with
  266,311 executions; all other targets passed extended independent runs. No
  crashing input or corpus failure was produced.

### Residual risk and next targets

- A directory-sync error occurs after atomic replacement. `AtomicWrite` returns
  the error because crash persistence is unconfirmed, while the new file remains
  visible; callers may safely retry.
- Actual power-cut testing and native APFS timing were not available on this
  Linux host. Ordering is fault-injected and grounded in the platform contracts,
  while Darwin correctness is cross-build verified.
- Filesystems that reject both `F_FULLFSYNC` and ordinary directory fsync will
  now report an error after replacement rather than silently claim durability.
- The nearest-existing-ancestor snapshot assumes the directory chain is not
  concurrently replaced by the same user during the write, consistent with the
  existing same-UID threat boundary.
- Audit cancellation and inherited-pipe behavior for SSH, Mutagen, runtime, and
  other non-provider subprocesses next; also review streamed diagnostic logs and
  copy sources for special-file blocking.

## 2026-07-14 — Bound inherited pipes for context-aware subprocesses

### Scope and evidence

- Re-read `prompt.md` and `PLAN.md`, inventoried every subprocess construction,
  and separated intentionally detached daemons/process-replacement commands from
  context-aware commands that callers expect to cancel or wait for.
- Provider commands already bounded inherited output pipes, but Mutagen, runtime
  engines, SSH, SCP, Mosh, pane transport, and CLI subprocesses all used the
  default zero `WaitDelay`.
- A pre-fix regression exercised the real Mutagen `CommandRunner` with a direct
  child that exited successfully while a grandchild retained stdout. The call
  blocked for 4.01 seconds until the grandchild exited and incorrectly returned
  nil.
- Go's [`CommandContext` documentation](https://pkg.go.dev/os/exec#CommandContext)
  specifies that it kills the direct process on context cancellation but leaves
  `WaitDelay` unset. The [`Cmd.WaitDelay` contract](https://pkg.go.dev/os/exec#Cmd.WaitDelay)
  states that a nonzero value bounds both a child that does not exit after
  cancellation and pipes retained after the direct child exits; the timer does
  not start while an ordinary command is still running.

### Plan

1. Add one internal context-aware command constructor with the already-tested
   one-second subprocess cleanup grace period.
2. Route every context-aware command through it while preserving intentionally
   detached Mutagen/SSH control processes and runtime commands returned for
   process replacement.
3. Reproduce the inherited-pipe behavior through a production runner, retain the
   provider regression, assert the constructor invariant, and compare allocation
   cost.
4. Stress affected packages under the race detector and rerun every repository
   gate.

### Completed change

- Added `internal/subprocess.CommandContext`, which delegates command creation to
  `os/exec` and sets a one-second `WaitDelay`.
- Migrated all context-aware subprocesses in broker, CLI, runtime, synchronization,
  terminal-provider, and transport packages. No direct `exec.CommandContext`
  remains outside the bounded constructor.
- Left detached Mutagen daemon startup, the persistent SSH control master and
  its cleanup, and runtime command construction unchanged because their lifecycle
  is deliberately not the lifecycle of one synchronous context-aware call.
- Added a production-runner regression for inherited stdout, retained the
  custom-provider regression, and added a direct constructor invariant test and
  benchmark.

### Verification and measurements

- The original four-second regression now returns `exec.ErrWaitDelay` in 1.01
  seconds. Both inherited-pipe regressions passed, all affected packages passed,
  and the focused set passed five race-enabled repetitions.
- Command-construction benchmarks measured the standard constructor at roughly
  28.2–32.5 microseconds and the bounded constructor at 30.4–37.8 microseconds;
  both used exactly 7,664 bytes and 85 allocations. Executable lookup dominates
  this synthetic benchmark, and setting one duration field adds no allocation.
- `make verify` passed formatting, module verification, all tests, vet, both
  Darwin client builds, the Linux agent build, artifact limits, and dependency
  separation. `make test-race` passed every package.
- `make security` passed gosec and `govulncheck` reported `No vulnerabilities
  found`. All eight five-second fuzz targets passed.

### Residual risk and next targets

- `WaitDelay` bounds cleanup only after context cancellation or direct-child
  exit; it intentionally does not impose an execution timeout on healthy pulls,
  synchronization operations, or interactive SSH sessions.
- Plain `exec.Command` remains appropriate for detached daemons and commands
  returned to process-replacement code, but several synchronous agent probes and
  remote multiplexer operations still lack a context or explicit execution
  deadline. Audit those call chains next.
- Review streamed diagnostic/log paths and local copy inputs for special-file
  blocking after the remaining synchronous command lifecycle work.

## 2026-07-14 — Bound synchronous remote-agent commands

### Scope and evidence

- Re-read `prompt.md` and `PLAN.md`, classified every remaining plain command as
  process handoff, intentionally detached/persistent lifecycle, or synchronous
  work expected to return to a caller.
- Agent bootstrap, filesystem and Python probes, and remote tmux/Zellij
  open/query/close commands were synchronous but had neither a context nor an
  execution deadline. A stuck pane query also ran inside the wrapper's ticker
  branch, preventing its signal-select loop from making progress.
- A pre-fix production-path regression installed a fake tmux client that slept
  for four seconds. `remotePaneExists` blocked for 4.01 seconds and then treated
  the delayed zero exit as a live pane.
- Go's [`signal.NotifyContext` contract](https://pkg.go.dev/os/signal#NotifyContext)
  provides a context cancelled by HUP/INT/TERM and requires its stop function to
  release signal resources. Linux [`signal(7)`](https://man7.org/linux/man-pages/man7/signal.7.html)
  documents signal delivery and process-group facilities; direct-child versus
  descendant termination remains a distinct lifecycle concern.

### Plan

1. Keep package installation healthy-time unbounded but cancel it when the agent
   receives HUP, INT, or TERM.
2. Give fast system probes finite per-command and aggregate deadlines.
3. Make remote pane open, polling, and cancellation cleanup signal-aware and
   bounded, while preserving the existing polling behavior.
4. Reproduce the hang, test context cancellation independently, quantify polling
   overhead, and rerun every gate.

### Completed change

- Bootstrap authentication and install subprocesses now use a shared signal
  context. Normal installs have no wall-clock deadline; agent termination kills
  the direct child and bounds post-cancellation I/O cleanup.
- Probe commands now have five-second individual limits beneath a 15-second
  aggregate budget. Failed or timed-out `df` and pwntools-version probes retain
  the existing fail-soft zero/empty results.
- Remote pane creation has a five-second deadline. Each 10 Hz existence query and
  signal-triggered close has a one-second deadline, uses the bounded subprocess
  constructor, and can be interrupted by the wrapper signal context.
- Closed a review-discovered race where a signal arriving during a query could
  be mistaken for normal pane exit; the wrapper now performs bounded cleanup and
  reports cancellation.
- No plain `exec.Command` remains in the agent. Runtime process handoff, detached
  Mutagen daemon startup, and the persistent SSH master remain intentionally
  plain.

### Verification and measurements

- The four-second pane regression now fails closed in approximately one second.
  A separate fake `df` regression proves a 50-millisecond parent deadline is
  honored. Remote-agent focused tests passed ten repetitions in 12.608 seconds
  and five race-enabled repetitions in 7.338 seconds; the complete agent package
  passed normally and under the race detector.
- A retained fake-tmux benchmark measured the old plain query at approximately
  0.87–0.95 milliseconds, 10,592 bytes, and 42 allocations, versus the bounded
  query at 0.98–1.08 milliseconds, about 11,128 bytes, and 50 allocations. At ten
  polls per second this is roughly one additional millisecond of CPU time per
  second and remains outside PTY byte paths.
- `make verify` passed formatting, module verification, all tests, vet, Darwin
  arm64/amd64 clients, the Linux agent, artifact limits, and dependency
  separation. `make test-race` passed every package.
- `make security` passed gosec and `govulncheck` reported `No vulnerabilities
  found`. All eight five-second fuzz targets passed.

### Residual risk and next targets

- `CommandContext` terminates the direct child. The one-second `WaitDelay` keeps
  Pwnbridge from waiting forever on inherited pipes, but a bootstrap shell's
  arbitrary descendant could survive unless its own parent/shell propagates
  termination. Audit safe process-group cancellation for Linux agent bootstrap
  separately before changing terminal job-control behavior.
- SSH master relay cleanup and the `ssh -O exit` control command are synchronous
  plain commands that can still delay `Master.Close`; bound them with a
  cancellation-independent cleanup budget next.
- Review streamed diagnostic/log paths and local copy inputs for special-file
  blocking after command lifecycle work.

## 2026-07-14 — Add a privacy-allowlisted support report

### Scope, research, and plan

- Re-read `prompt.md` and `PLAN.md`, traced reporting guidance, configuration
  layering, workspace/status/recovery state, diagnostics, bootstrap inventory,
  SSH execution, JSON conventions, help discovery, and release metadata.
- The existing help workflow required manually combining commands whose raw
  output can expose paths, host destinations, IDs, conflict/recovery names, and
  errors. The public repository has no issue history to suggest a more urgent
  request.
- Docker's official support guidance warns that diagnostics can include user
  and network identifiers; OWASP recommends excluding tokens, paths, session
  IDs, and internal names/addresses. Kubernetes provides useful stdout-first
  precedent but its broad log dump is inappropriate for challenge secrets.
  The selected plan therefore used a field allowlist with no log/archive/upload
  collection, not regex redaction.
- Ranked alternatives were recovery integrity verification, doctor partial-
  result redesign, Mutagen daemon-log hardening, and automatic pruning. The
  support workflow ranked first on user value, security, fit, and available
  evidence; the detailed acceptance criteria and primary references are in
  `PLAN.md` Cycle 17.

### Completed change and audit findings

- Added `pwnbridge support [--json] [--local-only]`, typed report structures,
  deterministic Markdown, schema-one JSON, safe error categories, independent
  10/10/20-second collectors, coarse sync/recovery summaries, and read-only
  remote capability inventory.
- No raw configuration/state/status/recovery/inventory/error object crosses the
  output boundary. Closed vocabularies or narrow grammars cover every string;
  custom provider/network names collapse to categories. No logs, paths,
  destinations, IDs, names, values, commands, images, tokens, raw output, or raw
  errors are collected.
- Sentinel review caught three initially over-broad token fields before
  completion: free-form `PWNBRIDGE_LOG`, user-defined container network names,
  and linker metadata. These now use closed log/network categories and strict
  release/hex-commit/RFC3339/Go-version grammars. Known GoReleaser snapshot
  metadata has a narrowly fuzzed grammar.
- The independent security/performance pass found a deadline without a memory
  bound: `bootstrap.Inspect` used unbounded `CombinedOutput`. Added a
  concurrency-safe draining output writer and `RawBounded`; inventories now
  retain at most 1 MiB and fail safely on excess. This protects support, doctor,
  and bootstrap without truncating an accepted inventory.
- Updated README and CLI/architecture/troubleshooting/security/development
  documentation and added local-only support discovery to the Lima workflow.

### Verification and measurements

- Twenty focused privacy repetitions passed. Renderer coverage is 98.2%; core
  collector functions are 80–100% covered. Hostile config, status, conflict,
  recovery, SSH error, inventory, capability, build-metadata, and writer cases
  are exercised across human/JSON boundaries.
- Renderer cost is 4.48–5.21 microseconds, 2,544 bytes, and 24 allocations.
  Twenty isolated local-only JSON processes averaged 8.74 milliseconds; typical
  JSON/Markdown output is 2,088/1,050 bytes.
- A 2 MiB hostile inventory retains exactly 1 MiB and returns a bounded error;
  the focused overflow path passed ten race repetitions.
- `make verify`, `make test-race`, module verification, vet, formatting,
  dependency separation, ShellCheck 0.11.0, and `bash -n` all pass. All ten
  five-second fuzz targets pass. Gosec is clean and `govulncheck` reports `No
  vulnerabilities found`.
- Cross-build sizes are 8,629,058 bytes Darwin arm64, 9,077,904 bytes Darwin
  amd64, and 5,026,691 bytes Linux agent. The final GoReleaser snapshot passes
  every checksum, archive-read, and Syft SBOM conversion; stripped binaries are
  8.264/8.778/3.305 MiB.

### Residual risk and next targets

- Default remote collection can trigger ordinary SSH authentication or host-key
  interaction; `--local-only` is documented for offline/private use.
- Coarse counts, sizes, booleans, and allowlisted versions are intentional but
  can still be sensitive in an unusual context, so the report says to review it.
- Omitted identifiers may be needed later for diagnosis and should be supplied
  individually through an appropriate private channel rather than widening the
  default report.
- Lima is not installed/configured here; unit/subprocess coverage and packaging
  pass, but the updated full remote E2E script was not executed.
- Next compare a digest-based `sync recovery verify` workflow with focused
  Mutagen daemon-log descriptor hardening, then implement the highest-evidence
  Cycle 18 improvement.

## 2026-07-14 — Cycle 16: acknowledge and verify remote conflict recovery

### Scope, reproduction, and evidence

- Re-read `prompt.md` and `PLAN.md`, traced conflict resolution, SSH control
  reuse, agent deployment, SCP, shell checks/removal, recovery persistence, and
  restore from the command boundary through every filesystem mutation.
- Ranked the remaining remote check/SCP/delete race as the highest-severity
  product gap. A deterministic reproduction replaced a checked remote parent
  with an outside symlink between backup and shell removal; the old final
  `rm -rf` removed the outside replacement.
- Primary research used Go's `archive/tar` contract and traversal guidance,
  Go's `os.Root` design, OpenSSH no-PTY behavior, POSIX Issue 8 directory and
  rename semantics, and rsync's remove-only-after-success/source-change model.
  These sources are linked in `PLAN.md` section 21.
- The implementation review reproduced a second flaw in its first draft: tar
  writer close after a source error could terminate an already-written prefix,
  allowing a client to mistake it for a complete directory. A FIFO-after-file
  regression proved the ambiguity before the application trailer fixed it.

### Completed product and engineering change

- Added deterministic, constant-memory recovery archive emission and strict
  durable extraction. Sorted descriptor-held traversal supports only regular
  files, directories, and symlinks; identity/mode/size/mtime are checked around
  exact nonblocking reads. The receiver requires one root, canonical unique
  parent-before-child names, GNU format, fixed timestamps, zero ownership and
  device fields, no PAX/xattrs, known types, bounded paths/links/entry counts,
  exclusive creation, and a fixed completion trailer.
- Added protocol-4 `recovery-stream`: the agent streams and waits; the client
  extracts, syncs, hashes, and atomically catalogs before acknowledging the
  exact SHA-256. The agent then re-streams to a digest sink, binds the original
  top object identity, removes through a held remote root, syncs the parent,
  and returns an exact summary. Missing/mismatched ACKs and changed sources
  retain the remote copy. Lost post-ACK results report an uncertain outcome and
  the already durable backup path.
- Reused one private SSH master for all selected remote losers and removed the
  independent remote shell parent check, loser SCP, and shell `rm -rf` from
  resolution. Invalid arguments fail before SSH, then current conflicts are
  revalidated under the workspace mutation lock.
- Added SHA-256 to new local and remote manifests and inventory. Restore hashes
  before copy and again after creation, cleaning a mismatched target. Existing
  schema-one and legacy entries remain restorable and display
  `sha256=unverified` rather than receiving a false integrity claim.
- Updated README, architecture, security, CLI, troubleshooting, development,
  protocol paths, and the Lima remote-loser scenario. The latter now requires
  a non-empty 64-character digest before restoring the real remote copy.

### Independent review perspectives

- Product/UX: resolution remains one explicit command; durable recovery IDs
  now carry a visible integrity identity and failure text distinguishes
  preserved, uncertain, and changed-source outcomes.
- Architecture: one typed bidirectional session replaces three separately
  resolved remote operations and introduces no daemon, dependency, compression
  layer, retention policy, or archive UI.
- Security: rooted operations contain namespace replacement, strict metadata
  rejects tar's broad compatibility surface, content is never deleted before
  durable ACK, and special/truncated streams fail closed. The same-account
  final in-root replacement interval remains documented.
- QA: round trips, empty directories, links, determinism, namespace attacks,
  hostile headers, traversal, duplicates, invalid parents, hard links,
  ownership/timestamps, partial writes, FIFO prefix generation, no/mismatched
  ACK, source change, strict final JSON, bounded stderr, same-size tamper,
  legacy manifests, and a real subprocess/OS-pipe transaction are covered.
- Performance/operations: transfer and verification are streaming and bounded
  in memory. Protocol-versioned agent deployment, cancellation, control-master
  closure, release packaging, checksums, and SBOMs all passed validation.
- Documentation: discovery, integrity semantics, acknowledgement ordering,
  uncertainty recovery, compatibility behavior, and the residual trust
  boundary are documented for both new users and operators.

### Verification and measurements

- `make verify`, full `go test -race ./...`, `go vet ./...`, formatting/module
  checks, 20 focused repetitions, and `git diff --check` passed.
- All nine three-second fuzz targets passed; the new filesystem-backed archive
  target exercised 167 inputs in its recorded run. ShellCheck 0.11.0 passed all
  repository shell scripts.
- Gosec 2.27.1 passed after documenting two conversions already proven bounded
  to permission bits; govulncheck 1.6.0 reported `No vulnerabilities found`.
- Focused coverage: recovery 75.7%, CLI 39.5%, agent 35.2%. One MiB archive
  output: 972,859 ns/op, 35,112 B/op, 29 allocs/op. Durable extract/remove:
  1,334,413 ns/op, 36,147 B/op, 60 allocs/op.
- Darwin arm64/amd64 and static Linux agent cross-builds passed at
  8,561,506/9,023,184/5,026,707 bytes. GoReleaser snapshot output measured
  stripped release binaries at 8.215/8.722/3.305 MiB. Every archive checksum,
  archive member list, and all three non-empty SPDX 2.3 SBOMs validated.
- No Lima VM/SSH configuration, actionlint, or Ruby YAML tooling is installed,
  so those optional environment-dependent checks could not run. The protocol
  itself ran end to end through the Go test subprocess and real OS pipes.

### Residual risks and next opportunities

- POSIX exposes no portable conditional recursive unlink by observed inode.
  A same-account process can still change an object after the agent's second
  digest/identity check and before rooted removal; it cannot redirect removal
  outside the held workspace root.
- Large losers can exhaust local disk. Partial extraction is cleaned and the
  remote source is retained until fsync/catalog completion, but automatic
  pruning remains intentionally deferred without an operator retention policy.
- Deterministic archive identities are versioned by the recovery stream design
  and protocol. Future changes to the canonical encoding must preserve old
  manifest verification rather than silently rewriting digests.
- Start Cycle 17 with a broad product/operations assessment. Prioritize a
  meaningful diagnosability or recovery workflow over further narrow archive
  refactoring unless new evidence identifies a correctness regression.

## 2026-07-14 — Make conflict recovery discoverable, restorable, and rooted

### Scope and evidence

- Re-read `prompt.md` and `PLAN.md`, mapped the complete recovery layout and
  conflict-resolution mutation flow, and confirmed that recovery copies were
  discoverable only in transient `sync resolve` output. There was no catalog,
  JSON inventory, restore command, or retained original directory boundary.
- Reproduced the local deletion weakness deterministically: after a parent was
  checked as a real directory, replacing it with a symlink caused the existing
  path-based recursive-removal shape to delete an outside victim.
- Go's official [`os.Root` guidance](https://go.dev/blog/osroot) identifies
  exactly this check/use traversal class and documents descriptor-held rooted
  APIs. The supported Go 1.25 line supplies rooted `RemoveAll`, `Rename`, and
  `Symlink` operations.
- Borg's official [list](https://borgbackup.readthedocs.io/en/stable/usage/list.html)
  and [extract](https://borgbackup.readthedocs.io/en/stable/usage/extract.html)
  commands separate discovery from restoration. Restic's official
  [restore guidance](https://restic.readthedocs.io/en/v0.19.1/050_restore.html)
  recommends a non-existing target or no-overwrite mode, and its
  [scripting contract](https://restic.readthedocs.io/en/latest/075_scripting.html)
  provides structured inventory. Git's reflog/restore model independently
  supports stable prior-state identifiers followed by an explicit restore.
- Ranked recovery inventory/restore first and rooted local mutation second.
  Deferred automatic retention without policy evidence, a support bundle
  without field-level redaction evidence, and a remote streamed transaction
  until it can preserve arbitrary trees without buffering them in memory.
  The complete pre-change plan, criteria, risks, and sources are in `PLAN.md`.

### Completed product and security change

- Added `pwnbridge sync recovery list [--json]`. Human output quotes IDs and
  paths and reports creation time, losing endpoint, type, aggregate bytes and
  objects, mode, original path, and legacy state. JSON uses the existing
  versioned envelope and the same stable fields. Listing reads local state only
  and never contacts, resumes, or flushes Mutagen.
- Added `pwnbridge sync recovery restore ID --to PATH`. The destination must be
  explicit, canonical, project-relative, and non-existing. Files, directory
  trees, empty directories, permission bits, and raw symlinks are preserved;
  partial top-level destinations are removed on failure and the recovery source
  remains intact. Restoration is deliberately local and offline.
- New nanosecond UTC archives contain an atomically replaced, fsynced schema-1
  manifest. Each backup is recorded before loser deletion, preserving its
  original conflict boundary. Older timestamp/winner directories remain
  available as conservative, individually restorable leaf entries.
- Moved recovery filesystem logic into `internal/recovery`. Copy, restore, and
  local recursive removal operate below held `os.Root` descriptors. Regular
  files open nonblocking, bind descriptor identity to the lstat observation,
  copy exactly the observed length, recheck size/mode/mtime, use exclusive
  destination creation, and sync files and affected directories.
- Recursive source copies open a nested root for every directory. A directory
  renamed after it is opened therefore keeps serving the original children
  instead of silently switching to a replacement namespace. Symlinks are read
  and recreated as links and are never followed for backup content.
- `sync resolve` now acquires the workspace lock before re-reading the current
  conflict set, holds it through backup/catalog/removal, and releases it before
  the existing barrier reacquires the lock. This closes a second Pwnbridge
  interleaving without creating a recursive-lock deadlock.
- Added real Lima workflow coverage: after preferring the local conflict copy,
  the test locates the cataloged remote loser through JSON, restores it to a
  new local name, and checks its content. README, CLI, troubleshooting,
  architecture, security, and development documentation cover the complete
  user journey and limitations.

### Verification and measurements

- Tests cover regular files, nested/empty directories, symlinks, modes,
  no-overwrite behavior, malformed and changed manifests, multiple entries,
  legacy ordering and boundaries, traversal, missing IDs, special files/FIFOs,
  partial cleanup, source-file replacement, opened-directory replacement, the
  original parent-symlink removal escape, command discovery, JSON output, and
  terminal-safe human output.
- Twenty-five focused repetitions passed in 0.147 seconds for recovery and
  0.495 seconds for CLI. Ten race-enabled repetitions passed in 1.137 and
  1.548 seconds. Statement coverage is 73.9% for the new recovery package and
  remains 39.0% for the broad CLI package.
- A 1 MiB rooted durable copy measured 0.70–0.80 milliseconds, about 2.3 KiB
  and 41 allocations across five runs. The simple whole-file read/write
  baseline measured 1.41–1.51 milliseconds, about 1.06 MiB and 13–14
  allocations. Listing and validating 100 manifested entries measured
  1.39–1.52 milliseconds total, approximately 14–15 microseconds per entry.
- Final `make verify` passed formatting, module verification, every package,
  vet, Darwin arm64/amd64 clients, the static Linux amd64 agent, size ceilings,
  and agent dependency separation. The complete race suite passed; the changed
  packages passed again after the final benchmark addition.
- `make security` passed gosec and govulncheck reported no vulnerabilities.
  All eight five-second fuzz targets passed. Official ShellCheck v0.11.0 passed
  every packaging/E2E shell script, and Python byte-compilation passed.
- A cold GoReleaser run first exhausted the 2 GiB tmpfs during parallel Darwin
  assembly. Moving only Go's temporary build directory to disk completed all
  archives and exposed the absent SBOM executable. An official Syft v1.44.0
  Linux archive was downloaded from Anchore, checked against its published
  SHA-256 list, and supplied temporarily. The final snapshot produced and
  checksum-verified two Darwin archives, the agent archive, embedded agent,
  documentation, completions, and three parsed SPDX 2.3 SBOMs.
- This environment has no Lima/`limactl` or SSH fixture, so real-host additions
  could not run. `actionlint`, Ruby, and PyYAML are also unavailable; no success
  is claimed for those optional local tools. Existing workflow parsing and
  release acceptance from the complete project record remain unchanged.

### Independent post-implementation audit

- Product: the backup is now usable after resolution output disappears, and
  restore cannot replace the chosen winner accidentally.
- Architecture: recovery behavior is isolated behind a small package and reuses
  workspace identity, locking, XDG storage, JSON envelopes, and durability
  primitives instead of adding a daemon, database, or dependency.
- Security: rooted operations prevent namespace escape; manifests and regular
  reads bind validated descriptor identities; exclusive restore and escaped
  output close overwrite and terminal-injection paths.
- QA: legacy ambiguity is handled conservatively, every supported type and
  malformed boundary is covered, partial output is cleaned, and directory
  rename behavior has a deterministic regression.
- Performance: streaming exact-length copies allocate essentially constant
  memory and catalog scans remain low-millisecond at 100 entries.
- UX: commands are discoverable below `sync recovery`, JSON is scriptable, and
  the explicit destination/local-only message makes side effects predictable.
- Operations and documentation: catalogs are durable, recovery works without a
  live session, release artifacts include the new docs, and troubleshooting
  carries discovery through restore and propagation.

### Residual risk and next targets

- Manifests validate structure and metadata, not same-size content integrity or
  authenticity; the same local account can alter both catalog and data.
- Rooted APIs deliberately include mount points already inside a root and may
  affect a replacement object inside that root, though they cannot escape it.
- Remote loser backup and deletion still use separate path-based SCP and shell
  commands. A same-account remote process can replace a path between checks,
  backup, and removal. The next cycle will design a bounded streamed agent
  transaction with descriptor-held directory traversal and identity-bound
  removal, rather than buffering arbitrary challenge trees or adding tar-shell
  trust.

## 2026-07-14 — Add safe endpoint-aware conflict previews

### Product and technical assessment

- Re-read `prompt.md` and `PLAN.md`, inventoried the complete command/docs/test
  surface, exercised current help and package coverage, reviewed the 0.1.0–0.1.13
  history, and queried the public repository. It has no open or closed public
  issues yet, so documentation and implemented user journeys are stronger
  evidence than issue volume.
- The largest product gap was concrete: troubleshooting required users to
  inspect both conflict copies before choosing a winner, but unhealthy sync
  intentionally blocks normal remote execution and the CLI offered only path
  listing followed by destructive resolution.
- Mutagen's official
  [synchronization documentation](https://mutagen.io/documentation/synchronization)
  says safe-mode conflicts are manually resolved by deleting the losing
  endpoint. Previewing both versions is therefore part of Pwnbridge's explicit
  data-loss decision rather than optional polish.
- [POSIX Issue 8 `diff`](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/diff.html)
  specifies unified `-u` output, and the current
  [macOS `diff(1)` manual](https://keith.github.io/xcode-man-pages/diff.1.html)
  documents both `-u` and explicit `-L` labels. This supports familiar output
  without a Go diff dependency.
- A redacted support bundle and a combined setup wizard were also assessed.
  [VS Code Remote troubleshooting](https://code.visualstudio.com/docs/remote/troubleshooting%5C),
  [Docker diagnostics](https://docs.docker.com/desktop/troubleshoot-and-support/troubleshoot/),
  and [Tailscale bug reports](https://tailscale.com/docs/account/bug-report)
  establish their ecosystem value, but Pwnbridge has no support cases to define
  a safe redaction contract and its existing bootstrap wizard already handles
  setup's complex phase. Both were deferred. The ranked portfolio and acceptance
  criteria were persisted in `PLAN.md` before implementation.

### Plan and acceptance criteria

1. Add `pwnbridge sync diff -- PATH...` for exact current conflict paths, using
   the same traversal/duplicate/non-conflict validation as resolution.
2. Capture each endpoint from an opened workspace descriptor without following
   symlinks or blocking on special files; represent missing, regular,
   directory, link, and special endpoints explicitly.
3. Return at most 1 MiB of content per endpoint, strictly authenticate response
   structure/digest, and render unified local-to-remote output only when bytes
   are display-safe UTF-8.
4. Summarize control-bearing, binary, oversized, link, directory, special, and
   type-mismatched versions without exposing raw controls or mutating sync.
5. Integrate diagnostics, help, docs, a real Lima scenario, repeated/race tests,
   benchmarks, cross-builds, security scans, fuzzing, and an independent review.

### Completed product change

- `sync diff` now checks the exact stored Mutagen session and rejects healthy
  sessions, non-conflict paths, escapes, and duplicates before remote setup.
  Output is explicitly labeled `local -> remote`, and ordinary `diff` status 1
  is normalized as a successful preview.
- Added a shared descriptor-rooted snapshot package. It opens every directory
  component with close-on-exec, nonblocking, directory, and no-follow flags,
  opens the final entry nonblocking/no-follow, classifies special files without
  waiting for a peer, and re-stats regular files after reading to reject
  concurrent size/mode/mtime changes.
- The content-addressed Linux agent gained one typed, per-invocation `snapshot`
  operation. Preview setup reuses one private SSH control master for agent
  verification/deployment and every requested path; it creates no execution
  session, broker, runtime, synchronization barrier, or workspace mutation.
- Remote snapshot JSON rejects unknown/trailing fields, unknown kinds,
  impossible kind/data combinations, negative/oversized fields, mismatched
  length, and a digest that does not authenticate the returned bytes.
- Valid UTF-8 preview content excludes C0/C1 controls and Unicode format
  controls except tab/newline. Paths and link targets use ASCII-escaped labels,
  so filenames, symlinks, and endpoint bytes cannot inject terminal controls.
  Larger than 1 MiB content and non-text/non-regular types receive bounded
  type/size/mode/digest metadata instead.
- Doctor now checks the supported macOS/POSIX `diff` utility. README, CLI,
  troubleshooting, architecture, security, installation, development, and the
  canonical plan document discovery, directionality, limits, and recovery use.
  The real Lima conflict flow now asserts preview headers and both hunk sides
  before resolving.

### Tests, measurements, and verification

- New tests cover regular/missing/oversized capture, final and parent symlinks,
  traversal, invalid roots/limits, immediate FIFO classification, typed agent
  output, exact conflict validation, unified/identical/mode-only output,
  control and Unicode-safe suppression, every non-regular class, strict remote
  decoding, diagnostic discovery, and CLI command discovery.
- Changed packages passed 25 repetitions: filesnapshot in 0.026 seconds, agent
  in 31.623 seconds, CLI in 0.472 seconds, and diagnostics in 0.007 seconds.
  Ten race-enabled repetitions passed in 1.036, 13.730, 1.502, and 1.017
  seconds respectively.
- The first 1 MiB snapshot benchmark exposed geometric buffering: 3.42–3.51
  milliseconds, 5.24 MiB, and 45 allocations. Size-informed bounded
  preallocation reduced it to 1.11–1.38 milliseconds, 1.058 MiB, and 14–15
  allocations. Plain reading measured 0.35–0.43 milliseconds and 1.057 MiB;
  the remaining explicit-preview cost is descriptor traversal and SHA-256.
- New package coverage is 80.6%. CLI coverage rose from 37.0% to 39.0% and
  agent coverage from 32.4% to 33.3%; syncer/transport/workspace remained
  45.2/59.1/73.1%.
- `make verify` passed formatting, module verification, every test, vet, Darwin
  arm64/amd64 clients, the Linux amd64 agent, 16 MiB artifact caps, and client-
  only UI dependency separation. Artifact sizes are 8,309,746 bytes (Darwin
  arm64), 8,732,432 bytes (Darwin amd64), and 4,747,414 bytes (Linux agent).
  `make test-race` passed every package.
- `make security` passed gosec and `govulncheck` reported `No vulnerabilities
  found`. All eight five-second fuzz targets passed. The modified POSIX script
  passed `sh -n` and official current ShellCheck v0.11.0 across the complete
  packaging/e2e shell suite.
- A native client and static agent build passed, and live help shows `sync diff`
  with its `PATH...` contract. No configured Lima SSH environment/VM exists in
  this audit host, so the extended real-host scenario could not execute here;
  prior full Lima acceptance remains recorded in `PLAN.md`.

### Independent review and residual risk

- Product/UX: the operator can now inspect, decide, resolve, and recover without
  bypassing Pwnbridge's unhealthy-session boundary. Plain output, escaped
  labels, multiple paths, transient TTY-only progress, and explicit direction
  keep the command accessible and script-readable.
- Architecture/operations: one small reusable boundary and one typed agent
  operation fit the existing stateless architecture. No daemon, config schema,
  protocol-version migration, persistent state, or third-party library was
  added.
- Security/QA: path escape, symlink traversal, FIFO blocking, malformed remote
  responses, terminal injection, file growth/shrinkage, normal `diff` status 1,
  missing files, and endpoint type changes are covered. A compromised same-UID
  remote account remains able to alter its own files, as documented by the
  product trust model; resolution independently reloads current conflict state.
- Performance: SSH/agent readiness dominates an explicit preview. One master is
  reused, content is network-bounded, and the measured local work is about one
  millisecond for the maximum rendered file.
- Very large files intentionally omit content and digest; size/mode/type remain
  available. Recursive directory diffs are intentionally excluded because they
  would multiply transfer and terminal-output bounds. Both can be reconsidered
  only with evidenced demand.
- The earlier path-based recursive backup/removal race remains the highest
  security residual. The next cycle will reassess it against recovery discovery
  and restore workflows so hardening and user-facing recovery value can be
  delivered together rather than as another isolated micro-fix.

## 2026-07-14 — Bind local recovery copies to validated file descriptors

### Scope and evidence

- Re-read `prompt.md` and `PLAN.md`, then traced local conflict recovery from
  Mutagen conflict selection through losing-side backup and source deletion.
- A recovery file was checked with `Lstat` and then reopened by pathname with
  ordinary `os.Open`. A concurrent replacement could therefore change the
  object being copied; replacing it with a FIFO also made recovery block before
  it could protect the losing version.
- A pre-fix production-path regression replaced the source with a FIFO and was
  still blocked after 200 milliseconds. The destination did not yet exist, but
  conflict recovery could not make progress or report the malformed source.
- Go's [`os.SameFile`](https://pkg.go.dev/os#SameFile) documents the
  platform-specific identity comparison used between the path observation and
  opened descriptor. [`io.CopyN`](https://pkg.go.dev/io#CopyN) guarantees that
  a nil error means exactly the requested byte count was copied. POSIX
  [`open`](https://man7.org/linux/man-pages/man3/open.3p.html) defines the
  close-on-exec, nonblocking, and no-follow flags used to reject descriptor
  substitution and blocking special files.

### Plan

1. Reproduce special-file blocking and same-sized pathname replacement through
   the real recovery copy helper.
2. Open the source without following its final component, validate the opened
   file against the earlier observation, and copy only its observed length.
3. Exclusively create the backup, remove every partial destination on failure,
   and durably commit both file data and its directory entry before deleting
   the source can proceed.
4. Benchmark the low-frequency path, review mutation limitations, and rerun all
   repository quality, race, security, and fuzz gates.

### Completed change

- Regular recovery sources now open with
  `O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOFOLLOW`. The opened descriptor must still
  be regular, have the observed size, and identify the same file as `Lstat`.
- Copying uses `io.CopyN` with that observed size, so a growing source cannot
  make backup work unbounded and a shrinking source fails rather than silently
  publishing a truncated backup.
- Backup destinations retain exclusive creation and source permissions. Any
  copy, file-sync, close, or directory-sync failure removes the partial output
  and returns an error, preventing the caller from deleting the losing source.
- Exposed the existing platform durability primitives as narrow fsutil helpers;
  Darwin still uses `F_FULLFSYNC` with its documented fallback and other
  platforms use `File.Sync`.
- Added regressions for immediate FIFO rejection, same-sized path replacement,
  partial cleanup after injected sync failure, and successful content/mode
  preservation.

### Verification and measurements

- The original FIFO source now rejects immediately and leaves no destination.
  The focused recovery suite passed 25 repetitions in 0.026 seconds and ten
  race-enabled repetitions in 1.037 seconds.
- A 1 MiB copy benchmark measured the former plain path at approximately
  0.53–0.62 milliseconds, 518–521 bytes, and 13 allocations, versus the
  descriptor-validated durable path at 0.57–0.66 milliseconds, 1366–1367 bytes,
  and 18 allocations. This work occurs only during explicit conflict recovery.
- `make verify` passed formatting, module verification, all tests, vet, both
  Darwin clients, the Linux agent, artifact limits, and dependency separation.
  `make test-race` passed every package.
- `make security` passed gosec and `govulncheck` reported `No vulnerabilities
  found`. All eight five-second fuzz targets passed.

### Independent review and residual risk

- Product: recovery now fails promptly and preserves the original when its
  backup cannot be proven complete, directly supporting the no-silent-data-loss
  product rule.
- Architecture/operations: the change reuses the existing durability layer and
  adds no dependency or background service; the measured cost is confined to a
  rare operator-initiated workflow.
- Security/QA: final-component replacement, special-file blocking, growth,
  shrinkage, pre-existing destinations, and persistence failures fail closed.
- Performance/UX/documentation: the sub-millisecond durability increment is
  preferable to falsely completing recovery, and failures retain the original
  conflict version for a retry.
- An in-place writer can change bytes on the same inode during copying. A
  generic portable copy cannot provide a filesystem snapshot; complete
  point-in-time consistency requires producer coordination or filesystem-native
  snapshots. Pwnbridge therefore guarantees descriptor identity, bounded work,
  complete persistence, and non-deletion on error rather than claiming snapshot
  isolation.
- Directory traversal and deletion still use path-based APIs after validated
  parent checks. Concurrent same-user namespace mutation remains a separate
  recovery hardening opportunity, but the next cycle deliberately returns to a
  broad product and workflow assessment before selecting more narrow hardening.

## 2026-07-14 — Audit bootstrap descendant cancellation without changing TTY job control

### Scope and evidence

- Re-read `prompt.md` and `PLAN.md`, traced bootstrap from the local CLI through
  `RunPTY`, the structured remote-agent request, sudo authentication, each
  installer child, signal handling, and command cancellation.
- Bootstrap always uses `ssh -tt` so sudo remains visible and can read credentials
  directly from the controlling terminal. Children currently inherit the
  agent's process group; context cancellation kills the direct child but does
  not promise to kill arbitrary descendants.
- A live reproduction ran the built Linux agent with a structured shell step
  that started a background `sleep`, then sent TERM to the agent. The agent
  returned after its bounded cancellation path, while the recorded descendant
  was still alive (`descendant_survived=true`); the audit explicitly killed it.
- Go's [`SysProcAttr` documentation](https://pkg.go.dev/syscall#SysProcAttr)
  supports creating a child process group and optionally making it the terminal
  foreground group. POSIX [terminal access control](https://pubs.opengroup.org/onlinepubs/7908799/xbd/termios.html)
  requires background process groups that read the controlling terminal to
  receive `SIGTTIN`, whose default action is to stop. Linux's
  [`setpgid(2)` notes](https://www.man7.org/linux/man-pages/man2/getpgrp.2.html)
  describe the same foreground-only read rule and preservation of process groups
  across exec.

### Decision and verification

- No production code was changed in this cycle. Applying `Setpgid` alone would
  make sudo and interactive installers background TTY readers and could suspend
  the very recovery path it is intended to harden.
- A correct group-based design would also need atomic foreground transfer to
  each child, restoration to the agent between multiple steps, signal-safe
  handling of HUP/INT/TERM, and coverage on both Linux PTYs and the macOS SSH
  client path. That is a job-control feature, not a safe one-line cancellation
  patch.
- The preceding full verify, race, security, cross-build, and fuzz matrix remains
  applicable because the audit made no code/configuration changes. `git
  diff --check` remained clean.

### Residual risk and next targets

- A malicious or poorly behaved bootstrap step can fork away from its shell and
  survive direct-child cancellation. The structured recipe boundary prevents
  arbitrary command templates, but package managers/installers can still create
  descendants as part of normal operation.
- Closing the SSH PTY commonly causes the remote session to deliver HUP, which
  reduces practical leakage, but Pwnbridge does not treat that external behavior
  as a complete descendant-reaping guarantee.
- Revisit foreground process-group ownership only with native PTY integration
  tests and explicit terminal restoration. Do not weaken visible sudo or move
  credential handling into Pwnbridge.
- Audit bootstrap log creation, growth, replay, and streamed-line buffering next;
  these paths currently accept unbounded package output and use ordinary file
  opens on generated state paths.

## 2026-07-14 — Bound and authenticate bootstrap logs and streamed lines

### Scope and evidence

- Re-read `prompt.md` and `PLAN.md`, traced bootstrap output from the SSH PTY
  through the raw log, progress parser, optional sanitized display, failure UI,
  and later log replay.
- Live logs used ordinary create/append and repaired permissions after opening;
  replay used blocking `os.Open`. Neither side rejected a final symlink or
  special file, and live package output could grow a log without a ceiling.
- A pre-fix regression passed a private FIFO to `PrintSanitizedLog`; after 200
  milliseconds the open was still blocked. The same ordinary-open pattern was
  present before SSH in the live bootstrap path.
- The progress parser retained any unterminated non-authentication line without
  a limit. Verbose sanitization used the default scanner token ceiling but
  ignored scanner errors. Go's [`bufio.Scanner` contract](https://pkg.go.dev/bufio#Scanner)
  says scanning stops unrecoverably when a token exceeds its buffer and that the
  reader may already have advanced arbitrarily far.
- Linux [`open(2)`](https://man7.org/linux/man-pages/man2/open.2.html) documents
  the no-follow, nonblocking, and close-on-exec flags used by the descriptor-first
  private-file boundary established in the earlier persisted-input cycle.

### Plan

1. Add a descriptor-first private append open that rejects final links, special
   files, wrong ownership/mode, oversized existing files, and pathname races.
2. Cap each raw bootstrap log at 16 MiB while allowing the SSH stream and
   bootstrap operation to continue after a truncation marker is committed.
3. Replace implicit scanner buffering in live parsers with explicit 1 MiB line
   ceilings that discard an overlong line and recover at its next newline.
4. Replay only a private bounded regular file, test both pre-SSH append and UI
   replay, benchmark boundary overhead, and rerun every gate.

### Completed change

- Added `fsutil.OpenPrivateAppendFile`, using
  `O_WRONLY|O_APPEND|O_CREAT|O_CLOEXEC|O_NONBLOCK|O_NOFOLLOW`, descriptor type,
  current-user/private-mode, existing-size, and path-identity validation.
- Live bootstrap now opens logs through that helper before SSH. A bounded writer
  limits the file to exactly 16 MiB, reserves space for a truncation marker when
  possible, and then reports successful writes while discarding further log
  bytes so disk exhaustion does not abort package installation.
- Progress and sanitized-verbose streams now retain at most 1 MiB for one line.
  Overlong lines are omitted (with a visible verbose marker), discard until the
  next newline, and then resume normal structured-event parsing.
- Replay now uses `ReadPrivateFileLimit` with the same 16 MiB file ceiling and a
  1 MiB line ceiling before sanitizing output.
- Added tests for safe create/append, mode, ownership boundary, final symlink,
  FIFO, existing size, live pre-SSH rejection, replay rejection/sanitization,
  exact log truncation, and recovery after overlong unterminated lines.

### Verification and measurements

- The original FIFO replay hang now rejects immediately. The focused file/log/
  stream suite passed 25 repetitions in 0.047 seconds combined and ten
  race-enabled repetitions in 2.095 seconds combined; complete fsutil and
  bootstrap packages passed normally and under race.
- Append-open benchmarks measured ordinary append at approximately 4.1–4.6
  microseconds, 168 bytes, and three allocations, versus private bounded append
  at 5.6–6.1 microseconds, 648 bytes, and six allocations. This runs once per
  bootstrap attempt.
- Normal bounded progress and verbose event parsing measured approximately
  2.9–3.2 microseconds per event, with 824/688 bytes and 18 allocations
  respectively; package installation and SSH latency dominate this path.
- `make verify` passed formatting, module verification, all tests, vet, both
  Darwin clients, the Linux agent, artifact limits, and dependency separation.
  `make test-race` passed every package.
- `make security` passed gosec and `govulncheck` reported `No vulnerabilities
  found`. All eight five-second fuzz targets passed, including both bootstrap
  fuzzers after the parser rewrite.

### Residual risk and next targets

- The no-follow check protects the final component. The generated log directory
  remains beneath the owner-private XDG state root and retains the same
  earlier-component assumption as other private state.
- A same-user concurrent writer holding a separate descriptor could grow the
  file independently after validation; normal Pwnbridge ownership has one log
  writer per attempt. Enforcing a cross-process quota would require locking or a
  separate log service.
- One overlong line is intentionally omitted rather than partially rendered, so
  JSON/control sequences cannot be exposed through a truncation boundary. Raw
  bytes before the 16 MiB file cap remain available for diagnosis.
- Audit local backup/copy source replacement next: current code checks a source
  with `Lstat` and then reopens by path, allowing a regular file to be swapped
  for a blocking special file between those operations.

## 2026-07-14 — Bound and serialize SSH master teardown

### Scope and evidence

- Re-read `prompt.md` and `PLAN.md`, traced SSH master construction, startup
  readiness, relay forwarding, command reuse, wait ownership, and every close
  call site.
- The master intentionally outlived foreground-context cancellation so later
  cleanup could still stop containers and relays. However, `Master.Close` used
  new plain SSH commands for remote relay cleanup and `ssh -O exit`, giving those
  operations no replacement deadline. Repeated/concurrent closes also reran the
  same teardown sequence.
- A pre-fix production-path regression replaced SSH with an interruptible
  four-second sleeper. `Master.Close` blocked for 4.006 seconds in the control
  command.
- OpenSSH's current [`ssh(1)` manual](https://man.openbsd.org/ssh.1) defines
  `-O exit` as a control request passed to an active multiplexing master and
  `-S` as its control-socket path; it does not specify a completion deadline for
  the requesting client. Go's bounded command contract from the prior cycle is
  therefore still required around the control request.

### Plan

1. Create a fresh cleanup context independent of the already-cancelled
   foreground command, but give the complete control-command sequence a finite
   budget.
2. Serialize teardown so only one caller owns remote cleanup, control-master
   exit, signal escalation, and wait consumption.
3. Bound retained output pipes for the persistent master and wait for process
   reaping after interrupt/kill without allowing teardown to wait forever.
4. Reproduce each boundary and rerun all repository gates.

### Completed change

- `Master.Close` now uses `sync.Once`; concurrent and repeated callers wait for
  the same teardown and never launch duplicate remote/control operations.
- Remote relay cleanup and `ssh -O exit` share a fresh five-second background
  cleanup context. Expiry proceeds to local master termination even if remote
  cleanup did not acknowledge completion.
- The persistent master itself now has a one-second `WaitDelay`, which begins
  only when it exits and bounds output descriptors retained by unexpected child
  processes.
- Local termination sends interrupt, waits one second, escalates to kill, and
  then waits at most two more seconds for the existing wait goroutine to reap the
  process. The maximum teardown path is finite even if control commands and the
  master both misbehave.
- Added regressions for the stalled control command, eight concurrent closes,
  an early-exiting master with an inherited output pipe, and an
  interrupt-ignoring master that must be killed and reaped.

### Verification and measurements

- The original 4.006-second control-command hang completes in approximately 100
  milliseconds under the injected test budget. The timeout/idempotency pair
  passed 25 repetitions in 2.586 seconds and ten race-enabled repetitions in
  2.064 seconds.
- The full four-regression lifecycle set passed five repetitions in 10.748
  seconds and three race-enabled repetitions in 7.470 seconds. The complete
  transport package passed in 7.223 seconds and under race in 8.241 seconds.
- No throughput benchmark was added: the changed work executes only on one
  control-master startup failure or session teardown, and the focused timings
  directly validate its latency bounds.
- `make verify` passed formatting, module verification, all tests, vet, both
  Darwin clients, the Linux agent, artifact limits, and dependency separation.
  `make test-race` passed every package.
- `make security` passed gosec and `govulncheck` reported `No vulnerabilities
  found`. All eight five-second fuzz targets passed.

### Residual risk and next targets

- The worst-case local teardown budget is five seconds of control cleanup, one
  second after interrupt, and two seconds after kill. Normal teardown returns as
  soon as OpenSSH acknowledges exit and the master wait completes.
- If remote relay cleanup consumes its entire budget, Pwnbridge kills the local
  master and may leave a stale remote PID/socket file. Later stale-session
  cleanup remains responsible for that degraded network case; teardown no
  longer hangs the local CLI.
- Audit process-group cancellation for agent bootstrap descendants next, taking
  care not to alter PTY job control or deliberately detached daemons.
- Review streamed diagnostic/log paths and local copy inputs for special-file
  blocking after command lifecycle work.

## 2026-07-14 — Verify conflict recovery integrity proactively

### Scope, research, and plan

- Re-read `prompt.md` and `PLAN.md`, traced recovery creation, deterministic
  archive hashing, manifest inventory, restore, workspace locking, CLI/JSON
  conventions, support summaries, and the remaining Mutagen daemon-log path.
- Recovery digests were visible and enforced during restore but could not be
  checked proactively, leaving accidental damage latent until an urgent use.
- Borg's read-only `check --verify-data`, restic's `check --read-data`, Git's
  full versus connectivity-only `fsck`, and GNU checksum verification all
  support an explicit full-content check with visible cost and nonzero failure.
  Go's `os.Root` guidance supports reuse of the existing rooted digest path.
- A privacy/permission hardening of the owner-private Mutagen daemon log ranked
  second. The product workflow had stronger direct value and reused complete
  primitives without a new format, dependency, daemon, or configuration. The
  detailed ranked roadmap, acceptance criteria, risks, and authoritative links
  are recorded in `PLAN.md` Cycle 18 before implementation.

### Completed change and audit findings

- Added `sync recovery verify [ID...] [--json]` for all or exact selected
  entries. It holds the workspace lock, checks sequentially, supports
  cancellation, emits per-entry and aggregate results, returns nonzero for
  damage or missing historical digests, and never contacts SSH/Mutagen or
  mutates any state.
- Added context-aware deterministic digesting and typed verification across
  files, directories, and symlinks. SHA-256, type, mode, byte count, and item
  count must all match the manifest.
- Initial integration used strict `List`, which correctly rejects current
  metadata drift but prevented later entries from being checked. The independent
  architecture/QA review caught this before completion. `ListForVerification`
  now validates manifest structure while deferring current content/metadata to
  each verifier; ordinary listing remains strict and corrupt catalogs remain
  fatal.
- Human IDs are ASCII-quoted, JSON uses the stable envelope, read/integrity/no-
  digest reasons are bounded categories, and incomplete output is written before
  the command returns its automation-friendly error.
- Documentation and Lima E2E now cover periodic checking, selected IDs,
  full-byte and lock cost, Ctrl-C, nonzero incomplete results, no repair or
  digest enrollment, and same-account limitations.

### Verification and measurements

- Twenty focused repetitions and ten focused race repetitions passed. Recovery
  package coverage is 76.8%; the new digest, context digest, verify, ordinary
  list, and verification list entry points are 100% covered. CLI selection,
  aggregation, rendering, and incomplete status are 100% covered.
- A 1 MiB file verifies in 0.99–1.06 milliseconds with about 35.7 KiB/40
  allocations. A 100-file tree verifies in 1.87–1.93 milliseconds with about
  293.6 KiB/3,058 allocations.
- `make verify`, every race test, all ten fuzz targets, module verification,
  vet, formatting, dependency separation, ShellCheck 0.11.0, and `bash -n`
  pass. Gosec is clean and `govulncheck` reports `No vulnerabilities found`.
- Cross-builds measure 8,645,954 bytes Darwin arm64, 9,094,688 bytes Darwin
  amd64, and 5,026,811 bytes Linux agent. GoReleaser, all checksums/tar reads,
  and Syft SBOM validation pass; stripped binaries are 8.280/8.794/3.305 MiB.

### Residual risk and next targets

- Verification is point-in-time and not authenticated against a process with
  access to both catalog and data. Legacy entries remain explicitly incomplete.
- Structurally corrupt catalogs fail before per-entry results rather than
  guessing object boundaries. Very large scans hold the workspace lock and do
  not show live progress before the buffered result, but Ctrl-C is honored.
- Lima is not installed/configured, so the updated real remote verification
  assertion was not executed; all local subprocess, unit, race, and packaging
  layers pass.
- Next prioritize descriptor-safe Mutagen daemon-log startup against broader
  doctor redesign and per-operation SSH output bounds in Cycle 19.

## 2026-07-14 — Make isolated Mutagen startup cancellable and descriptor-safe

### Scope, research, and plan

- Re-read `prompt.md` and `PLAN.md`, traced the normal and fallback Mutagen
  launcher, long socket-path alias, subprocess deadlines, XDG permissions,
  private-file primitives, release path, history, and current diagnostic gaps.
- The normal launcher failure path detached `daemon run` even after context
  expiry. Its log used path-based stat/rename/open, followed a final symlink,
  could block opening a FIFO, accepted unsafe ownership/mode, and discarded
  rotation failures.
- Mutagen's authoritative daemon documentation confirms both the fast,
  idempotent `daemon start` and hidden foreground `daemon run` embedding modes.
  Linux `open(2)` documents `O_NOFOLLOW` and FIFO-safe `O_NONBLOCK`; `rename(2)`
  documents atomic destination replacement and retained open descriptors. Go's
  rooted-filesystem guidance supports a held directory boundary. The new July
  2026 `os.Root` trailing-slash advisory is fixed in audit Go 1.25.12 and does
  not affect the fixed-basename `openat` implementation selected here.
- A partial-result `doctor` redesign ranked as the next larger product feature,
  but the startup hang/background-service violation had higher severity and a
  narrow independently verifiable fix. The ranked roadmap, acceptance criteria,
  risks, and primary links were recorded in `PLAN.md` before editing.

### Completed change and audit findings

- Startup now honors pre-cancellation before state creation, cancellation after
  the normal launcher, and cancellation immediately before fallback creation.
  A successful child is released only after the parent log descriptor closes;
  an ambiguous close/release failure kills and reaps it.
- The real Mutagen data directory is no-follow opened and must be an
  owner-private current-user directory before either launcher. The long-path
  alias is revalidated after normal-launch failure, so a detected swap cannot
  redirect fallback or its log.
- Added reusable descriptor-rooted private directory validation and rotating
  append. Log opens are relative, no-follow, nonblocking, close-on-exec, and
  restricted to a current-user private regular file. Oversized logs rotate to
  one `.previous` entry with inode verification; a previous symlink is replaced
  without following it, while destination directories and all errors fail
  closed.
- Review widened data-directory validation ahead of the normal launcher and
  moved the final context check to immediately before `Start`. Tests cover
  normal/fallback launch, pre-cancel/deadline, linked or broad directories,
  symlink/FIFO/directory/broad logs, rotation and destination failure,
  disappearing executable, long-alias replacement, and prompt failure.
- Architecture, security, troubleshooting, and development docs state the log
  path, cancellation and permission behavior, safe remediation, and the
  startup-only—not runtime—5 MiB threshold.

### Verification and measurements

- Twenty focused repetitions and ten focused race repetitions passed. New
  entry-point coverage is 75.0% rotating open, 83.3% directory validation, and
  76.3% daemon start; inode/private-directory predicates are 100% covered.
- A validated reuse open measures 9.9–11.4 microseconds, 928 bytes, and 11
  allocations; rotation measures 38.6–42.6 microseconds, 1,752 bytes, and 25
  allocations.
- `make verify`, the full race suite, all ten fuzz targets, gosec,
  `govulncheck` (`No vulnerabilities found`), ShellCheck 0.11.0, and `bash -n`
  pass. Cross-builds are 8,646,242 bytes Darwin arm64, 9,115,440 bytes Darwin
  amd64, and 5,026,835 bytes Linux agent.
- GoReleaser succeeded with Go 1.26.5. Six checksums, three tar reads, embedded
  agent hashes, and three SPDX 2.3/Syft conversions passed; stripped binaries
  are 8,698,722 bytes Darwin arm64, 9,237,456 bytes Darwin amd64, and 3,465,378
  bytes Linux agent.

### Residual risk and next targets

- Runtime growth is not capped after the short-lived parent releases the daemon
  descriptor. Same-UID state races remain outside the privilege boundary, and
  log rotation is non-critical rather than directory-synced durable state.
- Mutagen 0.18.1 and Lima are unavailable here, so fake executable integration
  plus Linux race and Darwin compilation cover the accessible layers.
- Next design partial-result, independently budgeted `doctor` diagnostics and
  audit remaining raw SSH output bounds. Automatic recovery deletion and a log
  forwarding wrapper remain unjustified complexity.

## 2026-07-14 — Make doctor read-only, partial-result, and independently bounded

### Scope, research, and plan

- Re-read `prompt.md` and `PLAN.md`, traced both doctor commands, bootstrap
  inventory/planning, agent deployment, forwarding, context propagation,
  transport output, rendering, JSON envelopes, exit mapping, docs, tests,
  packaging, and the available real-runtime surface.
- The project command deployed an agent during a health check, shared one
  unbounded context across local and remote work, discarded completed results
  on collector errors, exposed unsanitized multiline error text, and disagreed
  with host doctor's recipe-derived checks. Several tiny SSH protocols retained
  unbounded combined output.
- Official Homebrew, GitHub CLI, Docker, Kubernetes, Go context, OWASP logging,
  and Python command-line documentation support all-check/partial reporting,
  independently scoped request deadlines, bounded control-safe output, and
  `-B` for a Python metadata import that must not create `.pyc` files. The
  ranked roadmap, acceptance criteria, risks, and primary links were recorded
  in `PLAN.md` before implementation.

### Completed change and audit findings

- Project and host doctor now share bounded read-only inventory, resolved
  recipe planning, configured Mosh/container checks, and an ephemeral private
  reverse-forwarding probe. Doctor never discovers, deploys, or runs the agent,
  invokes SCP or sudo, installs software, or persists a remote diagnostic file.
- Independent 10/20/15-second local, inventory, and forwarding contexts retain
  failures as ordered checks. Inventory failure still permits forwarding;
  parent cancellation stops later probes and returns after partial output with
  exit 130.
- A shared typed report adds stable `ok`, `complete`, and ordered `checks` data
  to schema-one JSON and one-write human rendering. Detail/remediation are
  valid UTF-8, one line, ANSI/control/format-free, capped at 512/256 bytes, and
  visibly truncated. Health and output failures are propagated after emission.
- Basic/forwarding output is capped at 64 KiB, agent JSON at 1 MiB, and control
  master startup output at 64 KiB. Overflow is drained and rejected; context
  causes and inherited-pipe teardown remain bounded. The Python pwntools
  metadata read uses official no-bytecode-write mode.
- Independent product, architecture, security, QA, performance, UX, operations,
  and documentation review found and closed the Python bytecode and fuzz-target
  integration gaps. Remaining cleanup-over-deadline, non-cooperative interface,
  raw-detail privacy, and invalid-config boundaries are documented rather than
  hidden by misleading health states or extra configuration.

### Verification and measurements

- One hundred collector repetitions, five fake-OpenSSH CLI repetitions, twenty
  captured-inventory repetitions, focused transport/race repetitions, and a
  standalone binary check pass. Integration proves project/host parity,
  configured requirements, no SCP/agent operation, timeout continuation,
  cancellation output/exit 130, writer errors, JSON, and human output.
- Report coverage is 100% construction, 88.9% failure classification, 89.5%
  rendering, 95.0% normalization, and 83.3% escape parsing. Local/remote doctor
  aggregation is 100%/85.7%; configured and forwarding paths are 100%.
  Bounded SSH output is 91.7%, with writer/snapshot at 100%.
- Thirty-two-check report normalization/rendering measures 78.7–136.7
  microseconds, about 18.4 KiB, and 375 allocations. Healthy remote collection
  measures 23.9–27.5 microseconds, about 21.0 KiB, and 72 allocations.
- `make verify`, all race tests, all eleven fuzz targets, gosec,
  `govulncheck` (`No vulnerabilities found`), ShellCheck 0.11.0, `bash -n`,
  cross-builds, and GoReleaser pass. Cross binaries are 8,679,554/9,123,936/
  5,026,835 bytes; stripped releases are 8,699,026/9,254,144/3,465,378 bytes.
  Six checksums, three archives, both embedded-agent hashes, and three SPDX 2.3
  SBOM conversions validate.

### Residual risk and next targets

- OpenSSH cleanup has its own finite budget and can outlive the nominal probe
  work deadline. Production subprocesses honor forceful cancellation, but the
  narrow interface cannot compel an arbitrary non-cooperative implementation.
- Raw doctor output can contain private paths or remote errors; `support` is the
  positive-allowlist public-sharing path. Invalid project configuration remains
  fatal before remote collection because effective requirements are unknown.
- Lima and Mutagen 0.18.1 are unavailable here; fake process integration, race
  tests, Darwin builds, and full packaging cover the accessible layers.
- Next audit the remaining unbounded SSH/control response paths and compare a
  bounded execution improvement with live recovery-verification progress.

## 2026-07-14 — Add visible partial-result recovery verification and bound SSH management replies

### Scope, research, and plan

- Re-read `prompt.md` and `PLAN.md`, inventoried every repository file and
  command-output path, reviewed recovery archive/verify/restore, locks,
  cancellation, progress, JSON, transport, SCP, forwarding, tests, docs,
  dependencies, release history, and public issue/PR history. The GitHub
  repository has no issues or pull requests; v0.1.0–v0.1.13 and the local audit
  remain the product-history evidence.
- Full recovery verification held the workspace lock with no progress and
  discarded completed results on cancellation. SSH management replies used
  unrestricted `CombinedOutput` buffers despite empty/port/bounded-JSON
  contracts. Interactive/bulk streams were correctly separate and excluded.
- Official restic and Borg documentation supports TTY progress separated from
  machine output and preserving full check evidence. Go source confirms
  `CombinedOutput` uses an unrestricted `bytes.Buffer`; OpenSSH specifies one
  allocated port for dynamic control forwarding. The ranked plan, criteria,
  risks, rejected JSONL/config/destructive alternatives, and primary links were
  recorded in `PLAN.md` before edits.

### Completed change and audit findings

- The deterministic archive reader optionally emits monotonic source bytes and
  item counts from the same digest traversal. Existing APIs delegate unchanged;
  updates coalesce at 256 KiB/64 items and force an exact final state, avoiding
  a second pass and per-read callback overhead.
- Human terminal verification uses the existing delayed spinner for a throttled
  path-free entry/count/percentage line. Fast, redirected, and JSON scans remain
  quiet. Recorded totals are display-only, progress clamps at 99% until entry
  completion, and final human/JSON reports add checked/total counts.
- Cancellation during a file, in the final callback, or before rendering emits
  all fully completed ordered results with `complete=false`, then preserves the
  context cause and exit 130. No checkpoint or recovery mutation is written.
- Ordinary SSH setup/control is capped at 1 MiB, forwarding/SCP diagnostics at
  64 KiB, and agent management at 2 MiB. Excess is drained and rejected while
  contexts and `WaitDelay` remain effective. A maximum 1 MiB conflict snapshot
  is accepted after JSON/base64 expansion; PTYs and recovery archives remain
  streamed.
- Independent product, architecture, security, QA, performance, UX, operations,
  and documentation review found and fixed premature 100% display, per-read
  callback overhead, duplicate management error detail, and the final
  cancellation race. Dependency updates and local Mutagen/container/provider
  output bounds remain separate evidence-driven work.

### Verification and measurements

- Fifty recovery-core, twenty CLI/PTY, three management-flood, and ten final
  boundary repetitions pass, along with focused and full race tests. Coverage
  is 100% for progress digest/verify/read, progress formatting/percentage/final
  rendering, ordinary bounded SSH/raw capture/writer/snapshot; aggregation is
  93.1%, agent management 93.3%, and forwarding setup 81.0%.
- Ordinary 1 MiB verification measures 0.93–1.15 ms after cold start, about
  35.9 KiB/41 allocations. Coalesced progress measures 0.99–1.07 ms, about
  35.9 KiB/43 allocations—overlapping baseline with 39 bytes/two allocations
  of callback state.
- `make verify`, full race, all eleven fuzz targets, gosec, `govulncheck` (`No
  vulnerabilities found`), ShellCheck 0.11.0, `bash -n`, and cross-builds pass.
  Cross binaries are 8,680,242/9,136,912/5,028,441 bytes; preliminary stripped
  releases are 8,716,210/9,267,104/3,469,474 bytes.
- The final snapshot is rebuilt after this append-only record so packaged plan
  and audit content match the implementation; archive/checksum/embedded-agent/
  SPDX results are recorded in the completed Cycle 21 plan.

### Residual risk and next targets

- Progress is intentionally an estimate; final integrity remains digest and
  metadata comparison. Interrupted scans do not persist resume state, and
  bounded collectors still depend on process exit or context cancellation to
  finish draining.
- Mutagen, container-engine, and terminal-provider diagnostics still need
  workload-specific output analysis. Current dependency updates are available
  but not vulnerability-driven; test them as a focused compatibility cycle.
- Lima and Mutagen 0.18.1 are unavailable, so fake SSH/SCP, PTY, race, Darwin
  cross-build, and inspected packaging are the accessible validation layers.

## 2026-07-14 — Stream cancellable container pulls and bound local tool replies

### Scope, research, and plan

- Re-read `prompt.md` and `PLAN.md`, inventoried repository subprocess paths,
  runtime setup, terminal providers, Mutagen state, conflict previews, signal
  ownership, tests, documentation, E2E, packaging, dependencies, and the prior
  audit. The largest workflow gap was a silent, unrestricted first container
  image pull that was not explicitly tied to agent signals.
- Official Docker and Podman contracts support native pull progress and quiet
  automation; Docker documents formatted immutable image inspection and a
  single detached container ID. Mutagen and the terminal providers document
  potentially large complete state inventories, while Go documents
  cancellation, inherited-pipe `WaitDelay`, `NotifyContext.stop`, and the
  unrestricted buffers behind `Output`/`CombinedOutput`.
- The ranked Cycle 22 plan, workload-specific ceilings, acceptance criteria,
  risks, streamed exclusions, rejected shared-limit design, and primary-source
  links were recorded in `PLAN.md` before implementation.

### Completed change and audit findings

- Added a synchronized bounded subprocess collector with stdout prefixes,
  diagnostic tails, truncation, context-cause precedence, and inherited-pipe
  teardown. Exact limits succeed; overflow is drained and rejected; invalid
  setup cannot start a child.
- First image acquisition streams Docker/Podman's native output only to a real
  TTY. Redirected operation uses official quiet mode and bounded diagnostics.
  SIGINT/SIGTERM/SIGHUP now cancel and reap setup clients before replacement,
  while the immutable-image-ID and runtime-record contracts remain intact.
- Mutagen state, terminal inventories, custom providers, small management
  replies, probes, runtime commands, and conflict diagnostics now have
  evidence-specific 16 MiB/4 MiB/1 MiB/64 KiB bounds. Bulk PTY, shell, runtime,
  bootstrap, diff, and recovery content stays streamed. No direct production
  `Output`/`CombinedOutput` call remains.
- Tests cover concurrency, exact/excess limits, final tails, inherited pipes,
  large structured state, real PTY versus `/dev/null`, quiet and interactive
  pulls, delivered-signal reaping, and cancellation. Review found and fixed the
  `/dev/null` terminal false-positive and two provider overflow paths before
  final gates. Documentation and E2E cover the complete first-run journey.

### Verification and measurements

- Twenty subprocess/runtime, ten agent, and five Mutagen/provider repetitions,
  focused race tests, full unit and race suites, all twelve fuzz targets, and
  `make verify` pass. Subprocess coverage is 95.1%, with capture and writer
  machinery at 100%; affected-package aggregate coverage is 52.6%.
- A 32 MiB flood through `bytes.Buffer` allocates about 67.1 MiB and takes
  18.3–24.0 ms. The 64 KiB tail allocates 180,288 bytes and takes
  0.823–0.859 ms: 99.73% less allocated memory and roughly 22–29 times less
  elapsed time on this runner.
- Gosec, `govulncheck` (`No vulnerabilities found`), ShellCheck 0.11.0,
  `bash -n`, module verification, source audit, and diff checks pass. Cross
  binaries are 8,680,482/9,149,424/5,056,177 bytes; stripped release binaries
  are 8,732,962/9,275,536/3,489,954 bytes.
- The final snapshot is rebuilt after this append-only record so packaged plan
  and audit content match implementation; archive, checksum, embedded-agent,
  and SPDX results are recorded in the completed Cycle 22 plan.

### Residual risk and next targets

- Engine-native terminal output remains opaque and can contain control
  sequences; it comes only from the explicitly configured engine, is shown
  only on a real terminal, and is never persisted or included in support data.
  Engine daemons may retain reusable partial layers after client cancellation.
- Huge legitimate state above the new ceilings fails with an exact actionable
  error. The 16 MiB Mutagen collector can briefly coexist with an immutable
  snapshot but remains bounded; quiet CI intentionally has no live progress.
- Lima, Mutagen 0.18.1, and live container engines are unavailable here. Next
  isolate compatibility upgrades for the deferred UI/TOML dependencies while
  re-ranking meaningful feature opportunities and avoiding dependency churn
  without user value.

## 2026-07-14 — Bound hostile TOML and harden Unicode bootstrap rendering

### Scope, research, and plan

- Re-read `prompt.md` and `PLAN.md`, inventoried repository behavior, command
  coverage, configuration boundaries, UI integration, module updates, and
  issue/release evidence. The largest evidenced gaps were an automatically
  discovered TOML parser predating an upstream stack-overflow defense and a
  terminal stack predating wide-character loop, unavailable-input panic, race,
  and grapheme fixes.
- Researched the primary go-toml, Bubble Tea, Bubbles, Lip Gloss, x/ansi, and
  Staticcheck releases. Recorded the ranked product/technical assessment,
  acceptance criteria, risks, validation, and rejected speculative workflow
  features in Cycle 23 of `PLAN.md` before editing code.

### Completed change and audit findings

- Upgraded only go-toml 2.4.3 and the coordinated Charm UI stack. Configuration
  retains strict typing and its 1 MiB ceiling; pathological 100,000-level TOML
  is now rejected by the parser depth guard without exhausting the process.
- Decode failures preserve typed parser errors while adding a concise
  file/line/column/key summary. Multiple unknown keys are bounded to the first
  key plus a count, and values/source context are never echoed.
- Added real-program pipe/unavailable-input coverage plus model and fuzz
  invariants for CJK, combining/joining marks, emoji, narrow widths, visible
  selection, inline rendering, and a 250 ms per-view deadline. The repository
  now has thirteen fuzz targets.
- Staticcheck 2026.1 found seven pre-existing issues, all fixed without
  suppression. Review confirmed deprecated tar xattrs already flow through the
  PAX map rejected by the extractor. Documentation now covers the user,
  security, troubleshooting, architecture, and contributor journeys.

### Verification and measurements

- Focused repetitions/races, full unit/race suites, all thirteen fuzz targets,
  `make verify`, vet, Staticcheck, gosec, `govulncheck` (no vulnerabilities),
  ShellCheck 0.11.0, `bash -n`, module verification, cross-builds, and diff
  checks pass. A 30-second single-worker Unicode fuzz run rendered 67,059 cases.
- Strict project decode improved by about 15% median time, 76.1% allocated
  bytes, and 42.4% allocations. Correct complex-grapheme rendering costs about
  5 us/~20.6% median per human-paced view with unchanged allocation.
- Config coverage is 65.4% (`decodeOptional` 100%, contextual errors 89.5%);
  wizard coverage is 52.2% (choice view 92.9%, terminal view 100%). Cross
  binaries are 8,830,690/9,306,640/5,056,457 bytes; stripped releases are
  8,866,626/9,432,752/3,489,954 bytes and remain below 16 MiB.
- Snapshot checksums, archives, standalone/embedded agent equality, and all
  three SPDX 2.3 conversions pass. The agent graph contains none of the client
  config/UI dependencies. Product, architecture, security, QA, performance,
  UX, operations, and documentation review found no remaining release blocker.

### Residual risk and next targets

- The fixed parser's depth policy is upstream and Unicode view time modestly
  increased; both boundaries now have explicit regression evidence. Normal
  config errors reveal repair-essential local paths/keys, while support reports
  still expose only categorized failures.
- No live macOS bootstrap, Lima, Mutagen 0.18.1, or container engine is
  available. Cycle 24 returns to end-to-end product/workflow assessment and
  will reject features whose persistence or destructive risk outweighs
  evidence of user value.

## 2026-07-14 — Complete recovery lifecycle with crash-safe archive pruning

### Scope, research, and plan

- Re-read `prompt.md` and `PLAN.md`, inspected every user journey and command,
  queried the public issue/release history, and compared current first-host and
  recovery behavior with official Restic, Borg, POSIX, Go `os.Root`, and Mutagen
  guidance. The largest concrete gap was indefinite recovery growth with no
  supported storage-reclamation path.
- Selected explicit whole-archive retention over a combined host wizard,
  per-entry manifest surgery, digest enrollment, or automatic age/size policy.
  Recorded the ranked assessment, acceptance criteria, risks, measurements,
  primary sources, and rejected designs in Cycle 24 of `PLAN.md` before code.

### Completed product and engineering change

- Added strict newest-first resolution-archive inventory and `sync recovery
  prune --keep-last N (--dry-run|--yes) [--json]`. It retains at least one
  newest archive, previews exact quoted IDs and logical totals, deletes complete
  resolution groups only, and reports pruned/pending/not-run partial state.
- Confirmed pruning is local/offline under the workspace lock. Each archive is
  descriptor-relatively renamed to a random hidden tombstone and the recovery
  root is synced before context-aware reclamation. Stage-sync failure restores
  the visible archive; post-rename interruption leaves a retryable hidden tree.
- Removal never follows symlinks, checks directory identity, refuses top-level
  and nested mount/device crossings, and cleans only exact valid Pwnbridge
  tombstones on a later confirmed run. Corrupt catalogs, overflow, stale
  selections, and unrelated hidden data fail closed or remain untouched.
- Human/actual JSON/no-op/partial output, path-free delayed progress, help,
  README, CLI, troubleshooting, security, architecture, development, and the
  real two-conflict Lima workflow now cover the complete journey. No manifest,
  config, protocol, dependency, daemon, network, or automatic policy changed.

### Verification and measurements

- Twenty focused repetitions, focused/full races, full unit tests, `make
  verify`, vet, Staticcheck 2026.1, gosec, `govulncheck` (no vulnerabilities),
  module verification, ShellCheck 0.11.0, `bash -n`, diff checks, cross-builds,
  and all thirteen fuzz targets pass.
- Recovery coverage is 77.7% (archive inventory 88.9%, exported prune 100%,
  core state transitions 75.8%); CLI coverage is 53.7% with selection/result
  application at 100% and report construction at 90.9%.
- Strict 100-entry listing remains ~1.38–1.45 ms, ~205.2 KiB, and 1,280
  allocations, overlapping its prior timing with identical allocation. Full
  strict inventory, durable rename/sync, and descriptor removal of a 100-file
  archive takes ~1.59–1.68 ms, ~234.7 KiB, and 1,522 allocations.
- Cross binaries are 8,864,546/9,348,448/5,056,489 bytes; stripped releases are
  8,900,530/9,474,560/3,489,954 bytes. Client cost is 33,904/41,808 bytes and
  the stripped Linux agent is unchanged. Snapshot checksums, archives, embedded
  agent equality, current docs, and three SPDX 2.3 conversions pass.

### Independent audit and residual risk

- Product, architecture, security, QA, performance, UX, operations, and
  documentation review found and fixed top-level mount acceptance, ambiguous
  partial counts, and stage-sync rollback reporting before final gates.
- Pruning intentionally keeps one newest complete archive and has no age/size
  or per-entry mode. Recursive cleanup is linear under the workspace lock;
  huge trees receive transient status, and mounted content remains pending until
  unmounted. Logical bytes are not allocated disk blocks.
- A crash can leave hidden space until a confirmed rerun; dry-run never cleans
  it. Corrupt catalogs block pruning, and the trusted local account can still
  mutate recovery state. Lima/macOS/Mutagen live environments remain
  unavailable, so shell-validated E2E, fakes, races, cross-builds, and package
  inspection are the accessible evidence.

## 2026-07-14 — Add transactional checked host registration

### Scope, research, and plan

- Re-read `prompt.md` and the complete plan, audited the repository's first-host
  behavior, tests, global configuration mutations, bootstrap planner, doctor
  collectors, docs, E2E scripts, public issue history, and package state.
- Compared official VS Code Remote SSH connection verification/guided host add,
  DevPod add-time provider validation, Docker's separate context create/update
  operations, and current OpenSSH connection/forwarding/control semantics.
- Ranked checked registration above a combined privileged setup wizard, corrupt
  recovery diagnosis, and a new installer. Recorded acceptance criteria, risks,
  validation, measurements, and primary sources in Cycle 25 of `PLAN.md` before
  code.

### Completed product and engineering change

- Added `host add --check [--json]` with bounded read-only SSH inventory and
  temporary forwarding validation. It requires Linux amd64, writable/capacious
  home, acceptable ptrace, an executable full `pwn` bootstrap plan, and
  forwarding when global terminal scope needs it. Missing installable tools are
  pending bootstrap work, not false registration failures.
- Added explicit `--replace` and `--default`; the first host still becomes the
  default. Failed new/replacement checks and cancellation do not save, human
  details are control-safe, and JSON reports persisted/replaced/default plus the
  complete/partial check. Local-only add remains the default behavior.
- Decoupled add/transport/default from project parsing and migrated every CLI
  global read-modify-write to one fresh-read owner-private lock transaction.
  Slow probes stay outside the lock; commit merges unrelated updates, rechecks
  duplicates/default, and rejects a concurrent terminal-scope policy change.
- Updated README, CLI, configuration, installation, troubleshooting, security,
  architecture, development, completions, and the Lima scenario. No dependency,
  config/protocol schema, agent, daemon, implicit network, or remote mutation
  changed.

### Verification and measurements

- Twenty focused repetitions, focused/full races, full tests, `make verify`,
  vet, Staticcheck, gosec, `govulncheck` (no vulnerabilities), all thirteen fuzz
  targets, module verification, ShellCheck/syntax, diff/format checks, realistic
  local CLI use, cross-builds, and inspected snapshot packaging pass.
- CLI/diagnostics coverage is 56.2%; registration/common prerequisites and
  result rendering are 100%, integrated add 91.5%, collector 80.0%, global
  transaction 71.4%, and labeled reporting 89.5%. Fuzz executions are recorded
  in the completed Cycle 25 plan.
- Full-`pwn` readiness collection takes 30.9–38.7 us, 17,697 bytes, and 80
  allocations versus the minimal doctor baseline's 24.5–25.7 us, 21,042 bytes,
  and 72 allocations. The difference is negligible beside SSH and resolves a
  larger plan.
- Cross binaries are 8,881,282/9,365,056/5,056,481 bytes; stripped releases are
  8,917,266/9,499,360/3,489,954 bytes. Client growth is 16,736/24,800 stripped
  bytes and the stripped agent is unchanged. Checksums, archives, embedded-agent
  equality, generated flags, current docs, and three SPDX 2.3 conversions pass.

### Independent audit and residual risk

- Product, architecture, security, QA, performance, UX, operations, and docs
  review found and fixed lost concurrent global updates and a stale
  terminal-scope forwarding decision before final gates.
- Validation stays opt-in and remote-focused; doctor still covers local and
  installed health. OpenSSH interaction can consume the bounded budgets, direct
  editors do not honor the CLI lock, and successful persistence can precede a
  stdout failure.
- Global callbacks are bounded local work, but advisory lock waiting itself is
  not context-aware. The trusted same account can mutate state directly. Live
  Lima/macOS/Mutagen environments remain unavailable, so fakes, shell E2E,
  races, fuzzing, cross-builds, and package inspection are the evidence.

## 2026-07-14 — Add safe, reference-aware host retirement

### Scope, research, and plan

- Re-read `prompt.md` and the plan, audited host removal, bindings, workspace/
  session/recovery state, cleanup behavior, documentation, release history, and
  public issues (none), then compared official Docker context and Terraform
  workspace deletion safeguards with Kubernetes' simpler context deletion.
- Ranked safe host retirement above a global workspace browser, recovery repair,
  a checksec wrapper, and a combined privileged setup wizard. Recorded the
  product assessment, acceptance criteria, risks, primary sources, and
  validation plan in Cycle 26 before code.

### Completed product and engineering change

- Added `host remove NAME (--dry-run|--yes) [--force] [--json]`. It inventories
  default status, all bindings, managed workspace/sync/runtime state, recovery
  roots, and active sessions locally; normal removal refuses references and
  active sessions are never forceable.
- Force removes only the global record and preserves all inactive dangling
  state for same-name re-registration. Reports are deterministic, bounded,
  scriptable, and control-safe. Malformed project TOML and network/remote tools
  are outside this machine-global operation.
- Added strict, backward-readable workspace/binding schema two with canonical
  project identity, stored remote path, and remote-retention state. Owner-private
  catalogs validate grammar, hashes, schemas, sizes, counts, and links and fail
  closed on corruption or unattributed legacy recovery.
- `clean` now retains lifecycle evidence and clears remote retention only after
  successful explicit remote deletion. A per-host lease serializes confirmed
  removal with binding/session startup; startup revalidates the durable host
  before network work and publishes state before releasing the lease.
- Updated README, CLI/configuration/troubleshooting/architecture/security/
  development guidance, help/completions, and the Lima script. No dependency,
  remote deletion, implicit network action, agent/protocol, or daemon changed.

### Verification and measurements

- Twenty focused repetitions, focused/full races, full tests, `make verify`,
  vet, Staticcheck, pinned gosec, `govulncheck` (no vulnerabilities), module
  checks, ShellCheck/syntax, formatting/diff checks, realistic local CLI use,
  all thirteen fuzz targets, cross-builds, and snapshot inspection pass.
- CLI/workspace coverage is 57.5%/72.2%; removal integration/reference
  collection are 87.5%/89.1%, and state load is 100%. A strict 100-workspace
  catalog scan takes 2.10–2.50 ms, ~540.5 KiB, and 3,118 allocations.
- Fuzz executions were 58,233/73,382/16,776/8,517/7,700/85,438/324/107,296/
  12,820/66,323/23,237/13,191/19,749 across the thirteen targets. Cross clients
  are 8,931,778/9,423,360 bytes; the 5,056,481-byte agent is unchanged.
- Release checksums, three archives, embedded/standalone agent equality,
  generated removal flags, current docs, and three SPDX 2.3 conversions pass.

### Independent audit and residual risk

- Product, architecture, security, QA, performance, UX, operations, and docs
  review found and fixed misleading blocked output, remote-root migration
  compatibility, uncertain clean-state durability, and a launch/removal race.
- Legacy project paths and orphan recovery remain unattributable and block
  normal removal. Force intentionally permits inactive dangling state; direct
  same-account editors can ignore advisory locks. Catalogs cap at 4,096 records.
- Live Lima/macOS/Mutagen environments remain unavailable. The user requested
  completion and stop after this cycle, so no next cycle was started.
