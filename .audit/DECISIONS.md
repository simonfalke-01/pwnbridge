# Audit Decisions

Append-only record of non-trivial design and compatibility decisions.

## 2026-07-22 — Treat both SSH master startups as one diagnostic boundary

The pre-existing removal of `-q` from shared-master startup is completed across the session-scoped master in the same change. Both paths already collect and bound stderr specifically to return actionable startup errors; retaining quiet mode in either path defeats that contract. Quiet mode remains on health-check and shutdown control operations, whose expected failures are intentionally not surfaced.

## 2026-07-22 — Reject known-vulnerable build toolchains at startup

The Go module retains its compatible, fixed Go 1.25.12 language/toolchain floor instead of unnecessarily dropping the supported 1.25 line. Because Go's module version ordering cannot express “1.25.12 or 1.26.5” and accepts vulnerable 1.26.0–1.26.4 as newer, both the client and agent check their embedded runtime version before doing any work. Known affected official versions fail closed with rebuild guidance; unrecognized development/vendor version strings remain allowed because their patch ancestry cannot be determined reliably from the string alone.

## 2026-07-22 — Publish create-only files with same-directory hard links

Create-only CLI outputs are first written, permissioned, and synced in a temporary file beside the destination, then published with `link(2)`. A hard link fails atomically when any destination entry already exists, avoiding the check-then-rename overwrite window while preserving the complete-file visibility and same-filesystem durability properties of `AtomicWrite`. The temporary link is removed and the directory chain is synced after publication. This needs no dependency and works on the supported macOS client filesystem boundary.
