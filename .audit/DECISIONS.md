# Audit Decisions

Append-only record of non-trivial design and compatibility decisions.

## 2026-07-22 — Treat both SSH master startups as one diagnostic boundary

The pre-existing removal of `-q` from shared-master startup is completed across the session-scoped master in the same change. Both paths already collect and bound stderr specifically to return actionable startup errors; retaining quiet mode in either path defeats that contract. Quiet mode remains on health-check and shutdown control operations, whose expected failures are intentionally not surfaced.
