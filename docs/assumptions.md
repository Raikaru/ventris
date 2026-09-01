# Assumptions and defaults

Recorded per spec rule 7 (make a reasonable default, document it, continue).

- **Project prefix `lre`, repo name ventris.** Public product name is a
  later decision (spec licensing rule 8).
- **Ghidra install location:** `$VENTRIS_GHIDRA`, then
  `~/ghidra_12.1.3_PUBLIC`. Verified with JDK 25.
- **Project store:** `project.sqlite` (WAL, foreign keys ON,
  `schema_version=1`) inside `--project DIR`. Bridge projects live under
  `DIR/bridge-projects/` — disposable Ghidra projects, not the source of
  truth.
- **Session naming:** CLI uses `main` for import and `cli-<program>` for
  per-command bridge sessions.
- **Address strings:** canonical Ghidra hex (`00400466`) as the wire
  format; the typed `Address{space, offset}` model exists in lre-model but
  Stage 1 only materializes `ram`.
- **Xref export scope:** outgoing refs of every function body (all
  instruction addresses). Data xrefs to non-function addresses arrive with
  the native analysis path (Phase 4+).
- **One bridge process per project** (Ghidra project lock is
  single-writer). Multiplexing deferred until measured (spec 14.3).
- **JVM heap cap:** not yet set (spec 14.3 wants a measured cap; pending
  baseline experiments).
