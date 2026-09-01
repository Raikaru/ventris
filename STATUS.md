# STATUS

## Current phase/generation
Stage 1.5 complete (Phase 0 leftovers closed: baseline + spike + ADR-0001).

## Completed and verified
- Scrap of the old partial-decompiler-port architecture; pinned Ghidra
  12.1.3 reference tree kept and hash-manifested (commit 993605f, 8cf03d3).
- Java bridge (`service/`): JSON-RPC over stdio; methods import/open/close/
  functions/function/symbols/read_memory/xrefs_to/xrefs_from/
  function_xrefs_from/export_facts/rename/decompile/disassemble/ping.
  Written against verified Ghidra sources only.
- Rust workspace: lre-model, lre-db (SQLite WAL+FK, schema_version=1,
  revision-stamped mutations), lre-core (CoreService facade),
  lre-cli. 7/7 unit tests pass.
- E2E proven on x86-64 ELF fixture (gcc -O0, 12.6 KB):
  - import: 15 functions, 34 xrefs, 93 symbols persisted with
    provenance `ghidra-bridge / 12.1.3`
  - store-only `open` (no JVM launched): works
  - rename persists in store, revision bump verified in unit tests
  - decompile + disasm through bridge against saved program

## Measured (benchmarks/reports/)
- Stock Ghidra (analyzeHeadless, tiny ELF fixture, 3 runs): median wall
  10.83 s, median peak process-tree RSS 375 MiB.
- Native spike: pinned C++ decompiler + sleigh_opt compiled x86-64.sla;
  `add` and `main` decompiled with zero JVM in the process tree
  (benchmarks/reports/native-spike.md).
- Stage-1 CLI import (bridge): ~5-10 s Ghidra work + ~7 s JVM startup.

## Known gaps / risks
- Bridge project lock is single-writer: concurrent CLI invocations fail
  with "Unable to lock project" (Ghidra project lock). One bridge per
  project is the Stage 1 contract; multiplexing needs measurement (14.3).
- The CLI's `xrefs --from <entry>` is address-addressed, not
  function-addressed; mid-body refs live under their instruction address.
- Decompilation latency bounded by JVM startup for one-shot CLI use; a
  persistent service session amortizes it.
- `Loaded.save`+`ProgramLoader` path persists correctly, but re-import of
  the same binary name creates `.1` duplicates (Ghidra duplicate naming);
  dedupe is a Stage 2 store concern.

## Next bounded task
Stage 2: extend native store ownership (comments, types, PE import) and
launch the native worker shell (protocol + program-provider callbacks per
spec 15.2), differential-tested against the bridge as oracle.
