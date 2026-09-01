# STATUS

## Current phase/generation
Stage 1 complete (Phase 1 + the store-ownership half of Phase 3 exit).

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

## Measured
- Import+analysis ~5–10 s of Ghidra work; JVM startup dominates (~7 s).
- No memory measurements yet (spec 21 baselines pending).

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
Phase 2: native loaders for ELF facts (17.1 order), or Phase 0 leftovers:
stock-Ghidra baseline benchmarks and the native-worker feasibility spike
(15.1) — the spike should come first since it gates the whole Stage 3 path.
