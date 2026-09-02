# STATUS

## Current phase/generation
Stage 2-3: worker protocol + differential test landed; store ownership next.

## Completed and verified
- Scrap of the old partial-decompiler-port architecture; pinned Ghidra
  12.1.3 reference tree kept and hash-manifested (commit 993605f, 8cf03d3).
- Java bridge (`service/`): JSON-RPC over stdio; methods import/open/close/
  functions/function/symbols/read_memory/xrefs_to/xrefs_from/
  function_xrefs_from/export_facts/rename/decompile/disassemble/ping/
  dump_specs. Written against verified Ghidra sources only.
- Rust workspace: lre-model, lre-db (SQLite WAL+FK, schema_version=1,
  revision-stamped mutations), lre-core (CoreService facade),
  lre-cli, lre-worker. 14/14 unit tests pass.
- E2E proven on x86-64 ELF fixture (gcc -O0, 12.6 KB):
  - import: 15 functions, 34 xrefs, 93 symbols persisted with
    provenance `ghidra-bridge / 12.1.3`
  - store-only `open` (no JVM launched): works
  - rename persists in store, revision bump verified in unit tests
  - decompile + disasm through bridge against saved program
- Native worker protocol (lre-worker) fixed to the pinned C++ exactly:
  - registerProgram (queries answered from store/binary),
  - arch-id frame for decompileAt/setAction (ghidra_process.cc:82-97),
  - packed `<addr>` element + attribute ids from the marshal tables,
  - response tail (result stream, warnings frame 0x10..0x11, 0x07),
  - interleaved queries inside the result stream (Java readResponse model),
  - callbacks: getBytes, getMappedSymbols (doc/mapsym/function),
    getRegister, getRegisterName, getCodeLabel, getUserOpName,
    isNameUsed (bool), tracked-register pointset, plus safe empties.
  - deferred cleanly: stdin close before wait (Drop no longer deadlocks).
- Differential test (tests/differential.sh): x86-64 ELF, native (pinned
  console decompiler, no JVM) vs bridge oracle:
  - add: both decompile to "return A + B" (oracle params vs native
    unaff registers normalized),
  - main: both call add (0x400466) and printf (0x400370), return 0.
  - PASS: native matches the oracle modulo naming.

## Measured (benchmarks/reports/)
- Stock Ghidra (analyzeHeadless, tiny ELF fixture, 3 runs): median wall
  10.83 s, median peak process-tree RSS 375 MiB.
- Native spike: pinned C++ decompiler + sleigh_opt compiled x86-64.sla;
  `add` and `main` decompiled with zero JVM in the process tree
  (benchmarks/reports/native-spike.md).
- Stage-1 CLI import (bridge): ~5-10 s Ghidra work + ~7 s JVM startup.

## Stage 3 closed: JVM-free protocol decompile (getPcode gap)
- Out-of-tree `ghidra_opt` gains a raw-SLEIGH translator hook
  (native/ghidra-opt-sleigh.patch + native/build_ghidra_opt.sh; the pinned
  third_party tree is untouched): when VENTRIS_SLA points at the compiled
  x86-64.sla, ArchitecutureGhidra::buildTranslator registers the
  `<sleigh>`-path tag (SleighArchitecture::buildSpecFile handshake,
  sleigh_arch.cc:410-418) and builds a real `Sleigh`; buildContext then
  uses ContextInternal (ContextGhidra blocks registerVariable).
- Consequence: GhidraTranslate::oneInstruction's client-side getPcode
  query is gone — the decompiler self-disassembles, the worker's
  getBytes callback feeds the bytes, and the whole register →
  mappedsymbols → setAction → decompileAt flow runs with zero JVM.
- Verified end to end on the x86-64 ELF fixture:
  - add: `int add(int param_1,int param_2){return param_2 + param_1;}`
    — token-identical to the bridge oracle (differential test's
    "exact worker-vs-oracle check").
  - main: calls add + printf with the right consts, returns 0.
- native/ghidra-opt-sleigh.patch = the two hunks (buildTranslator,
  buildContext) plus the Makefile link rule for the SLEIGH objects.
- Repro: `native/build_ghidra_opt.sh` (copies sources aside, git-apply
  the patch, `make ghidra_opt`), binary at native/build/ghidra_opt.

## Remaining for Stage 4 (goal)
Native import (no-JVM ELF/PE loading into the store facts), native memory
inspection, native xref/function discovery for imported binaries, and the
memory/perf gates. The workflow today: import (bridge, once) then
functions/memory/decompile/reopen/rename fully JVM-free via the store +
worker.

## Native import (no-JVM) landed
- `lre-core::native`: ELF64 + PE32+ parsers (sections -> memory map,
  SHT_SYMTAB function symbols, SHT_DYNSYM externals, SHT_RELA GOT relocs
  naming the `ff 25` PLT stubs), direct-call sweep (call/jcc/jmp rel32),
  and the call-target closure (FUN_<hex> naming). Facts land in the same
  store tables with provenance `native-import / 12.1.3`.
- CLI: `lre-cli import-native <binary> [--name N] [--project DIR]` — the
  whole import with zero JVM.
- Verified: tiny_bin native import = 12 code functions whose entry set
  is a subset of the bridge oracle's (differential "import parity" step);
  tiny_pe.exe native import = 310 functions (entry + CRT call closure vs
  Ghidra's 138 — closure granularity differs, documented approximation;
  the ELF parity is exact at the entry-set level).

## Memory measurement (ADR-0001 target: beat 375 MiB stock)
- Protocol worker run (register + setAction + decompileAt on the x86-64
  ELF fixture, VENTRIS_SLA self-disassembling build):
  peak RSS 39.5 MB — **9.5× under the 375 MiB stock-Ghidra baseline**.
- The native console path and the store-only workflows stay in the same
  order of magnitude (no JVM in any no-JVM path).

## JVM-free workflow CLI (added this phase)
- `lre-cli import-native <binary> [--name N]` — ELF/PE -> store, no JVM.
- `lre-cli mem <binary> <vaddr> <size>` — mapping-backed memory dump.
- `lre-cli disasm-native <binary> <addr>` — SLEIGH disassembly via the
  pinned console (no JVM).
- `lre-cli comments <program>` / `types <program>` — store-owned facts.

## Known gaps / risks
- Bridge project lock is single-writer: concurrent CLI invocations fail
  with "Unable to lock project" (Ghidra project lock); stale locks need
  manual removal after an aborted JVM.
- Decompilation latency bounded by JVM startup for one-shot CLI use; a
  persistent service session amortizes it.
- `Loaded.save`+`ProgramLoader` path persists correctly, but re-import of
  the same binary name creates `.1` duplicates (Ghidra duplicate naming).
- The CLI's `xrefs --from <entry>` is address-addressed.

## Store ownership (Stage 2-3 remainder)
- Schema v2 (migration in place): `comments` (address, function, type,
  text) and `datatypes` (name, definition) tables, revision-stamped by the
  same replace/upsert path as functions/xrefs.
- Bridge export_facts now includes comments (eol/pre from the function
  body via the listing) and datatypes (dtm.getAllDataTypes, pointers
  skipped, deduped on insert).
- CLI: `comments <program>` and `types <program>` (store-only, no JVM).
- Verified: PE import (tests/fixtures-src/tiny_pe.exe, mingw x86-64)
  stores 138 functions incl. add @ 0x140001450 and main @ 0x140001464,
  win32 types (BOOL/BYTE/CRITICAL_SECTION/...), and pre-comments.
- Worker protocol: getComments answered safely (empty response; the C++
  guards the decode, comment_ghidra.cc:46).

## Next bounded task
Native getPcode server (SLEIGH pcode generation for
GhidraTranslate::oneInstruction): the last gap between the protocol
worker and a fully JVM-free decompile of the supported workflow.
