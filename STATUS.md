# STATUS

## Current phase/generation
Stage 4: JVM-free supported workflow closed and gated (39.6 MB peak vs 375 MiB stock;
see gate numbers below and benchmarks/reports/stage4-gate.json).

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

## Stage 4 closed (this phase)
- CLI `decompile-native <binary> <addr> [--name P] [--project DIR] [--base HEX]`:
  the supported no-JVM decompile route. Spawns `lre-worker` against the
  patched ghidra_opt (env VENTRIS_GHIDRA_OPT, default native/build/ghidra_opt)
  with vendored specs (native/specs) and the store project. Verified
  token-identical to the bridge oracle (`int add(int param_1,int param_2){
  return param_2 + param_1;}`) — differential step "CLI decompile-native".
- `native/build_console.sh`: reproducible SLEIGH console build (needs
  binutils-devel/bfd.h, Ghidra's own native-build prerequisite; the bfd-less
  spike binary predates the pinned tree). Console env defaults now derive
  from the Ghidra install (VENTRIS_GHIDRA) instead of /tmp/spike.
- `benchmarks/gate.sh`: full JVM-free workflow gate (import-native ->
  functions/xrefs/rename/open -> disasm-native -> decompile-native),
  per-phase peak RSS + total wall; asserts < 100 MB and < 120 s.
  Result on the tiny ELF fixture: peak 39 920 KB, median wall 0.32 s (3 runs) —
  9.5x under the 375 MiB stock baseline (benchmarks/reports/stage4-gate.json).
- Bridge robustness: null CodeUnit guard in export_facts comments
  (Dispatcher.getCommentAddressIterator can yield addresses with no code
  unit; the NPE aborted bridge imports).
- Bridge lifecycle fixes (service/ + bridge.rs):
  - `shutdown` method in the service (the CLI's shutdown RPC used to hit
    "unknown method", then child.wait() blocked on a JVM whose read loop
    never saw EOF — the import CLI hung >120 s at exit).
  - The bridge closes its stdin pipe before waiting, so an unresponsive
    service can't stall the CLI.
  - Session.close releases only import-flow programs (open-flow programs
    are released by GhidraProject.close; releasing them first threw
    "unknown consumer" at every shutdown).
  - GhidraBootstrap.shutdown skips GhidraProject.close: import-flow
    programs register the bootstrap consumer, so the project's own
    release throws; the process exit releases the project lock anyway.
- Differential fixes: dump_specs now runs after the import (ordering bug
  on fresh runs), stale project locks are removed at the start, and the
  CLI decompile-native check compares token-identical content (the
  worker's C text carries no layout whitespace).
- Final differential (2026-09-02): PASS — protocol worker and CLI
  decompile-native token-identical to the oracle; native import parity
  11/11; stripped CLI discovery 7/7 subsets of the oracle; add/main
  semantic parity.

## QA-003 corpus matrix: earned its keep
- `tests/corpus.sh`: builds and imports plain C (O0/O2), PIE, C++ (exceptions
  + TLS + switch), and a 400-function binary; writes
  benchmarks/reports/corpus.json. Result: 5/5, **many_o2 = 406 functions**.
- The matrix immediately found a critical decoder default bug: `op_info`
  assumed no ModRM for unlisted opcodes, but most one-byte opcodes (01 add,
  03 or, all /r forms...) carry one — `add eax,ebx` decoded as 1 byte and
  misaligned every walk past the first arithmetic instruction (main of the
  400-fn fixture stopped after its first call). Fixed: default ModRM, with
  an explicit no-modrm set (push/pop, nop/xchg, cbw-family, enter/leave,
  aam/aad, loop, int1, clc-family, movs/cmps). Regression tests:
  `main_prologue_lengths` (1,5,5,2,5,5,2) and the existing suite.
- Also fixed: last-function size cap used `start+16` as the fallback
  "next entry" — capping proven bodies at 16 bytes for the final function
  of a section; now uses the end of the current map.

## CORE-001: typed address migration
- Model rows now carry `Address { space, offset }` (FunctionRow/SymbolRow/
  XrefRow/CommentRow/DisasmRow); strings exist only at serialization edges:
  lre-db (hex TEXT columns, `addr_cell`/`addr_from_cell`), the JSON-RPC
  bridge (tolerant `parse_rows`: rows with unsupported-space addresses
  — e.g. Ghidra stack comments `Stack[-0x10]` — are skipped with a count,
  not silently mangled or import-aborting), and the CLI (argument parsing).
- `Address` has a custom `Deserialize` (hex string OR `{space, offset}`;
  last-colon split for overlay names like `.annobin.notes::00000000`) and
  `Display`/`hex()`.
- API: `Core::{xrefs_to, xrefs_from, rename_function}` take typed
  `&Address`; `lre-db` same; the worker consumes `f.entry.offset` directly.
- Verification: 34 workspace tests; differential RC=0 (bridge boundary
  exercised through import + oracle steps); CLI e2e (functions/xrefs/rename)
  clean; corpus 5/5.

## Phase 1 correctness closure (review batch)
- CORE-008 shape: SLEIGH-first discovery — with the pinned console present,
  its disassembly is the primary flow source (unioned with the in-Rust
  two-path walk, which is now explicitly the fallback/cross-check; the
  handwritten decoder is no longer the sole production source).
- Conservative function bodies: the walk records each function's proven
  extent (span of decoded instructions, stop-based) capped at the next
  entry's distance; flow_discover uses those sizes instead of the
  always-distance-to-next fiction. tiny_stripped: `_entry` 38 (was 64),
  `0x4003c0` 33 (was 112), `0x400430` 33 (was 48) — walk-verified bodies.
- QA-002 fuzz smoke: deterministic malformed-input loop (truncated/
  magic-only/absurd-section-table ELF+PE + decode over byte soups) — no
  panic, typed errors (19 lre-core tests incl. this).
- PIE evidence: gcc `-fPIE -pie -O2 -s` executable imports natively
  (11 functions; entries include `_entry` 0x800 with the RDI convention;
  zero-based vaddrs like ET_DYN). Remaining (QA-003 corpus): oracle
  differential on PIE binaries is part of the matrix work.
- Differential policy (QA-004): comparisons are categorized —
  exact (byte/whitespace-normalized token identity: worker + CLI
  decompile-native), semantic (add/main A+B and call targets), subset
  (native entries ⊆ oracle), skipped (console-dependent, explicit note).
  No claim mixes categories.

## Sessionful runtime foundation (review Phase 2 start)
- `lre-core::session`: `RuntimeConfig` (immutable; env-derived defaults, the
  internal contract services take — native_runtime migration continues),
  `MemoryRegion { vaddr, size, file_off, file_size, flags }`,
  `ProgramImage` (one read-only `memmap2` mapping + regions + sparse patch
  overlay; BSS zero-fill bounded by `file_size`), `ProgramSession`
  (program name + `Arc<ProgramImage>` + metadata with language/format/image
  base).
- `Core::open_session` (map-once) and `Core::mem_native` now served from a
  cached `ProgramImage` — repeated reads no longer re-read, re-parse, or
  re-discover the binary (review CORE-002 / 4.8).
- New dependency: `memmap2` (safe `Mmap`; the one reviewed FFI-adjacent
  site, read-only mappings only).
- Tests (18 lre-core, 32 workspace): region file-byte reads, BSS zero-fill,
  patch overlay, unmapped/crossing reads, `RuntimeConfig` defaults, and
  `ProgramImage::open` against the real fixture (add's bytes at 0x400466).
- The environment-var contract inside `native_runtime` moves to accept a
  `RuntimeConfig` next (CORE-001 typed identity; CORE-004 paging...), per
  the ratified 9-phase roadmap.

## Post-review hardening (facade contract + real-binary evidence)
- Native paths moved into the Core facade (review: "a GUI can't reuse the
  native decompile/disasm without copying lre-cli's spawn logic"): new
  `lre-core::native_runtime` + `Core::{import_native, disasm_native,
  decompile_native, mem_native}`; lre-cli is now a thin delegate (same
  methods a GUI consumes). `decompile-native` validates VENTRIS_SLA
  existence — a missing .sla used to surface as a silent "no architecture
  registered" decompiler exception.
- Typed address accessors on the model rows (FunctionRow::entry_addr,
  XrefRow::{to_addr, from_addr}, Address::parse_ram_hex/hex) — the storage
  stays canonical hex strings, consumers get typed values.
- Durable-store dedupe: replace_functions/symbols/xrefs now dedupe within
  a batch — libc's versioned exporter aliases (memcpy/__GI_memcpy broke
  the UNIQUE index on the bridge import of libc.so.6).
- **Real-binary sample (`/usr/lib64/libc.so.6`, 2.48 MB, stripped)**:
  native import recovers 3,999 functions in 0.54 s (dynsym exports +
  init/fini arrays + flow closure; no console rounds); the Ghidra-oracle
  bridge import recovers 3,987 in ~2 min — count parity within 0.3%.
  Same-function decompile (`asprintf`): native and oracle both produce
  the full 1.4 KB C bodystructurally; the delta is naming/type knowledge
  (oracle: `__ptr`/`__fmt`/`iVar1` from libc type info; native: generic
  `param_N`/stack names). That is exactly the analysis-depth trade the
  review called: the native path brings no Ghidra knowledge, only the
  same decompiler.
- **Address-base note**: Ghidra rebases ET_DYN imports to image base
  0x100000 (asprintf at 0x135b40) while the native import is zero-based
  (0x35b40) — same bytes, different space convention; document for
  cross-tool comparisons.
- Environment: the SLEIGH console (native/build_console.sh) needs
  binutils-devel (bfd.h) which is not installed here; console-dependent
  test steps are skipped with an explicit note, worker/CLI parity runs
  unconditionally.
## Second-review hardening (decoder/parser correctness, gate honesty)
- Decoder fixes with regression tests (all in `short_branch_and_no_modrm_0f_lengths`):
  - short branches (EB/70..7F) read the displacement as ONE sign-extended
    byte; the old 4-byte reader included following instructions in the
    target (frame_dummy's `jmp -0x76` used to mislabel its target).
  - 0F opcodes without ModRM (syscall, rdtsc/cpuid, bswap, emms, ...) no
    longer take a phantom ModRM byte (length 2, not 3+).
  - F6/F7 group: the immediate exists only for the TEST form (modrm ext 0);
    NOT/NEG/MUL/DIV no longer gain 1/4 phantom bytes.
- PE: executable classification now tests IMAGE_SCN_MEM_EXECUTE only
  (0x20000000); the old mask OR'd in MEM_READ and classified readable data
  sections as code (regression `pe_exec_requires_execute_characteristic`).
- ELF: a magic-only/truncated header returns a typed error instead of
  panicking on `data[4]`/`data[5]` (`truncated_elf_magic_errors_not_panics`).
- Discovery: the walk became genuinely two-path (conditional branches
  explore the taken edge and resume the fall-through from an explicit
  stack). The decoder fixes had dropped 0x4003c0 from the stripped fixture
  because dtors_aux's `jne` skipped the fall-through body containing its
  call; with both edges explored it returns (7/15, correct edges, not
  decoder luck). Regression `conditional_fallthrough_discovers_call_target`.
- `mem_native` no longer re-reads/re-discovers the binary per read (one-entry
  parsed-import cache).
- Gate honesty (review 4.13): `rss()` defined before use (console-present
  runs previously tripped `command not found` under `set -e`); reports now
  carry `complete`/`skipped`/`performance_pass`/`functional_pass` and exit 2
  on PARTIAL — an incomplete run can no longer read as PASS.
- `.gitignore`: volatile `benchmarks/reports/gate-run/` + run sqlite files.
- SECURITY.md: removed stale Python-wheel/VSCode claims from the scrapped
  project; documents the actual child-process and parser boundaries.
- libc function-set metrics (not count proximity): 3,930 common of
  native 3,999 / oracle 3,987; precision 0.983, recall 0.986; residuals are
  boundary/alias differences (e.g. native-only 0x774 `_dl_argv`-adjacent
  aliases vs oracle-only 0x7b0).


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

## PE parity closed
- PE32+ ImageBase fixed (PE32+ has no BaseOfData: ImageBase at optional+24,
  not +28) — the mingw fixture parses to the true base 0x140000000; worker
  --base matches; the section map (RVA -> raw) now feeds byte resolution.
- PE protocol worker: add == oracle exactly (`return param_2 + param_1`);
  main semantically identical (__main, add(2,0x28), printf+format addr,
  return 0). The differential's PE step checks add.

## Stripped-binary discovery (closed)
- In-Rust flow discovery: seed walk (symtab/dynsym, entry, externals) with
  direct call/branch closure, the ELF `_start` -> `__libc_start_main` RDI
  convention (mov rdi imm64/imm32, lea rdi [rip+disp32] scan), and
  init/fini-array function-pointer seeds.
- Fixed a pre-existing decoder bug: ModRM index for prefixed instructions
  (`m = p + len` read the wrong byte; REX-prefixed memory operands
  misaligned every walk) — regression test `prefixed_memory_lengths`.
- tiny_stripped (no symbols, no JVM): 7 functions recovered (__gmon_start__,
  _entry, frame_dummy, __do_global_dtors_aux, deregister_tm_clones, add,
  main) — every one in the Ghidra oracle's 15; the oracle-only remainder is
  indirect-only CRT and PLT shims (`register_tm_clones`, `_init`/`_fini`,
  0x404000+), outside the call-closure model by construction.
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
