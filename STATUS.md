# STATUS

## Current phase/generation
Stage 9 optional surfaces are implemented. Stage 4 remains the gated native
workflow baseline (39.6 MB peak vs 375 MiB stock; see gate numbers below and
`benchmarks/reports/stage4-gate.json`).

## Current implementation surface

- Phases 5–7 are implemented in `lre-core`, `lre-api`, the Qt workstation
  source, and `python/`: symbols/strings/search, memory and graph views,
  bookmarks/patches, typed data manager and propagation, a versioned
  stdio/HTTP API, a dependency-free SDK and console, an isolated
  permissioned plugin host, and an AI tool adapter.
- Phase 9 surfaces now include isolated GDB/LLDB read backends, a read-only
  Dolphin GDB-RSP memory client for the live overlay, durable trace timeline
  events, and a deterministic, idempotent collaboration operation log exposed
  by Core/API/Qt/SDK.
- Native ELF structural import selects Ghidra language ids for x86-64,
  AARCH64, ARM, MIPS, RISC-V and PowerPC. ELF/PE discovery now uses the generic
  SLEIGH worklist; without the console, only structural facts remain. Worker
  verification covers x86-64 and the Agent Under Fire PPC e500 target.
- `lre-cli architectures --project DIR` scans the installed `.ldefs` catalog.
  Non-x86 native decompile parity is not claimed without a matching compiled
  SLEIGH language and normalized specification bundle.
- `desktop/ventris-qt` has CPack TGZ packaging. `packaging/sbom.py` emits an
  SPDX 2.3 SBOM; `update_manifest.py` and `verify_update.py` produce and
  validate release artifact metadata.
- `.github/workflows/ci.yml` is the cross-platform build/test definition.
  The Qt 6 development files are available on this workstation; the Qt
  configure, target build, and offscreen launch smoke path run locally.

## Completed and verified
- Scrap of the old partial-decompiler-port architecture; pinned Ghidra
  12.1.3 reference tree kept and hash-manifested (commit 993605f, 8cf03d3).
- Java bridge (`service/`): JSON-RPC over stdio; methods import/open/close/
  functions/function/symbols/read_memory/xrefs_to/xrefs_from/
  function_xrefs_from/export_facts/rename/decompile/disassemble/ping/
  dump_specs. Written against verified Ghidra sources only.
- Rust workspace: lre-model, lre-db (SQLite WAL+FK, schema_version=1,
  revision-stamped mutations), lre-core (CoreService facade), lre-cli,
  lre-worker, lre-worker-client, lre-api, and lre-debug. `cargo test
  --workspace`: 82 tests pass across 20 suites.
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

## CORE-006: command + undo journal
- `command_journal` table (schema v2, migrate): per-program monotonic seq,
  kind, JSON payload/undo_payload, done flag.
- lre-db composes command transactions: `rename_command` (rename + revision
  bump/event + journal push, one tx) and `undo_rename` (rename back + event
  + mark done, one tx); `journal_latest`/`journal_push`.
- Core: `rename_command` (captures prior name for undo) + `undo_last`
  (dispatches on kind; rename undo verified). `rename` (CLI) now goes
  through the command path; new CLI `undo <program>`.
- E2E: rename my_add -> undo -> add; second undo reports "nothing to undo";
  journal shows (1, rename, done=1, payload).
- Test `rename_command_undo_roundtrip`. 37 workspace tests.

## CORE-005: revision/event model
- `revision_events` table (schema v2, created by migrate): every mutation is
  transactional with a revision bump + an event row (kind/detail).
- Wired: rename ("rename" + new name) and all five replace_* paths
  ("replace-functions"/"replace-symbols"/"replace-xrefs"/
  "replace-comments"/"replace-datatypes" + row count). rename_function is
  now transactional.
- `lre-model::RevisionEvent { revision, kind, detail }`; store
  `events_since(program, since)`; `Core::events_since`.
- Evidence (native import + rename, real store):
  (2, replace-functions, 11), (3, replace-xrefs, 3), (4, rename,
  renamed_add) — strictly increasing, observable windows.
- Tests: `revision_events_recorded` (kinds, revisions, since-windows);
  paged test updated for bump semantics. 36 workspace tests.

## CORE-004: paged query API
- `lre-model::Page<T> { rows, offset, total, revision }`; store methods
  `functions_page`/`symbols_page`/`xrefs_page` (LIMIT/OFFSET windows +
  COUNT + revision); Core exposes the same three.
- CLI: `functions --offset N --limit M` proves the window path (header
  prints the window, total, and rev); default remains the full list.
- Test: `paged_functions_window` (100 rows; 10-row windows; boundaries;
  revision 1).
- 35 workspace tests.

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
- `lre-core::native`: ELF64 + PE (PE32/PE32+) parsers (sections -> memory map,
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

## UI roadmap (2026-09-02, v0.5.0)

Phases 0-3 of the desktop roadmap are implemented and tagged `v0.5.0`
(31 commits, qt-001..qt-021 + core-008..core-011). Phase 0 split the
1,914-line `main.cpp` into one file per class with typed views; Phase 1
finished the core loop (server-side filter/sort on `functions_page`,
inline rename + undo, virtualized listing over core-007 windows with
operand jumps and a context menu, paint-based token decompiler with
hit testing and a revision-keyed cache, two-tab xrefs with containing-
function resolution, go-to dialogs, per-project session persistence);
Phase 2 added BB-graph extraction + layered layout in core, a
virtualized hex canvas with pointer detection, paged strings, and job
surfacing with cancel; Phase 3 added themes, the command palette,
project management, the first-run gate dialog, and CPack packaging.

Verified on this machine: libc (2.48 MB) imports in 4.5 s with 4,023
functions; server-side filter answers in 20-30 ms; listing windows and
decompilation render (malloc_printerr decompiled JVM-free); the Qt app runs
the libc project offscreen without crashing; `cargo test --workspace` is
green (82 tests across 20 suites); the CPack TGZ builds.

- Engine-gated progress:
- WorkerPool is wired through API and Qt `decompile_doc`; `jobs_page`
  reports bounded job rows, idle/busy workers, restart count, configured
  memory cap, and memory-cap hits. The x86 tiny API smoke returned a
  succeeded row with one idle worker; a `/bin/false` worker smoke returned
  a failed row with `restarts=1`.
- Listing rows now carry explicit `function_header`, `bb_separator`, `label`,
  `data`, and `instruction` kinds from the core model. The parser acceptance
  fixture covers all five kinds; native console smoke emitted four basic-block
  separators, the API default-overscan smoke returned structural rows, and
  the Qt target built and launched offscreen without a crash.
- UI gate baseline (`benchmarks/reports/ui-gate.json`) now records the
  frozen II.2 schema and three-run libc metrics on a clean package install:
  load 9.648 ms, filter 4.762 ms, sync 2.216 ms, graph layout 11.571 ms,
  graph paint 7.891 ms, and install.ok true. All six UI metrics pass their
  frozen thresholds (`passed: true`).
- m0-002 instrumentation now records all six frozen UI fields on libc
  (`ui.list.load_ms`, `ui.list.filter_ms`, `ui.sync_ms`, `ui.graph.layout_ms`,
  `ui.graph.paint_ms`, and `ui.install.ok`); the acceptance smoke confirms
  every field is non-null.
- Phase 4 (game-first surfaces): the target arrived (007 Agent Under
  Fire, GameCube GQFE78). ELF32 BE PowerPC import landed (644 functions
  with symbols from base.elf), the first two Phase 4 surfaces ship
  (signature search + vtable recovery, core-012/qt-022), and PPC
  decompile parity is DONE (core-013): the decompile path resolves the
  SLA, language dir, and spec bundle from the program's stored language
  id; the PPC e500 bundle is vendored; base.elf __start decompiles
  JVM-free with zero configuration. x86 unchanged.
  - Prototype injection is complete: the worker sends a packed function
    shell, the native command parses and applies the full C prototype to
    `FuncProto`, renames the loaded function, clears analysis, and the
    Agent Under Fire PPC target smoke renders the edited name and params.
  - Live-target memory overlay is complete at the transport, Core/API,
    and Qt layers: `lre-debug` implements read-only GDB RSP memory reads,
    Core reuses a bounded connection, and the hex canvas exposes a live
    endpoint toggle and source marker. A deterministic local RSP server
    verifies acknowledgements, checksum rejection, target errors, bounds,
    connection reuse, and the two-byte read path. A real Dolphin validation
    now also passes: Dolphin 2606a, headless `Null` backend, and the Agent
    Under Fire RVZ served GDB port 24689; `memory_live` read 16 bytes at
    `0x80000000`, beginning with `47 57 37 45 36 39` (`GW7E69`).

- m0-003: added `lre-cli graph <program> --largest --binary <path>` locator
  which sorts recovered functions by size descending, analyzes their native
  basic-block graphs, and returns the target function with >= 200 blocks
  (found `__vfscanf_internal` at `00042cb0` with 297 basic blocks on libc).
  The acceptance smoke `tests/largest_graph.sh` passes against `/usr/lib64/libc.so.6`.

- m0-004: measured and verified Qt layout/paint execution on the largest-BB graph
  (`__vfscanf_internal` at `00042cb0`, 297 blocks). Pre-resolved edge node indices
  in `GraphCanvas` to eliminate repeated quadratic string scans, accelerating paint
  >3x (paint: ~9.1ms vs 50ms threshold, layout: ~11.9ms vs 200ms threshold), and
  streamlined view address synchronization (`ui.sync_ms` down to ~2.4ms vs 16.0ms threshold).
  The acceptance smoke `tests/largest_graph_qt.sh` passes against `/usr/lib64/libc.so.6`.

- m0-005: decoupled auxiliary panel loading from `FunctionTableModel::refreshed`
  into `loadProgramPanels()`, eliminating queue contention in `CoreBridge` during
  filtering. `ui.list.filter_ms` on fresh libc imports dropped from ~416ms to 5.69ms
  (median of 3 runs, threshold 100.0ms), and `ui.sync_ms` reduced to 2.15ms (threshold 16.0ms).
  The acceptance smoke `tests/filter_latency.sh` passes against `/usr/lib64/libc.so.6`,
  and `benchmarks/reports/ui-gate.json` now records all 5 numeric metrics passing.

- m0-004: added package installation smoke test `tests/package_install_smoke.sh`
  building the CPack release archive, extracting to a clean prefix, and running
  the gate on libc with install evaluation enabled. All six metrics pass within
  thresholds (`ui.install.ok: true`, `passed: true`). Final README matrix
  citation is deferred until verified on three-OS CI.

- m0-007: recovered RIP-relative data xrefs (`InstrInfo::rip_data` over `[rip + disp32]`),
  full near/short conditional branch kinds, and CRT helpers (`_init`, `_fini`, and
  relative relocation function pointers like `register_tm_clones`) in the native import
  pipeline. Recovered 11,282 `DATA` xrefs on libc and all 4 xref kinds on tiny_bin.
  The acceptance smoke `tests/data_xrefs.sh` passes.

- m0-009: added `CONTRIBUTING.md` with explicit clean-room policy (no proprietary
  or leaked material; citation rules; docs/third-party.md) and gate-file rule.
  Updated `AGENTS.md` with the verbatim Section II.0 operating loop and Section
  II.1 human reservations. Added CI check (`tests/agents_policy_test.py`) in
  `.github/workflows/ci.yml` asserting the verbatim loop is present. Acceptance
  smoke `tests/agents_policy_test.py` passes.
- m0-006: split `main_window.cpp` from 2,195 lines down to 377 lines (<= 400 lines)
  across 10 modular dock classes (`functions_dock`, `decompiler_dock`, `facts_dock`,
  `memory_dock`, `graph_dock`, `analyst_dock`, `types_dock`, `xrefs_dock`,
  `jobs_dock`, `vtables_dock`) and extracted `gate_runner`. App behavior
  unchanged per m0-001; acceptance smoke `tests/main_window_split_test.py` passes.

- m0-010: added `scripts/gen_support_matrix.py` to regenerate the README support
  matrix from committed gate files, preventing manual overclaiming; added CI
  staleness check and acceptance test `tests/support_matrix_test.py`.

## Current milestone
M1 — Discovery becomes generic

## M1 progress
- m1-003-d: benchmarked hand decoder vs console flow on libc and the x86-64 corpus.
  All corpus rows scored against unstripped symbol references (zero null metrics).
  On libc, hand achieves exact set equality against console flow (3,953/3,953),
  and against the Ghidra oracle libc recall is 0.991472. Median speedup on libc: 1.1964×.
  hand decoder is 1.2× faster than console (<2.0× threshold) even though set-metrics are equal against the oracle;
  decision: keep_disasm_rs: false; deactivated default hand-decoder production path (default = []).

- m1-005: implemented PE base relocations (.reloc directory 5, IMAGE_REL_BASED_DIR64/HIGHLOW),
  entry point calculation fix (opt + 16), strict PE machine/magic pair validation without mock fallbacks
  (PE32+ AMD64 0x8664/0x20b and PE32 i386 0x014c/0x10b; typed errors on truncated fields, parsing
  NumberOfRvaAndSizes before accessing directory 5 without requiring six directories), and durable
  store writes of relocated pointers as data xrefs with provenance (`native-import:pe-reloc`, independent
  of whether targets land in executable code). Extracted candidate filtering to pure helper
  `CandidateFilterContext` / `filter_candidate` with unit tests verifying rejection of internal and out-of-code
  candidates under `--no-default-features`. Containment uses actual flow-proven extents (`proven_bodies`
  tracked from instruction spans during BFS walk; size-1 stripped entries cannot disable containment;
  positive regression test confirms relocation-only code functions in gaps are promoted, descendant origins are canonicalized/reparented to merge full spans, and internal candidates reached via fallthrough/branches are reconciled/dropped while call targets remain separate). Console-only path explores
  trusted seeds first and rejects relocation candidates already visited inside those bodies. Guarded x86-64
  hand decoder against x86-32, propagating detected language into `ConsoleSession` and BFD selection (`pei-i386`),
  routing PE32 through console-backed flow confirmation. Restored deterministic console child process cleanup
  via `impl Drop for ConsoleSession`. Restricted `close_call_targets` strictly to call xrefs (never branches or DATA).
  Added real 32-bit x86 PE32 test fixture (`tests/fixtures-src/tiny_pe32.exe`) testing language (`x86:LE:32:default`),
  ImageBase (`0x400000`), entry point (`0x401400`), HIGHLOW relocations, data xrefs, and discovery using CARGO_MANIFEST_DIR.
  Added load_native regression proving a PE32 data-to-data relocation remains an xref and never becomes a function.
  On `tiny_pe` unstripped twin (123 oracle symbols): 33 discovered, overlap 33, p=1.0000, r=0.2683;
  on `dispatch` unstripped twin (125 oracle symbols): 35 discovered, overlap 35, p=1.0000, r=0.2800.
  Acceptance tests `tests/m1-005_pe_relocs.sh` and `tests/m1-003_benchmark.sh` pass (PASS).
- m1-003-f: hand decoder candidate pre-pass confirmed by batched flow; achieves
  fn.precision=1.0000 and exact set equality (3,953/3,953) on libc describing hand-versus-console
  parity (neither Bad nor Unimpl, with pad and body containment checks; no opcode blacklists).

- m1-003-e: implemented batched flow in the console (`flow <addr1> <addr2> ...`);
  console-path libc import runs in 3.56s (acceptance threshold < 5.0s, PASS).
- m1-004: implemented ELF PIE relative relocation discovery (SHT_RELA / R_*_RELATIVE
  and SHT_RELR packed relocations across architectures), image base selection
  via `elf_image_base` (minimum PT_LOAD vaddr or 0x100000/0x10000 default for ET_DYN),
  and durable store writes of relocated pointers as data xrefs with provenance (`native-import:elf-reloc`).
  Acceptance test `tests/m1-004_pie.sh` passes with fn.recall=1.0000 on both
  plain_pie (8/8 oracle functions) and relr_pie (12/12 oracle functions).
- m1-001: implemented native SLEIGH console request `flow(addr)` extracting
  {length, fallthrough, targets, kind} from p-code (BRANCH, CBRANCH, BRANCHIND,
  CALL, CALLIND, RETURN, FALLTHROUGH) across loaded architectures. Unit test
  `test_pcode_flow_x86_and_ppc` passes on x86-64 (`tiny_bin` return/fallthrough)
  and PowerPC (`base.elf` 0x80680000 fallthrough length=4 and 0x8068001c CBRANCH
  targets=[0x80680030]).
- m1-003-c: wired console flow path for x86-64 when `x86_decoder` is off.
  `sweep_calls_x86` and `flow_discover_x86` now use a persistent SLEIGH
  console session; the acceptance `tests/m1-003_x86_flow.sh` asserts
  fn.precision=1.0000 and fn.recall>=0.9965 against the hand-decoder
  baseline on /usr/lib64/libc.so.6. Result: precision=1.000000,
  recall=1.000000 (exact set equality 3,953/3,953), PASS.

## Sub-tasks (m1-003)
- m1-003-a: split `x86_decoder` feature and add failing acceptance test.
- m1-003-b: implement persistent SLEIGH console session for x86-64.
- m1-003-c: wire `sweep_calls` and `flow_discover` to use console flow when
  `x86_decoder` is off.
- m1-003-d: benchmark the two paths on libc and the x86-64 corpus and decide
  keep/delete `disasm.rs`.

## Known gaps
- Corpus-binary discovery vs unstripped symbols is far below the M1 threshold
  (cpp_o2 p=0.43 r=0.56, plain_o0 0.80/0.80).
- m1-008b (before m1-010): dump missed/extra entries for cpp_o2 and plain_o0;
  classify each as (a) reference noise Ghidra also omits, (b) reachable only
  via data pointers (vtables, init/fini arrays, function-pointer tables), or
  (c) unreferenced. Add seeds for (b): scan .init_array/.fini_array, and pointer-sized
  values in .data/.rodata/.data.rel.ro that land in executable sections and confirm
  via batched flow. Acceptance: cpp_o2 and plain_o0 recall >= 0.98 against the
  m1-007 Ghidra oracle.
- Commit rule note: commits `e0db463` (1,386 insertions) and `0dca6cd` (1,148 changed lines:
  919 additions + 229 deletions across generator, lockfile, gate, and report) exceeded the 800
  changed line limit; per II.0, recorded as acknowledged violations without history rewriting.

- m1-006: generated multi-architecture corpus across 4 target architectures (x86-64,
  x86-32, aarch64, powerpc) × 5 variants (plain_o0, plain_o2, plain_pie, cpp_o2, many_o2)
  = 20 binaries + 20 unstripped twins containing .symtab function symbols. Committed sources
  in tests/corpus-src/ (plain.c, src.cpp, many.c) and lockfile tests/corpus.lock.json (with
  zero host-specific absolute paths). Added scripts/gen_corpus.py with --architectures and
  --msvc-only support. Primaries derived by stripping copies of twins (via llvm-strip --strip-all
  or PE debug directory zeroing), ensuring bit-for-bit loadable code identity while stripped
  primaries lack .symtab and twins contain function symbols (plain_o0 stripped).
  Added machine 0x3 (EM_386) to elf_language in lre-core, enabling native ELF32 x86 import.
  All 20 binaries import cleanly natively: x86-64 (8..408 functions), i386 (6..13 functions),
  aarch64 (3..5 functions), and powerpc (9..408 functions). Gate outputs and import
  databases are temporary; source digests, artifact hashes, recipes, unique matrix entries,
  independently counted symbols, twin identity and native imports are checked.
  Committed report: benchmarks/reports/m1-006.json (local MSVC skips with reasons).
  Added dedicated Windows CI job (corpus-windows with MSVC activation) and Linux CI job (corpus-linux).

## m1-006 corrective sub-tasks
- m1-006-a: reject missing/duplicate entries; enforce recipes, hashes and isolated
  gate outputs; preserve the recipe schema in explicit lock updates.
  Acceptance: `tests/m1-006_integrity_test.py`.
  Verified: 3 integrity tests (8 manifest mutations), 97 workspace tests,
  legacy corpus 5/5 and m1-006 Linux corpus 20/20; only 5 local MSVC skips allowed.
- m1-006-b: replace C++ exception stubs with real cross-target runtimes; execute
  the exception/TLS fixture on supported hosts. Acceptance: corpus gate runtime checks.
  Verified: exception/TLS inputs execute on all 4 ELF targets (native x86-64,
  QEMU i386/AArch64/PPC32-BE), 8/8 expected outcomes. Corpus 20/20 imports;
  3 integrity tests, 97 workspace tests and legacy corpus 5/5 pass.
- m1-006-c: validate PDB streams, symbols and exact CodeView association; use
  the linker PDB. Acceptance: `tests/m1-006_pdb_test.py`.
  Verified locally: real LLVM PE/PDB pair exposes 2 function symbols; 7 PDB
  corruptions rejected (header-only, truncation, block reference, GUID, age,
  missing symbol stream, malformed record). MSVC uses a separate compiler PDB
  and explicit linker `/PDB`. CI run 33914542193 passed MSVC corpus and all
  Rust/Qt jobs; Linux exposed host loader-cache leakage under qemu-i386.
  Cross execution now sets the pinned target library path explicitly.
  Run 33914879326 then passed i386/AArch64 runtime checks but exposed a PPC
  C++ PIE fault, reproduced with Ubuntu 24.04 LLVM 18/QEMU 8.2. Explicit
  non-PIE C++ output passed both inputs; the `cpp_o2` ELF recipe now fixes
  that relocation model on every target. `plain_pie` is unchanged.
- Closed m1-006 corrections at `2ea65bac64eb5921fd5c2939e2d9ecabb2941db1`:
  [CI run 33915494027](https://github.com/Raikaru/ventris/actions/runs/33915494027)
  passed 9/9 jobs, including Linux corpus 20 entries, MSVC corpus 5 entries,
  Rust on 3 operating systems, and Qt packages on 3 operating systems.
  Normal local gate: exit 0; `git diff --exit-code`: 0; porcelain output empty.
  All corrective commits stayed below 800 changed lines. No m1-007 implementation
  or acceptance test was started in this session.

## m1-007 sub-tasks
- m1-007-a: failing acceptance, bridge image-base metadata and SHA-keyed oracle
  generator. Acceptance: `tests/m1-007_oracle_test.py`; all 20 ELF entries,
  cache reuse without Java, invalid-cache and missing-input rejection.
- m1-007-b: publish the five x86-64 oracle references.
- m1-007-c: publish the five i386 oracle references.
- m1-007-d: publish the five AArch64 oracle references.
- m1-007-e: publish the five PPC32-BE oracle references.
- m1-007-f: commit the generated report and verification evidence.
  Generated reference arrays are split by architecture to keep each commit
  below 800 changed lines. The existing libc reference is unchanged.
- Completed: 20/20 ELF references committed, 0 failed, 0 skipped.
  `benchmarks/reports/m1-007.json` was generated from implementation
  `dfed639191be266c07079231c03ff8ef8ee69c2d` and committed in `718128a`.
  Non-external function totals: x86-64 488, i386 505, AArch64 526, PPC32-BE 489.
  Each architecture has 5 SHA-keyed references; total 2,008 entries.
  Provenance includes Ghidra 12.1.3 revision, bridge source SHA-256, automatic
  language selection and image base. Addresses remain in Ghidra coordinates.
  Ghidra selected `PowerPC:BE:32:e500` for all 5 PPC inputs; no native language
  selection or frozen discovery metric was changed.
- Verification: `tests/m1-007_oracle_test.py` passes 4 tests, including 20 fresh
  imports, 20 cache hits without Java, 4 invalid-cache cases and missing-primary
  rejection. Published-cache `--check`: 20 hits, 0 generated, 0 skips.
  `cargo test --workspace`: 97 passed; `tests/corpus.sh`: 5/5 passed;
  README support matrix check passed. Artifact commits contain 573, 590, 611
  and 574 added lines respectively. Added a Linux CI oracle job using the
  SHA-256-verified official Ghidra release.

## Extracted-source tracking cleanup
- Human-requested maintenance; no milestone implementation changes.
- cache-a: ignore `/.ghidra-java/` and record this tracking-only cleanup.
- cache-b: remove the 5,382 extracted files from the Git index, retaining local
  bytes. This is a bulk generated-source deletion, not a source modification.
- cache-c: verify local hashes are unchanged and the pushed branch tree has
  no `.ghidra-java` entry. Historical commits remain unchanged.
- Local verification: all 5,382 files retained with identical SHA-256 hashes;
  0 files remain tracked under `.ghidra-java/`. The root ignore rule prevents
  re-adding the extraction during ordinary staging.

## m1-008 verified
- Test-first commit `5af21d9`: 5 language cases passed and the ARM BE8 case
  failed (selected `ARM:BE:32:v7` instead of `ARM:LEBE:32:v7LEInstruction`).
- ELF language selection now reads `e_flags`; ARM `EF_ARM_BE8` selects the
  pinned mixed-endian language. ELF32 i386, ARM LE/BE32 and PE32 selection
  remain unchanged. No corpus matrix or discovery metric was changed.
- `tests/m1-008_languages.py`: 6/6 passed, 0 failed, 0 skipped. It checks real
  compiler-produced ELF32 inputs, the existing PE32 fixture, an ELF64 control,
  installed `.ldefs`/SLA metadata and the native architecture catalog.
  Generated report: `benchmarks/reports/m1-008.json`.
- `cargo test --workspace`: 97 passed; legacy corpus: 5/5; m1-006 Linux corpus:
  20/20 (5 MSVC skips permitted on Linux). README matrix check passed.
  The existing Ghidra CI job also runs the language gate.
- CI run `33919780791` passed all ARM/PE language cases but exposed 2 x86
  probe link failures with Ubuntu LLVM 18: generic ELF targets routed through
  GCC's default PIE link. Both failures were reproduced; explicit Linux GNU
  targets with `-fno-pie -no-pie` passed both compiler checks. The corrected
  full local gate again passed 6/6; compiler stderr is retained on failures.

## m1-009 sub-tasks and oracle decision
- Human approved the real `sys/main.dol` with `files/boot.elf` as its oracle.
  All 644 function bodies and all 10 file-backed allocated sections match
  byte-for-byte at their original addresses. `base.elf` is a different build:
  only 44/644 function entry addresses overlap. Exact-address recall >=0.95
  is unchanged; no address normalization or oracle seeds enter discovery.
- m1-009-a: commit the failing real-DOL acceptance and this oracle decision.
- m1-009-b: parse DOL section mappings, preserve initialized data inside BSS,
  reject malformed ranges, and integrate the shared native mapping loader.
- m1-009-c: use the existing SLEIGH XML image loader and generic flow worklist
  for sparse DOL discovery; do not modify the pinned upstream tree.
- m1-009-d: commit the generated recall report, regression evidence and docs.

## m1-009 verified
- Acceptance test first: `56e8c31`; implementation: `f52d1f7`.
  Generated real-input report committed in `a874753`:
  `benchmarks/reports/m1-009.json`.
- Matching GQFE78 `main.dol` / `boot.elf`: 644 oracle entries, 699 native
  entries, 633 matches. Recall 0.982919 >= 0.95; precision 0.905579.
  There are 11 misses and 66 native-only entries; both lists are recorded.
  This passes the specified recall gate, not a broader precision/parity gate.
- All 10 initialized section mappings and BSS zero fill checked through
  the consumer memory API; malformed file ranges, address wrap and overlap
  rejected. Unit tests also cover initialized data inside BSS and invalid entry.
- Sparse XML loading uses the pinned console without upstream changes.
  SLEIGH direct calls and return-boundary candidates feed the generic worklist.
  Decoded instruction ranges, not distant-branch bounding spans, prove
  candidate containment. The focused gap regression failed before the fix.
- `cargo test --workspace`: 100 passed; no-default-feature core: 51 passed;
  `tests/corpus.sh`: 5/5; README support-matrix check passed.
  Actual DOL disassembly at `80680040`: `bl 80680154`, `bl 80680230`,
  `li r0,-1`. Rust formatting could not run: `rustfmt` is not installed.
- The private DOL/ELF pair is not redistributed; the real-input gate ran
  locally, not in CI. Missing inputs remain skipped/non-passing.
  `.rel` support is not implemented. No corpus or metric definition changed.

## m1-008b prerequisite investigation
- CI run `33923983804` for `6e1bae6` passed all 10 jobs.
- The recorded m1-003 gap concerns the x86-64 `plain_o0` and `cpp_o2`
  corpus variants. Acceptance `tests/m1-008b_pointer_seeds.py` scores the
  corresponding locked m1-006 inputs against unchanged m1-007 references.
  No cross-architecture gate claim or address normalization is introduced.
- Failing acceptance: plain_o0 10/15 (0.666667), cpp_o2 14/29 (0.482759);
  precision 1.0 for both, 0 native-only entries. Every missing entry is
  retained in the generated report.
- Fresh bridge imports identify 3 plain_o0 and 9 cpp_o2 oracle functions at
  `00204000` and above as external symbols outside the binary's allocated
  sections (including `__libc_start_main`, `__gmon_start__`, and `printf`).
  Code-entry recovery alone is capped at 12/15 and 20/29, below 0.98.
  The other misses include unreferenced code and PLT resolver paths, not just
  data-pointer seeds. No implementation or oracle changes have been made.

## Approved scoring contract (m1-008b)
- Human approved excluding positively identified Ghidra-created synthetic
  external placeholders from code-function discovery scoring. This is not
  blanket filtering by executable permissions or address-range membership.
- Keep executable PLT stubs, thunks and unreferenced code. Preserve raw
  `oracle/*.json` unchanged. Publish a separately versioned scoring view
  with the raw-reference hash, evidence and reason for every exclusion.
- Apply the rule consistently to all 20 ELF corpus entries. The m1-008b
  discovery acceptance remains the two x86-64 variants and recall >=0.98.
- m1-008b-a: failing scoring-view acceptance and policy edge cases.
- m1-008b-b: oracle-only evidence exporter and scoring-view generator.
- m1-008b-c: publish each corpus input's generated view as its own bounded
  artifact sub-task/commit: x86_64, i386, aarch64, powerpc, each with
  plain_o0, plain_o2, plain_pie, cpp_o2 and many_o2. Never rewrite raw refs.
- m1-008b-d: update discovery acceptance to the approved scoring view,
  then fix legitimate remaining misses without oracle-derived seeds.
- m1-008b-e: required gates, generated reports and final verification.

## m1-008b verified
- Test-first commits: `9cbe142` (scoring policy), `35e07be` (pointer flow),
  `e50bafb` (approved-score discovery). Implementation: `16555ca`, `9189859`.
- Generated reports committed in `1c0cd74`:
  `benchmarks/reports/m1-008b-scoring.json` and
  `benchmarks/reports/m1-008b-v1.json`, both naming implementation `9189859`.
  Historical failure/classification reports and raw `oracle/*.json` are unchanged.
- All 20 ELF scoring views: 2,008 raw functions, 1,903 scored, 105 positively
  identified synthetic external placeholders excluded. Every exclusion records
  loader/block/thunk evidence; each view includes raw-reference/exporter hashes.
  PLT stubs, thunks and unreferenced code remain scored. No permission-only or
  address-range exclusion is used.
- x86-64 plain_o0: 12/12 matches; cpp_o2: 20/20 matches. Recall and precision
  are 1.0 for both; 0 misses, 0 extras. Recall threshold remains 0.98.
  This is the two-input prerequisite gate, not cross-architecture discovery parity.
- Native discovery now retains dynamic-symbol index zero, reads ELF unwind
  function indexes and the PLT resolver entry, and flow-confirms initializer/data
  pointers. Candidate traversal follows indirect-call fallthrough. The broad
  linear-scan experiment was discarded; no oracle-derived seeds are used.
- Verification: workspace 102 tests; core no-default 53; core x86_decoder 54.
  Scoring acceptance 4 tests passed with 20 fresh temporary raw oracles and
  20 fresh evidence exports; committed raw bytes stayed unchanged. CI runs this
  isolated acceptance without depending on this workstation's compiler hashes.
  Legacy corpus 5/5; DOL remains 633/644 matches, 699 native entries; support
  matrix check passed. Isolated release libc import: 4,046 functions in 3.879 s
  (<5 s). A run overlapping Ghidra verification took 5.454 s; no performance
  claim is made for concurrent verification workloads. Rustfmt is unavailable.

## m1-010 sub-tasks
- Acceptance: `benchmarks/discovery_gate.py` writes
  `benchmarks/reports/discovery-gate.json`; exact function-entry precision and
  recall must both reach 0.98 on each of the 20 locked ELF inputs covered by
  m1-007 and scoring-v1. Missing inputs/oracles are skipped and non-passing.
  Raw references and the approved scoring policy remain unchanged.
- Existing libc performance and real-DOL recall checks remain regressions with
  their existing thresholds; this task does not redefine their metrics.
- m1-010-a: commit and run the failing all-input acceptance, retaining every
  missed/extra entry and checking that legacy ISA-specific discovery has left
  native.rs. The generic discovery module must contain no ISA-specific logic.
- m1-010-b: move the shared flow worklist into the generic discovery module.
- m1-010-c: remove legacy architecture-specific production discovery routes;
  any retained accelerator must be separate and equivalence-tested.
- m1-010-d: fix remaining M1 loader/seed/flow failures exposed by the gate.
  If an M2 analyzer is necessary, record it under Blocked on and stop.
- m1-010-e: required regressions, generated gate evidence and CI integration.
  Keep each commit below 800 changed lines; no milestone pass until all rows
  and the architecture check pass.

## m1-010 progress and sequencing blocker
- Failing acceptance committed first in `bc0e10f`; the complete initial
  20-input report was committed in `ea0fed1`. Shared flow worklist extraction
  committed in `9f9bcf9`: no algorithm or caller behavior changed.
- Gate results before/after extraction: 7 pass, 13 fail, 0 skipped.
  All four PIE inputs have zero exact-address overlap. Smaller i386/AArch64
  inputs miss functions; PPC also has native-only entries. Full address lists
  remain in `benchmarks/reports/discovery-gate.json`. The legacy-route source
  check still fails. M1 and m1-010 are not complete.
- Concrete later-milestone dependency: stripped `i386_plain_o0`, SHA-256
  `cea7cb1a23dbe84ab789761e612422415ee857945668ed2d28f06b5b1e3237ba`,
  retains oracle entry `004014d0` (`register_tm_clones` in the source twin).
  `llvm-objdump` shows its only direct transfer is `00401540: jmp 004014d0`
  from `frame_dummy`. The stripped file contains zero absolute pointer
  occurrences of that address; `llvm-dwarfdump --eh-frame` lists FDE starts
  `00401440`, `00401470`, `00401550`, `00401570`, not `004014d0`.
- Recovering that distinct entry requires thunk/tail-call recognition
  (roadmap m2-009), not blanket branch-target promotion. Per the hard rule on
  later-milestone dependencies, implementation stops for a sequencing decision.
  No M2 analyzer, reference exclusion, corpus change or threshold change was made.
- Extraction verification: workspace 102 tests; legacy corpus 5/5; real DOL
  remains 633/644 matches with 699 native functions. Sub-tasks c–e are not
  complete; the failing gate is evidence, not a passing milestone claim.

## Approved m1-010 thunk prerequisite
- Human approved moving the minimal m2-009 thunk/tail-call prerequisite into
  M1. Scope: an established function whose first instruction is a pure
  direct jump; validate and retain its destination as a distinct function.
  Conditional jumps, interior branches, side-effecting transfers, self loops
  and invalid destinations do not establish functions. No blanket branch
  promotion, full thunk analyzer, signature matching or metric change.
- m1-010-t: commit failing thunk acceptance, add SLEIGH purity evidence and
  generic destination discovery, then verify the real i386 blocker and gates.
  Acceptance: `native::discovery::tests` and the existing discovery gate.

## m1-010-t verified
- Acceptance committed first in `ab61328`; implementation in `8be0ec7`.
  The console now supplies `pure_jump` evidence only for a single direct
  SLEIGH branch operation. Missing evidence defaults to false.
- Six regressions cover thunk chains, conditional/interior/effectful branches,
  invalid or mismatched destination flow, weak seeds, later-discovered body
  containment, and entry jumps that return into their own body.
- Real i386 blocker resolved: native import retains `00401540` with size 2
  and `004014d0` with size 57; the connecting xref is
  `UNCONDITIONAL_JUMP`, provenance `native-import:thunk`, not a call.
- i386 plain_o0/plain_o2: 11/15 matches (previously 10/15); cpp_o2: 19/23
  (previously 18/23); many_o2: 409/413 (previously 408/413). Precision is 1.0
  for all four. The full discovery gate remains 7 pass, 13 fail, 0 skipped;
  remaining PIE/loader/architecture-cutover failures are not marked resolved.
- Verification: workspace 108 tests; core no-default 59; legacy corpus 5/5;
  DOL unchanged at 633/644 matches, 699 native functions. An intermediate
  DOL false-positive regression exposed jump-over-body sequences and was fixed
  before committing. Isolated release libc import: 4,046 functions, 4.700 s
  (<5 s). Rebuilt console from the out-of-tree patch; pinned source unchanged.
- This completes the approved minimal prerequisite, not all of m2-009 or M1.
  Raw references, scoring exclusions and thresholds remain unchanged.

## m1-010-c execution slices
- c1: remove native.rs ISA dispatch/sweeps and decoder-backed discovery;
  ELF/PE use the shared SLEIGH worklist, DOL retains its mapped-image seed scan.
  Candidate admission uses decoded flow, not architecture-specific pad bytes.
- c2: delete the now-unused hand-decoder discovery implementation and its
  route-selection feature flags; retain instruction decoding used by listing
  and graph consumers. No discovery accelerator is retained.
- c3: retire the obsolete hand-versus-console benchmark producer and its
  acceptance wrapper, plus the unreferenced console text-discovery API and
  its seed/next-entry-size helpers. Publish the existing gate and regressions.
  Historical benchmark reports remain unchanged. Each slice is a separate
  commit below 800 changed lines; c1/c2/c3 precede m1-010-d.
- Acceptance is the existing discovery gate architecture check, extended to
  cover retired decoder discovery and feature switches, plus a failing
  candidate-flow regression. Precision/recall thresholds remain unchanged.

## m1-010-c verified cutover
- Test-first commits: `66331bd` and `6b6c236`. Implementation slices:
  `18e83bf` (generic routing), `7ff1b59` (decoder retirement), `6d32467`
  (orphaned console discovery and obsolete comparison tooling).
- Architecture check: 0 legacy native.rs discovery definitions, 0 retained
  decoder/console discovery helpers, 0 discovery feature switches, 0 ISA
  matches in the shared worklist. No accelerator retained. Listing/graph
  instruction decoding remains separate and unchanged in behavior.
- Full 20-input report: 4 pass, 16 fail, 0 skipped (previously 7/13/0).
  x86-64 plain_o0/plain_o2 are 11/12; cpp_o2 is 19/20, all precision 1.0.
  The affected m1-008b acceptance was run and fails both rows. Its thresholds,
  raw references and scoring policy were deliberately not weakened.
- Generic non-x86 flow improves AArch64 plain_o0/plain_o2 from 11/17 to
  15/17 matches and cpp_o2 from 13/24 to 20/24, with precision 1.0.
  PowerPC plain_o0/plain_o2 are 8/12 with precision 1.0; missing PLT/init
  seeds and remaining flow failures still belong to m1-010-d.
- Required checks: workspace 105 tests, core no-default 57, legacy corpus
  5/5. DOL retains 633/644 matches with 698 native functions (previously
  699), 65 extras (previously 66), 10 mappings and BSS checked. A candidate
  filter regression rejecting the one-instruction __OSDBJump call was
  reproduced, covered and fixed before the cutover commit.
- Isolated release libc import: 4,049 functions in 4.627 s (<5 s).
  Generated discovery and DOL reports name implementation `6d32467`;
  the support-matrix staleness check passes. M1 is not passed.
- c1–c3 are complete. Retired hand-versus-console comparison scripts cannot
  compare distinct routes after this cutover; historical results remain in git.

## Approved landing-prefix prerequisite
- Human approved extending minimal thunk recognition to one SLEIGH-verified
  landing instruction before the pure direct jump. Ghidra
  CreateThunkFunctionCmd.getThunkedAddr skips one empty-p-code instruction
  (extracted source lines 567–572, explicitly mentioning ENDBR64).
- m1-010-d1: emit explicit empty-p-code evidence; accept one contiguous,
  valid no-op at an established entry, followed immediately by the already
  validated pure branch. Preserve original entry, actual jump xref and both
  instruction extents. Missing evidence, extra prefixes, effects, weak seeds,
  invalid destinations and source-body jump-back chains remain rejected.
- Acceptance: native::discovery::tests plus existing m1-008b and full discovery
  gates. Complete d1 only; remaining loader/seed failures remain m1-010-d.

## m1-010-d1 verified
- Failing acceptance committed in `1883c39`; implementation in `27721f2`.
  Three landing regressions cover entry/extent/xref preservation, prefix and
  target rejection, and jump-chain return into the source body. All 11 generic
  discovery tests pass.
- The rebuilt console reports `00201670` as length 4, `no_op=1`, falling to
  `00201674`; that instruction is length 2, `pure_jump=1`, targeting `00201600`.
  The destination's first MOV is `no_op=0`. Native import persists separate
  function extents of 6 and 49 bytes, and a jump xref from `00201674` with
  `native-import:thunk` provenance, not a call or an entry at the jump itself.
- m1-008b restored: x86-64 plain_o0 12/12 and cpp_o2 20/20, precision 1.0.
  Full discovery: 7 pass, 13 fail, 0 skipped; architecture check passes.
  All four non-PIE x86-64 rows have precision/recall 1.0. Remaining PIE and
  non-x86 loader/seed failures are not marked resolved.
- Workspace 108 tests; core no-default 60; legacy corpus 5/5; DOL unchanged
  at 633/644 matches, 698 native functions and 65 extras, with 10 mappings and
  BSS checked. Isolated release libc import: 4,049 functions in 4.059 s (<5 s).
  Generated discovery, m1-008b and DOL reports name `27721f2`.
- No ISA-specific discovery, mnemonic matching, reference exclusions, metric
  changes or pinned-source edits. The approved prerequisite is complete;
  broader m2-009 remains outside scope and M1 remains incomplete.

## m1-010-d execution slices
- d2: share existing ELF64 `.init`, `.fini` and `.plt` section-start seeds
  with ELF32. Acceptance: `native::tests::elf32_startup_section_seeds`,
  covering little/big-endian inputs and non-executable section rejection;
  existing full discovery gate measures the resulting function sets.
- Source-twin inspection identifies i386 misses as `__x86.get_pc_thunk.bx`,
  `_init`, `_fini` and the PLT header. PowerPC misses include `_init`, `_fini`
  and `plt_call32` stubs. No symbol names are used as scoring exceptions.
- d3: fix PIE load bias consistently across imported mappings, address facts,
  memory readers and native runtime consumers. Ghidra preserves nonzero
  prelinked bases; zero-based ET_DYN defaults are 0x100000 for ELF64 and
  0x10000 for ELF32. Do not normalize addresses inside the scorer.
- d4: investigate remaining flow/seed misses without extending the approved
  thunk prerequisite. AArch64 plain_o0 misses `0021078c` (NOP immediately
  before the existing `00210790` function) and `002108a0` (`__gmon_start__`
  PLT stub). PowerPC cpp_o2 extra `10010980` is the `.glink` section start.
- Execute d2 first; d3/d4 and sub-task e remain open. References, corpus,
  metric definitions and thresholds remain unchanged.

## m1-010-d2 verified
- Failing acceptance committed in `5dcc13b`; implementation in `f55b15d`.
  ELF32 little- and big-endian startup sections produced 0 seeds before
  the fix; the regression now passes and rejects non-executable namesakes.
- ELF32 and ELF64 now use one section-start seed collector. No changes to
  the generic flow worklist, thunk recognition or scoring policy.
- i386 non-PIE matches: plain_o0 15/15, plain_o2 15/15, cpp_o2 23/23,
  many_o2 413/413; precision and recall 1.0 for all four.
- PowerPC matches: plain_o0/plain_o2 11/12 (previously 8/12), cpp_o2 18/19
  with 19 native entries, many_o2 409/410. The remaining non-PIE miss is
  the `__libc_start_main` PLT stub; cpp_o2 still has extra `10010980`.
- Full gate: 10 pass, 10 fail, 0 skipped; architecture check passes.
  `benchmarks/reports/discovery-gate.json` was generated from `f55b15d`.
  PIE address alignment and remaining non-x86 failures are not resolved.
- Workspace 109 tests; core no-default 61; legacy corpus 5/5. README
  support-matrix staleness check passes. M1 is not passed.
- d2 is complete. d3/d4 and e remain open.

## m1-010-d3 acceptance
- `crates/lre-core/tests/elf_image.rs` checks ELF64 LE and ELF32 LE/BE
  REL, RELA and RELR pointers, zero/signed addends, prelinked bases, partial
  memory reads and user-patch precedence against console mapping bytes.
- `tests/m1-004_pie.sh` compares zero-based PIE symbols at Ghidra's loaded
  base. Unsupported RELR generation exits 77 instead of substituting RELA.
- Before implementation: the image regression fails at the first rebased
  entry; both real PIE fixtures have 0 oracle matches at loaded addresses.

## m1-010-d3 verified
- Acceptance commits: `4024f16` (loaded ELF addresses/pointers) and `21250ec`
  (worker short reads). Implementation: `ed6bbf1`.
- One loader path applies PIE bias and REL/RELA/RELR words for ELF64 LE and
  ELF32 LE/BE. Mmap readers and console images retain identical relocated
  bytes; both worker entry points use ProgramImage instead of raw-file maps.
  Nonzero prelinked bases, BSS zero-fill and user-patch precedence are checked.
- Real PIE smoke: pointer at `00103010` reads `0010300c`; its pointee reads 41.
  Console listing at `00100469` loads that pointer; worker output is
  `return *piRam0000000000103010 + 1`. End-of-section `_fini` at `00100488`
  reproduced DataUnavailError and now decompiles after the bounded-read fix.
- PIE acceptance: plain 8/8 and RELR 12/12 symbol matches at loaded addresses.
  Full gate: 12 pass, 8 fail, 0 skipped. All ten x86-64/i386 rows have
  precision/recall 1.0. PowerPC PIE improves to 12/13 matches, precision 1.0.
- Workspace 111 tests; core no-default 62; legacy corpus 5/5. m1-008b remains
  12/12 and 20/20. DOL remains 633/644 matches, 698 native functions, 65 extras,
  with 10 mappings and BSS checked.
- Isolated release libc import: 3,959 functions in 3.949 s (<5 s); this is
  a timing/function-count result, not an oracle-recall measurement.
- Discovery, m1-008b and DOL reports were generated from `ed6bbf1`. No raw
  oracle, scoring policy, threshold or pinned-source changes. M1 is not passed.
- d3 is complete; d4 and e remain open.

## m1-010-d4 investigation
- PowerPC plain_o0 `_start` at `100103f0` performs register/stack setup,
  then branches from `10010420` to the missing `10010568` libc PLT stub.
  This is an interior tail transfer, not the approved entry-jump case.
  `.rela.plt` identifies GOT slot `1003074c` for `__libc_start_main`, not
  stub entry `10010568`; its undefined dynamic symbol has value 0.
  The two FDEs cover `100104e4..10010510` and `10010510..10010568`.
- Fresh Ghidra evidence export confirms AArch64 `0021078c` is a separate
  `FUN_0021078c` with no thunk target, followed by `_FINI_0` at `00210790`.
  The missing `002108a0` entry is the `__gmon_start__` PLT thunk. Padding
  entries must not be mislabeled as already-approved direct-jump thunks.
- A separate M1 loader defect is identified: PowerPC cpp_o2 dynamic symbol
  `__gxx_personality_v0` has nonzero value `10010980` but SHN_UNDEF. ELF32
  currently admits it as a defined function. A symbol-definition regression
  and repair remain pending; no scoring exclusion is proposed.
- No d4 analyzer implementation, oracle change or metric change was made.
  Implementation stops at the required later-milestone sequencing decision.

## m1-010-d4a ELF32 symbol admission
- Regression commit `d0b3e01` fails before implementation: a nonzero
  `SHN_UNDEF` function symbol incorrectly becomes a native function.
- Defined-symbol admission now requires a nonzero section index. The
  regression covers little/big endian, retained external identity, and
  the same symbol becoming a function when assigned a defined section.
- Verification: workspace 112 tests; corpus 5/5. Full discovery now
  11 pass / 9 fail / 0 skipped. PowerPC C++ precision rises to 1.0;
  i386 C++ recall is 22/23 because its unreferenced PLT entry at
  `004019f0` needs real discovery rather than undefined-symbol admission.
- Function-start/PLT prerequisite research proceeds against pinned Ghidra
  processor patterns and analyzers. No reference or metric is changed.

## m1-010-d4b loaded external relocation facts
- Regression commit `172bf78` fails before implementation when an imported
  function's relocated GOT slot has no instruction stub in the image.
- REL/RELA linkage records now retain loaded slot addresses and names through
  their linked dynamic symbol/string tables, including ELF32 big endian.
  Undefined symbols do not become function definitions through this path.
- Workspace: 113 tests. Full discovery remains 11 pass / 9 fail / 0 skipped.
  No new entry-discovery capability or gate pass is claimed for loader facts.

## m1-010-d4 prerequisite sub-tasks
- d4b: record loaded external relocation slots for ELF32/ELF64, independently
  of instruction decoding; preserve symbol-table linkage and endian/load bias.
- d4c: expose bounded SLEIGH p-code linkage-thunk evidence, rejecting unknown
  inputs, stores and non-thunk control flow.
- d4d: consume that evidence for PLT and branch-target discovery; remove the
  ELF64 x86 byte-scan path rather than maintaining two discovery conventions.
- d4e: add the function-start prerequisite for independently justified
  adjacent entries. Match actual upstream action semantics: `validcode="function"`
  requires an already-defined function; it is not a new-entry validation rule.
- d4f: rerun the unchanged complete gate and commit fresh evidence.
  Each implementation/test commit range stays below 800 changed lines.

## Authorized prerequisite sequencing
- The maintainer authorized scheduling necessary later-milestone analyzer
  prerequisites autonomously so the current milestone can pass unchanged gates.
  This includes required function-start and indirect-thunk/tail-call work,
  not changes to corpus, metrics, release policy or other reserved decisions.
- The maintainer requested deletion of `AGENTS.md`. The file and its obsolete
  verbatim-content test/CI invocation are removed; no replacement agent-policy
  file is introduced.

## Blocked on
- None for dependency-driven prerequisite sequencing; authorization is recorded
  above. The current M1 discovery gate remains 11 pass / 9 fail.

## Next task
- m1-010-d4c: bounded SLEIGH linkage-thunk evidence, then integrate it into
  discovery under d4d. Complete the d4 prerequisites above against unchanged
  full discovery acceptance; sub-task e remains open.

## Reserved decisions
- m1-010 gate amendment: architecture-specific code is permitted only in a
  clearly separated accelerator module with an equivalence test, never in the
  discovery core. (Recorded per user direction; do not re-argue.)
