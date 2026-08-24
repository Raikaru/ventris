# Changelog

All notable Ventris changes are documented here.

## [Unreleased]

### Added

- Added `ventris_decompiler::graph`, a mutable p-code data-flow graph ported
  from Ghidra 12.1.3's `Funcdata`/`Varnode`/`PcodeOp` object model: one varnode
  per definition, descendant lists, operand replacement, operation insertion and
  destruction, and construction from lifter output. Ghidra's Actions and Rules
  rewrite a live graph rather than build expressions, so this object model is
  the prerequisite for porting them instead of reinventing them.
- Added location refinement ported from `Heritage::buildRefinement`,
  `splitByRefinement`, `refineRead`, `refineWrite`, `concatPieces`, and
  `splitPieces`: overlapping accesses are cut at every access boundary, a read
  spanning several cells becomes a `PIECE` chain, and a write becomes one
  `SUBPIECE` per cell. Ventris previously keyed SSA on exact locations and
  handled sub-register views with an ad-hoc widening cast at read time.
- Added data-flow guards ported from `Heritage::guardCalls`, `guardStores`, and
  `guardReturns`: a call or aliasing store gains an `INDIRECT` definition for
  each location it may change, and a return reads its result storage. The effect
  model is supplied by the target ABI rather than guessed, so a preserved
  register is not needlessly invalidated.
- Added SSA construction on the graph, ported from `Heritage::calcMultiequals`
  and `renameRecurse`: reverse postorder, Cooper-Harvey-Kennedy immediate
  dominators, Cytron dominance frontiers and iterated phi placement, real
  `MULTIEQUAL` operations at joins, and renaming that rewrites every read to the
  definition dominating it. An undefined read becomes a function input rather
  than a bare register name.
- Added graph value resolution, ported from `ActionMarkExplicit` and
  `PrintC::pushVn`: a read resolves by following its definition edge, a value
  with several readers or an unduplicatable definition is named and declared,
  and a merged value is named with one assignment per incoming path instead of
  being dropped. Resolution is order-independent, so a definition below its use
  is found.
- Added graph statement emission, ported from `PrintC::emitBlockBasic`: blocks
  emit in address order into the label-and-goto form the structuring pass
  consumes, phi assignments land at the end of each predecessor, and a shared
  computation is spelled once and reused. No join repair, path-invariance proof,
  or predecessor-state intersection is needed, because the graph already records
  which values merge.
- Added dead code elimination, ported from `ActionDeadCode`: bit-level consumed
  masks propagate backwards from stores, calls, branches, and returns, so a byte
  extracted from a word keeps only that byte live. A call keeps its effect and
  loses only its unread result. Guarding and SSA construction over-approximate
  by design, and this is what removes the merges nothing reads.
- Added `NativeStatement::Assign` and `NativeStatement::DeclareLocal`. A merged
  value needs one declaration dominating an assignment on each path, which
  neither `Declare` (single definition site) nor `Copy` (block memory copy)
  could express; phi lowering previously rendered as `__builtin_memcpy`.
- Added `NativeDecompiler::decompile_via_graph`, the ported pipeline end to end.
  Branch and call targets are read as `ram` space addresses rather than `const`
  constants, which is what a direct call and a conditional branch actually are.
- Added the graph Action and Rule framework, ported from `Action`, `Rule`,
  `ActionPool`, and `ActionGroup`. Rules are registered by opcode and rewrite
  the graph in place, so one rule's result is another's input. Ported rules:
  `RuleMultiCollapse`, `RuleCollapseConstants`, `RuleTrivialArith`,
  `RulePropagateCopy`, `RuleIndirectCollapse`.
- Added unreachable-block removal, ported from
  `Funcdata::removeUnreachableBlocks`, including dropping the merge operand a
  removed predecessor contributed so operand slots stay aligned with the
  predecessor list.
- Fixed graph construction pre-linking reads in address order, which defeated
  renaming: a read already bound to a lower definition was skipped, so a call's
  result read afterwards showed the value from before the call. Reads are now
  free varnodes and renaming alone decides what they see.
- Fixed the graph pipeline running the statement-level action database. Those
  rules repair the address-ordered emitter's output and assume its shape; on
  graph-emitted statements they deleted conditional branches.
- Added type inference on the graph, ported from `ActionInferTypes`: types flow
  along data-flow edges under `Datatype::typeOrder`, bounded at seven passes.
  Propagation is bidirectional through copies, merges, and offsets, so a pointer
  discovered at a dereference reaches the argument register it arrived in and
  the base a field access started from. The previous solver only merged
  constraints per value, which could not carry a type upward at all.
- Added call prototype recovery, ported from `ParamActive::registerTrial`,
  `FuncCallSpecs::checkInputTrialUse`, and `buildInputFromTrials`: one trial per
  convention parameter location, read from the guard that names the location's
  value at the call, kept when the function actually produced that value. A call
  through the graph pipeline now carries arguments instead of none.
- Fixed graph value names colliding when one location holds values of different
  widths at one address, which emitted two C declarations of the same identifier
  with different types.
- Added variable merging, ported from `Merge::mergeOpcode` and `HighVariable`:
  the values a `MULTIEQUAL` or `INDIRECT` relates become one C variable, so a
  merge carries no content of its own and its per-path assignments disappear.
  Names belong to variables rather than SSA values, a merged variable is
  declared once at function scope, and writes to it are assignments rather than
  redeclarations.
- Added cast placement, ported from `ActionSetCasts` and `CastStrategyC`: a cast
  is emitted only where C would not perform the conversion itself. Integer
  widening and signedness changes, and testing any scalar as a condition, are
  implicit; crossing between integers and pointers, changing a pointer's target,
  and float conversions are spelled. A value already recovered as a pointer no
  longer carries `(uintptr_t)` at every dereference.

- Added `LiftedInstruction::skips_delay_slot`, which reports the MIPS
  likely-branch shape so consumers stop treating its sequential successor as
  implicit.
- Added a `declaration-narrowing` action rule: a temporary that every use
  narrows is declared at the narrow type instead.
- Added PS2 retail regressions pinned to real Dungeon Game bytes covering
  memory ordering, likely-branch flow, and merge points.
- Added epilogue inlining: a jump to a block that only returns becomes that
  return, so a shared epilogue no longer turns every path into a label.
- Added frame-slot promotion: a stack slot that is provably a private scalar is
  declared and named as a local instead of rendered as `sp`-relative memory. A
  slot whose address escapes, whose bytes are accessed at more than one width,
  or that overlaps another slot keeps its memory form.
- Added the Apache-2.0 R5900 language and routed the PS2 target to it. The
  generic MIPS64 language cannot decode the R5900's multimedia or COP2/VU
  macro-mode instructions.
- Added `SleighSpec::register_varnode` so ABI recovery reads register offsets
  from the language instead of assuming a per-family stride, plus a bundled
  register-layout audit over every shipped language.
- Added `tools/quality_census.py` and `tools/CensusDecompile.java`, which
  classify Ventris output against Ghidra's decompiler across every
  hash-verified corpus function and rank defects by affected function count.

### Fixed

- A value read before a store is now read once, before it. A definition holding
  a load that a following store may overwrite is captured in a named temporary,
  so `p->count++` no longer returns the incremented value where the program
  returns the original.
- MIPS likely-branches (`beql`, `bnel`, `bgtzl`, …) keep both successors. They
  were lifted as unconditional jumps, which deleted the not-taken path and
  truncated any function whose last branch was likely: `getBuiltInTexture` was
  discovered 12 bytes short and jumped to a label that was never emitted.
- A label reached from several blocks now keeps only the values every
  predecessor agrees on. Carrying one path's value made four of five
  comparisons in `getBuiltInTexture` test the wrong string and made the
  function claim one path's return value unconditionally.
- Casts that restate a value's own type are dropped, halving the cast count of
  an ordinary field read.
- Constant offsets fold through a truncating cast, since truncation commutes
  with addition; `(uint32_t)(sp - 0x40) + 0x40` is `sp`.
- A return register the function never writes is no longer reported as the
  return value: an untouched register holds the incoming argument, not a
  result.
- Derived PS2 register offsets, register names, and O32 argument slots from the
  R5900 language. The previous MIPS64 stride misidentified every argument and
  return register, which silently disabled PS2 type recovery.
- Narrowing casts of constants now truncate: a byte store of `0x1234` reports
  `0x34`, matching Ghidra, instead of the untruncated value.
- Widening casts of constants now adopt the declared width, so a 32-bit result
  materialized from a 16-bit immediate no longer infers a 16-bit type.
- Dropped redundant widen-then-narrow cast pairs, which the R5900 emits for
  every 32-bit arithmetic result.
- A value left in the return register is still recognized as a store byproduct
  when the store and the register disagree only about declared width.
- Recovered the comparison behind a packed condition-register field. A branch
  that tested `(a < b) << 3 | (b < a) << 2 | (a == b) << 1 | so` now renders as
  `a < b`, so no corpus function spells a comparison as a bit-field chain and
  the widest rendered expression in `TRK_fill_mem` fell from 2836 to 247
  characters.
- Collapsed rotate-and-mask pairs whose mask erases one half, folded chained
  constant offsets into one addition, dropped shifts at or beyond a value's own
  width, and dropped `x - 0`.
- Negative folded offsets render as subtraction: `rsp - 0x10` instead of
  `rsp + 0xfffffffffffffff0`.

## [0.3.0] - 2026-08-24

### Added

- Added a native Rust reader for Ghidra 12.1.3 compiled `.sla` files: bounded
  zlib inflation, packed marshal decoding, typed `ELEM_SLEIGH` trees,
  constructor decision selection, and p-code template parsing. The installed
  12.1.3 corpus gate decodes 137 processor specifications, 128,421 constructor
  templates, and 810,755 operation templates.
- Routed all 21 public architecture profiles through pinned compiled SLEIGH
  specifications, including Apache-2.0 community definitions for
  Gekko/Broadway and Cell SPU. The runtime now measures variable-length
  constructor trees, backtracks overlapping constructors on invalid operand
  tables, applies context actions, expands recursive BUILDs, and emits delay
  slots.
- Added a 21-function Animal Crossing differential corpus covering 1,704
  reachable Ghidra-decoded instructions with zero p-code differences,
  including paired-single and load/store-multiple semantics.
- Completed the native decompiler stage pipeline with Ghidra-derived
  Heritage/SSA versioning, ordered action-rule fixed points, conservative type
  propagation, block-action control-flow structuring, and a precedence-aware C
  AST printer. Stage fixtures and source-backed real-image baselines now gate
  the complete path rather than only lifting.
- Added provenance-pinned, Ghidra-authored offline GameCube p-code fixtures for
  `TRK_memset`, conditional branching, paired-single storage, and
  load/store-multiple expansion, plus deterministic exact-varnode regression
  tests.
- Added pinned Ghidra decompiler-stage oracles for `TRK_fill_mem`,
  `convert_partial_address`, and `__FrameCallback`. The exporter records raw
  function bytes, high-variable types, inferred parameters and return types,
  direct calls, structured C, and immutable source/Ghidra provenance.
- Added target-ABI direct-callee prototype recovery. Call arguments now come
  from the callee's recovered signature, known return types propagate through
  call results, and branch conditions reuse one materialized call result.

### Fixed

- Generate release checksum manifests with explicit binary-mode markers.
- Qualified compiler-gate addresses with their image spaces and accepted
  Windows LLVM object headers without weakening instruction parsing.
- Corrected the measured PowerPC EABI ninth-argument offset to `r1 + 8`;
  unmeasured Xenon and PS3 PPU floating-point, stack, and aggregate conventions
  now remain unknown instead of inheriting incompatible 32-bit EABI facts.
- Recovered PowerPC EABI frame save/restore sequences as machine state instead
  of C, limited function parameters to live-in values, propagated register
  copies through calls and returns, and excluded stack-frame accesses from
  recovered application structs. A pinned Animal Crossing `TRK_memset`
  baseline now gates the GameCube path against source-backed semantics.
- Pinned the Ghidra executable specification and p-code differential harness to
  Ghidra 12.1.3 (`Ghidra_12.1.3_build`), with install-version enforcement and
  recorded upstream commit and release checksum.
- Added bounded raw-function export and compact summary output to the Ghidra
  differential harness.
- Prevented GameCube DOL differential runs from deadlocking on the loader's
  interactive symbol-map prompt, selected Ventris's DOL loader explicitly, and
  bounded explicit-range comparisons to the Ghidra capsule address range.
- Canonicalized each compiled language's declared default address space to the
  stable RAM p-code space, including 6502 languages whose default is not named
  `ram`.
- Updated PS2 source-metadata receiver coordinates for canonical 64-bit R5900
  register varnodes and removed casts made redundant by recovered nominal field
  types.
- Merged SSA definitions from conditional fallthrough and branch paths before
  structuring, preserving branch-dependent call results without duplicating
  side effects in rendered C.
- Synchronized Rust, Python, VS Code, CI, and release-workflow metadata for
  0.3.0; Python distributions now use PEP 639 license metadata and every Rust
  crate records its canonical repository.

## [0.2.0] - 2026-08-23

### Breaking changes

- Reduced the public CLI to `inspect`, `lift`, and `decompile`.
- Replaced `decompile-native`, `recover-types`, and `reconstruct-source` with
  the canonical `decompile` command. Project, discovery, diff, batch, corpus,
  and HTTP commands are no longer public product API.
- Reduced the Python package to `inspect`, `lift`, `decompile`, `version`, and
  the low-level `run` process helper.
- Raised the Rust edition to 2024 and the minimum supported Rust version to
  1.98.

### Added

- Added a canonical `ventris::Pipeline` facade for loading, lifting, analysis,
  inventory, and deterministic C rendering.
- Added declarative target profiles that keep architecture, loader, ABI,
  address-space, image-part, and support-level facts together.
- Added executed legal-PS2 semantic baselines and machine-readable exact,
  diverged, unsupported, and unavailable comparison reports.
- Expanded the legal Dungeon Game ELF gate to ten bounded functions and added
  three per-function Clang `mipsel-none-elf` compiler floors whose retail
  instructions are fully decoded by the configured disassembler.
- Added a non-publishing release-candidate workflow mode.

### Changed

- Moved reusable function/data inventory and game-recovery algorithms from the
  CLI into library ownership.
- Split native decompilation into focused control-flow, SSA, and semantic-score
  modules without creating a second pipeline.
- Moved corpus, compiler, oracle, transport, project, batch, and packaging
  workflows behind development-only tools.
- Reduced Python and VS Code to thin adapters over the native executable.
- Froze the GPUI desktop workspace outside the product pipeline while retaining
  its formatting and test jobs as release compatibility gates.
- Corrected MIPS/N64 delay-slot discovery and ordering, made conditional-return
  folding label-safe, preserved partial-layout field offsets, and retained
  externally referenced control-flow labels.

### Known limitations

- Decompilation quality remains function-specific; a supported loader or lifter
  is not a uniform C-quality claim.
- Native function signatures are not yet selected from a container-specific
  ABI at every decompiler entry point.
- The Python and VS Code packages require a separately installed matching native
  executable.

## [0.1.0] - 2026-08-23

### Added

- Bounded binary inspection and address resolution for ELF, PE, COFF,
  Mach-O, Intel HEX, Motorola S-record, and supported console containers.
- Native lifting and checked-in p-code/decompiler corpus coverage across the
  documented architecture paths.
- Console target profiles and evidence-backed ABI/type recovery through the
  canonical Rust pipeline, CLI, Python adapter, and VS Code adapter.
- Source-backed corpus metadata and opt-in hash-verified real-image smoke tests.
- Release packaging now emits and verifies native archives, VSIX payloads, and
  Python wheel/source artifacts with policy and provenance files.
- Release smoke gates exercise the optimized release-profile executable before
  archive packaging.
- Cross-platform native release smoke checks and strict archive verification.

### Known limitations

- Native semantic parity is proven for the checked-in corpus, not for every
  instruction or every compiler idiom on every supported processor.
- Game recovery is an initial vertical slice. Engine/runtime pattern models and
  matching-C emission are not complete.
- The Python package forwards to an externally installed Ventris executable; it
  does not bundle a platform-specific Rust binary.
- Manual visual VS Code acceptance remains a release check.
