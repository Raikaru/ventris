# Changelog

All notable Ventris changes are documented here.

## [Unreleased]

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
