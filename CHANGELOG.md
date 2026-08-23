# Changelog

All notable Ventris changes are documented here.

## [Unreleased]

### Fixed

- Generate release checksum manifests with explicit binary-mode markers.

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
  eight per-function Clang `mipsel-none-elf` compiler floors.
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
