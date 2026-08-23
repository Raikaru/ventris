# Changelog

All notable Ventris changes are documented here.

## [Unreleased]

### Added

- Executed legal-PS2 semantic baselines and machine-readable exact, diverged,
  unsupported, and unavailable comparison reports; commercial-image parity
  remains opt-in and reports no unexecuted expected facts.
- O32 direct/indirect call facts, evidence-preserving object-layout recovery,
  nominal object relations, and reconstructed-source structure scoring.
- Expanded the legal Dungeon Game ELF gate to ten bounded functions and added
  a Clang `mipsel-none-elf` compiler gate with normalized assembly comparison.
- Corrected delay-slot discovery/order for MIPS/N64 control flow, made
  conditional-return folding label-safe, and report source-supplied metadata as
  applied evidence rather than machine-exact evidence.

## [0.1.0] - 2026-08-23

### Added

- Bounded binary inspection and address resolution for ELF, PE, COFF,
  Mach-O, Intel HEX, Motorola S-record, and supported console containers.
- Native lifting and checked-in p-code/decompiler corpus coverage across the
  documented architecture paths.
- Console target profiles and evidence-backed ABI/type recovery through the
  CLI, Python API, HTTP server, and VS Code integration.
- Persistent bounded native-analysis memoization with fail-closed snapshots.
- Source-backed corpus metadata and opt-in hash-verified real-image smoke tests.
- Release packaging now emits and verifies native archives, VSIX payloads, and
  Python wheel/source artifacts with policy and provenance files.
- Release smoke gates exercise the optimized release-profile executable before
  archive packaging.
- Cross-platform native release smoke checks, strict archive verification, and
  GPUI persisted-project acceptance coverage.

### Known limitations

- Native semantic parity is proven for the checked-in corpus, not for every
  instruction or every compiler idiom on every supported processor.
- Game recovery is an initial vertical slice. Engine/runtime pattern models and
  matching-C emission are not complete.
- The Python package forwards to an externally installed Ventris executable; it
  does not bundle a platform-specific Rust binary.
- The HTTP server has no authentication or TLS and is intended for loopback
  use only.
- Manual visual VS Code acceptance remains a release check; the GPUI desktop
  workspace has a recorded populated-project smoke.
