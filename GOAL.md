# GOAL

Drive ventris from Stage 1 (done) through Stage 4: a JVM-free reverse-engineering
platform whose supported workflow (x86-64 ELF+PE: import, memory inspection,
functions, disassembly, xrefs, decompile, rename, reopen without reanalysis)
runs with Java absent, passing differential tests against pinned Ghidra 12.1.3
and meeting measured memory targets.

## Stages

| Stage | Exit condition | Status |
|---|---|---|
| 1 | Rust core + SQLite store + Java JSON-RPC bridge, e2e verified | **done** |
| 1.5 | Baseline benchmarks + native-worker feasibility spike + ADR-0001 | **done** (39.5 MB spike vs 375 MiB stock; see benchmarks/reports/) |
| 2 | Store owns all facts; bridge on-demand only; reopen Java-free | **done** (schema v2: comments/datatypes; reopen verified no-JVM) |
| 3 | Native SLEIGH/disasm + decompiler worker replaces bridge (x86-64); differential tests pass | **done** (raw-SLEIGH worker wired into CLI `decompile-native`; differential passes) |
| 4 | JVM-free supported workflow, ELF+PE native import, memory/perf gates, support matrix | **done — gated** (benchmarks/gate.sh: 39.9 MB peak vs 375 MiB stock, 0.32 s median wall (3 runs); support matrix in README/STATUS) |

## Hard rules

- Every Ghidra API call verified against `.ghidra-java/` sources or the
  install jars — never from memory (see AGENTS.md).
- `third_party/ghidra/` stays pinned and hash-manifested; never edited in place.
- Subagents read-only research only; the primary agent owns all edits.
- No capability claimed without a test proving it.

## Remaining work (post-Stage-4, in priority order)

- UI / consumer surfaces (GPUI decision) over the `lre-core` facade — not
  started.
- PIE binaries: native import handles non-PIE only (bridge covers PIE).
- Indirect-only CRT helpers (`register_tm_clones`, `_init`/`_fini`) and PLT
  shims are outside native discovery; xrefs are call/branch-only (no data
  xrefs yet).
- CI + packaging (the differential/gate need a Ghidra install + the patched
  native build; no GitHub Actions yet).
