# GOAL

Drive ventris from Stage 1 (done) through Stage 4: a JVM-free reverse-engineering
platform whose supported workflow (x86-64 ELF+PE: import, memory inspection,
functions, disassembly, xrefs, decompile, rename, reopen without reanalysis)
runs with Java absent, passing differential tests against pinned Ghidra 12.1.3
and meeting measured memory targets.

## Stages

| Stage | Exit condition | Status |
|---|---|---|
| 1 | Rust core + SQLite store + Java JSON-RPC bridge, e2e verified | **done** (commits 993605f, 8cf03d3, a59cdb7, 9028da6, f51968c) |
| 1.5 | Baseline benchmarks + native-worker feasibility spike + ADR-0001 | **in progress** |
| 2 | Store owns all facts; bridge on-demand only; reopen Java-free | — |
| 3 | Native SLEIGH/disasm + decompiler worker replaces bridge (x86-64); differential tests pass | — |
| 4 | JVM-free supported workflow, ELF+PE native import, memory/perf gates, support matrix | — |

## Stage 1.5 checklist

- [x] Stock-Ghidra baseline benchmarks — median wall 10.83 s, median peak
      process-tree RSS 375 MiB (benchmarks/reports/baseline-stock.json)
- [ ] Native-worker feasibility spike: build pinned decompiler C++, decompile
      one function with no JVM
- [ ] ADR-0001: process topology + no-JVM migration route
- [ ] Results into docs/, gate Stage 2

## Hard rules

- Every Ghidra API call verified against `.ghidra-java/` sources or the
  install jars — never from memory (see AGENTS.md).
- `third_party/ghidra/` stays pinned and hash-manifested; never edited in place.
- Subagents read-only research only; the primary agent owns all edits.
- No capability claimed without a test proving it.
