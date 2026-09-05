# GOAL

The Stage-4 JVM-free workflow is the verified baseline, not the full completion
claim. The ratified milestone roadmap requires program-model parity with
Ghidra (C1), improvements over stock Ghidra measured against ground truth
(C2), and measured game-first sessions on the approved targets (C3).

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
  install jars — never from memory (see CONTRIBUTING.md).
- `third_party/ghidra/` stays pinned and hash-manifested; never edited in place.
- Subagents read-only research only; the primary agent owns all edits.
- No capability claimed without a test proving it.

## Remaining work

- M1 discovery evidence is measured: all 20 ELF rows have precision/recall
  1.0; the stripped DOL has recall 0.984472. Hosted CI verification is pending.
- M2 program-model parity: constant propagation, data references and strings,
  inferred prototypes, switch recovery, library identification and C++ facts.
  The parity gate, not discovery alone, establishes C1.
- M3 ground truth: DWARF scoring, a stock-Ghidra baseline and regression gates.
- M4 measured improvements over that baseline, behind approved flags and
  preserving oracle mode until the reserved decisions are made.
- M5 end-to-end game sessions on the human-approved targets.
- M6 user/analyzer documentation, release infrastructure and contributor
  sustainability. Releases and outside contribution merges remain reserved.

`STATUS.md` records the current milestone, exact next task and measured evidence.
