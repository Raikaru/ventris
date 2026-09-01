# ADR-0001: Process topology and the no-JVM migration route

Status: accepted
Date: 2026-09-01
Deciders: primary agent (user-directed staged architecture)

## Context

Ventris must deliver an x86-64 ELF/PE reverse-engineering workflow whose
steady state runs with no JVM. Ghidra's Java program model (loaders,
analyzers, symbol database) is Stage-1 irreplaceable, but the decompiler
and SLEIGH are native C++ already — verified by the feasibility spike
(benchmarks/reports/native-spike.md): the pinned 12.1.3 C++ decompiled real
functions with zero Java in the process tree. Stock Ghidra baseline on the
reference host: median 10.83 s wall, 375 MiB peak process-tree RSS for
import+analyze of the tiny fixture.

## Decision

1. **Three process classes, fixed roles:**
   - **Rust core** (`lre-core` + `lre-db`): the only owner of durable state.
     Owns `project.sqlite`, addresses/IDs model, revision-stamped facts,
     and the CoreService facade. Linked in-process by CLI today, by the GUI
     later. Never hosts Java or C++ analysis code.
   - **Java bridge** (`service/`): temporary Stage-1 provider for loaders,
     auto-analysis, and program-model queries. Launched as a child process,
     line-framed JSON-RPC on stdio, one project lock at a time. Forbidden
     from owning project state or writing `project.sqlite`.
   - **Native worker** (Stage 3): C++ shell around pinned `ghidra_opt`
     machinery (Ghidra-protocol server) implementing the program-provider
     callbacks the decompiler needs (bytes, map, symbols, function
     boundaries, context, types, injects). Replaces the bridge
     capability-by-capability, each gated by differential tests.
2. **Ownership transfer, not reimplementation.** Facts move
   bridge → store on import (already implemented). When the native worker
   can produce a fact class (decode, xrefs, decompile), the bridge copy is
   removed from the supported path the same release. The old pipeline's
   from-scratch port is rejected evidence: 125/162 rules was the wrong
   tradeoff.
3. **Address wire format.** Worker/bridge protocols carry addresses as
   explicit hex or space-qualified strings (`ram:0x400466`); leading-zero
   decimal/octal ambiguity (console parses leading zeros as octal — see
   spike report) is banned on every wire.
4. **Isolation is retained even when native.** The C++ decompiler stays in
   its own subprocess with deadline + memory cap; "no JVM" never means
   "in-process C++" (spec 4, 15.3).

## Consequences

- Stage 2 exit: reopen/browse/rename with the bridge absent (store already
  satisfies reopen for imported facts; remaining: PE, comments, types).
- Stage 3 exit: differential decode/decompile parity suite green with the
  bridge out of the supported path; bridge retained only as dev oracle.
- The 375 MiB stock peak RSS is the line Stage 4 must beat; every stage
  must record its own measurement in benchmarks/reports/.
- `third_party/ghidra/` build products (`ghidra_opt`, `sleigh_opt`, `.sla`)
  are build artifacts of the pinned tree — reproducible, not vendored.

## Alternatives considered

- **Port decompiler to Rust (old project's path):** rejected again on the
  same evidence — partial-rule parity, mutable-graph porting risk.
- **Embed native decompiler in the Rust process:** rejected; loses crash
  isolation for pathological functions, saves only IPC overhead.
- **Keep Java permanently for analysis:** rejected; violates the stated
  end state and forfeits the measured memory goal.
