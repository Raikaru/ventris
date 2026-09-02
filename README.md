# Ventris

Ventris is a lightweight reverse-engineering platform that reuses Ghidra's
proven components (SLEIGH, p-code, the native decompiler) as compiler
technology rather than reimplementing them. It is **not** a Ghidra fork and
claims no drop-in compatibility.

## Architecture: staged migration to JVM-free

| Stage | Architecture | Status |
|---|---|---|
| 0 | Stock Ghidra + pinned reference | pinned: 12.1.3 |
| 1 | Rust core + SQLite store + tiny Java JSON-RPC bridge | done |
| 2 | Rust core owns all state; Java only on-demand compatibility | done |
| 3 | Native SLEIGH/decompiler C++ worker replaces the bridge | done (x86-64) |
| 4 | Fully native, JVM-free supported workflow | **done — gated** |

The bridge is an implementation aid, not the final architecture. The Rust
core owns durable facts (functions, symbols, xrefs, renames) in SQLite with
provenance. The supported workflow — native import, store browsing, native
disassembly, native decompilation — runs with **no JVM in the process
tree**; the bridge starts only for capabilities deliberately kept on the
Ghidra side (stock `import`, `decompile`, `disasm`, `dump-specs` on demand).

## Layout

```text
service/           Java JSON-RPC stdio bridge over pinned Ghidra APIs
crates/lre-model   IDs, address-space+offset Address, API rows
crates/lre-db      SQLite durable store (WAL, FKs, schema versioning)
crates/lre-core    CoreService facade: store + native import/worker API
crates/lre-worker  no-JVM decompiler worker (pinned ghidra_opt protocol)
crates/lre-cli     scriptable CLI over the facade
tests/             differential test (native vs Ghidra oracle)
benchmarks/        gold baseline, Stage-4 gate, reports
native/            build scripts, specs, SLEIGH patch (see support matrix)
third_party/ghidra pinned Ghidra 12.1.3 decompiler C++ + language sources
```

## Prerequisites

- Rust stable (tested 1.98)
- A Ghidra 12.1.3 installation; default lookup is `$VENTRIS_GHIDRA`, then
  `~/ghidra_12.1.3_PUBLIC`. The JVM and JDK are needed only for the bridge
  (Java service) and oracle-side tests.
- Native C++ builds: `binutils-devel` (bfd.h) for the SLEIGH console,
  a C++ toolchain; JDK 25 for the Java side.

## Build

```sh
cargo build --workspace
# Native decompiler worker (patched ghidra_opt; raw-SLEIGH, no JVM)
./native/build_ghidra_opt.sh
# Optional: SLEIGH console (disasm-native / import-native --discover)
./native/build_console.sh   # needs binutils-devel
# Java service (only for bridge compatibility paths; Ghidra install jars)
./service/build.sh
```

## End-to-end (supported workflow, no JVM)

```sh
export VENTRIS_SLA=$HOME/ghidra_12.1.3_PUBLIC/Ghidra/Processors/x86/data/languages/x86-64.sla
export VENTRIS_GHIDRA=$HOME/ghidra_12.1.3_PUBLIC          # console defaults

./target/debug/lre-cli import-native ./smoke_bin --name smoke --project ./proj
./target/debug/lre-cli functions smoke --project ./proj   # store only
./target/debug/lre-cli xrefs smoke --to 00400466 --project ./proj
./target/debug/lre-cli rename smoke 00400466 my_add --project ./proj
./target/debug/lre-cli open smoke --project ./proj        # reopen, no reanalysis
./target/debug/lre-cli disasm-native ./smoke_bin 00400466 -n 8
./target/debug/lre-cli decompile-native ./smoke_bin 00400466 --name smoke --project ./proj
```

Bridge (compatibility) equivalents remain: `import`, `decompile`, `disasm`,
`dump-specs` with `--ghidra DIR` / the service jar.

## Verification

```sh
cargo test --workspace
VENTRIS_SLA=... ./tests/differential.sh     # native vs Ghidra oracle
RUNS=3 VENTRIS_SLA=... ./benchmarks/gate.sh # memory/perf gates
```

## Honest status

- **Supported (gated, tested)**: x86-64 ELF + PE32+ native import (section
  maps, symtab/dynsym, PLT/GOT naming, flow-based function discovery with
  the `_start` → `main` RDI convention and init/fini-array seeds); store
  browsing/reopen/rename; SLEIGH disassembly via the pinned console;
  decompilation via the raw-SLEIGH worker — token-identical to the Ghidra
  bridge oracle on the pinned fixtures (differential test).
- **Gate numbers (tiny ELF fixture, this machine)**: Stage-4 workflow peak
  RSS 39.9 MB (3-run median) vs the 375 MiB stock-Ghidra baseline; median
  end-to-end wall 0.32 s vs 10.83 s stock. See
  `benchmarks/reports/stage4-gate.json`.
  **Honest comparison caveat**: this is not an apples-to-apples throughput
  benchmark. The native pipeline performs **no auto-analysis** (import is
  structural discovery; analysis facts come from symbols, flow walking, and
  the SLEIGH console) while the stock baseline runs Ghidra's full analyzer.
  Speed/memory win is real but is *at the price of analysis depth* — a trade
  against Ghidra, not a replacement.
- **Real-binary sample (`/usr/lib64/libc.so.6`, 2.48 MB, stripped, this
  machine)**: native import recovers 3,999 functions in 0.54 s (exported
  symbols, init/fini arrays, flow closure); a real 192-byte varargs function
  (`__GI___asprintf`) decompiles natively in 0.9 s. Function-set parity
  against the Ghidra oracle on this binary is reported in STATUS.md.
- **Known limits (support matrix)**: non-PIE executables only (PIE/ASLR
  binaries work via the bridge); indirect-only CRT helpers (`_init`,
  `register_tm_clones`, PLT shims) are not recovered by native discovery;
  PE discovery uses the entry walk (closure granularity differs from
  Ghidra's analyzer: 310 vs 138 on the fixture); x86-64 only; the worker
  needs `VENTRIS_SLA` + a patched `ghidra_opt`; no packaging/CI yet.
- **No UI**: consumer surfaces (GUI, Python/agent adapters) are not built.
  The `lre-core` facade is the intended contract for them.
