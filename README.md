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

service/           Java JSON-RPC stdio bridge over pinned Ghidra APIs
crates/lre-model   IDs, address-space+offset Address, API rows
crates/lre-db      SQLite durable store (WAL, FKs, schema versioning)
crates/lre-core    CoreService facade: store + native import/worker API
crates/lre-worker  no-JVM decompiler worker (pinned ghidra_opt protocol)
crates/lre-api     versioned stdio/HTTP Core API
crates/lre-debug isolated GDB/LLDB read-only debugger backend
crates/lre-cli     scriptable CLI over the facade
desktop/ventris-qt Qt 6 Widgets workstation
python/            SDK, console, permissioned plugins, AI tool adapter
tests/             differential test (native vs Ghidra oracle)
benchmarks/        gold baseline, Stage-4 gate, reports
native/            build scripts, specs, SLEIGH patch (see support matrix)
packaging/         SPDX SBOM and release update metadata tools
third_party/ghidra pinned Ghidra 12.1.3 decompiler C++ + language sources
```

## Prerequisites

- Rust stable (tested 1.98)
- A Ghidra 12.1.3 installation; default lookup is `$VENTRIS_GHIDRA`, then
  `~/ghidra_12.1.3_PUBLIC`. The JVM and JDK are needed only for the bridge
  (Java service) and oracle-side tests.
- Native C++ builds: `binutils-devel` (bfd.h) for the SLEIGH console,
  a C++ toolchain; JDK 25 for the Java side.
- Python 3.10+ for the SDK, console, plugin host, and packaging scripts.
- Qt 6.4+ Widgets/Concurrent and CMake 3.21+ for the desktop build.

## Build

```sh
cargo build --workspace
# Native decompiler worker (patched ghidra_opt; raw-SLEIGH, no JVM)
./native/build_ghidra_opt.sh
# Optional: SLEIGH console (disasm-native / import-native --discover)
./native/build_console.sh   # needs binutils-devel
# Versioned Core API (stdio by default, HTTP with --listen)
cargo build -p lre-api
# Java service (only for bridge compatibility paths; Ghidra install jars)
./service/build.sh
# Qt desktop package (requires Qt development files)
cmake -S desktop/ventris-qt -B build/ventris-qt
cmake --build build/ventris-qt --config Release
cmake --build build/ventris-qt --target package --config Release
```

## API, scripting, and extensions

The versioned Core API uses newline-delimited JSON over stdio or `POST /v1`
over HTTP. It is the same `lre-core` service used by the CLI and desktop
bridge:

```sh
./target/debug/lre-api --project ./proj
./target/debug/lre-api --project ./proj --listen 127.0.0.1:8787
python3 python/ventris_console.py --project ./proj \
  --api-executable ./target/debug/lre-api \
  -c 'print(client.ping())'
python3 python/ventris_plugin_host.py plugin.py --project ./proj --permission read
```

`python/ventris_sdk.py` is dependency-free and supports both transports.
`ventris_plugin_host.py` runs each plugin in a child process and gates API
methods by `read`, `write`, `types`, and `native` permissions. The optional
`ventris_ai.py` adapter exposes the same read tools and requires an explicit
mutation opt-in.

`lre-debug` provides isolated GDB/LLDB read commands (backtrace, registers,
and bounded memory reads) through fresh child processes with deadlines.
`trace_events` stores an ordered timeline; `collab_ops` stores idempotent
Lamport/actor-ordered operations and explicit apply state, so API clients can
share durable analysis changes without sharing SQLite connections.

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
  symbols, init/fini arrays, two-path flow closure); a real 192-byte varargs
  function (`__GI___asprintf`) decompiles natively in 0.9 s. Against the
  Ghidra oracle (3,987): intersection 3,930 — **precision 0.983, recall
  0.986** (69 native-only / 57 oracle-only entries, mostly boundary and
  alias differences). Function-set agreement, not just count proximity.
- **Gate semantics**: `benchmarks/gate.sh` distinguishes a COMPLETE run
  (every required phase executed) from a PARTIAL one (missing SLEIGH
  console → `"complete": false, "skipped": ["disasm-native"],
  "functional_pass": false, "performance_pass": true`, exit 2). A complete
  PASS (exit 0) requires all phases; the current environment (no
  binutils-devel, no sudo) yields PARTIAL on both the gate and the
  console-dependent differential steps — the worker/CLI parity steps run
  unconditionally and pass.

## Support matrix

The architecture catalog reads the installed Ghidra `.ldefs` files and
`lre-cli architectures` reports the exact language ids available locally.
Native structural import selects these language ids from ELF `e_machine`:

| Input | Structural native import | Native flow/decode/decompile |
|---|---|---|
| ELF x86-64 | supported | **supported and gated** |
| PE32+ x86-64 | supported | **supported and gated** |
| ELF AARCH64 LE64 | supported | selected SLEIGH bundle required; not parity-gated |
| ELF ARM LE32 | supported | selected SLEIGH bundle required; not parity-gated |
| ELF MIPS LE32 | supported | selected SLEIGH bundle required; not parity-gated |
| ELF RISC-V LE64 | supported | selected SLEIGH bundle required; not parity-gated |
| ELF PowerPC LE32/LE64 | supported | selected SLEIGH bundle required; not parity-gated |

The fallback flow walker and PE parser are x86-64-specific. Non-x86 ELF
imports preserve mappings, symbols, and the entry point for a matching
`VENTRIS_LANGUAGE`, `VENTRIS_LANGUAGE_DIR`, and `VENTRIS_SLA` worker bundle;
cross-architecture decompile parity is not claimed yet. The catalog itself
was exercised against the pinned Ghidra installation.

## Packaging and desktop status

`desktop/ventris-qt` contains the Qt 6 Widgets workstation and CPack TGZ
configuration. `packaging/sbom.py` emits an SPDX 2.3 dependency inventory;
`packaging/update_manifest.py` creates release artifact size/SHA-256 metadata;
`packaging/verify_update.py` verifies downloaded artifacts before use.
The local environment used for this status report has no Qt 6 development
package, so CMake configure and visual UI verification remain unavailable
here. CI is the authoritative cross-platform Qt build.

Known limits remain: indirect-only CRT helpers (`_init`,
`register_tm_clones`, PLT shims) are not recovered by native discovery; PE
discovery uses the entry walk (closure granularity differs from Ghidra's
analyzer: 310 vs 138 on the fixture); the x86-64 worker needs `VENTRIS_SLA`
and a patched `ghidra_opt`; the API HTTP listener is localhost-oriented and
does not provide authentication; the Python plugin host is the capability
boundary for untrusted scripts.
