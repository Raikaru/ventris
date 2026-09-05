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
and bounded memory reads) through fresh child processes with deadlines. Its
read-only `DolphinGdb` client speaks acknowledged GDB RSP for live target
memory; the Core/API/Qt `memory_live` surface reuses that connection.
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

GameCube DOL import maps the section table and preserves initialized data
inside BSS bounds. Discovery requires the native console and installed
`PowerPC:BE:32:default` language; the console loads a temporary sparse XML
image and supplies instruction flow to the generic worklist. No symbol ELF
is supplied to the importer. `.rel` loading is not implemented.

```sh
./target/debug/lre-cli import-native /path/to/sys/main.dol --name dol --project ./proj
python3 tests/m1-009_dol.py --dol /path/to/sys/main.dol --oracle /path/to/files/boot.elf
```

The real-input gate requires the hash-pinned GQFE78 pair; missing private
inputs produce a skipped, non-passing report. It is a local gate, not a claim
that CI possesses or tests the game binary.

## Verification

```sh
cargo test --workspace
VENTRIS_SLA=... ./tests/differential.sh     # native vs Ghidra oracle
RUNS=3 VENTRIS_SLA=... ./benchmarks/gate.sh # memory/perf gates
```

## Honest status

- **Previously gated workflow**: x86-64 ELF + PE (PE32/PE32+) native import
  (section maps, symbols, PLT/GOT naming, unwind and pointer/init seeds);
  current discovery cutover limits are recorded below. Store
  browsing/reopen/rename; SLEIGH disassembly via the pinned console;
  decompilation via the raw-SLEIGH worker — token-identical to the Ghidra
  bridge oracle on the pinned fixtures (differential test).
- **Targeted GameCube sample (`Agent Under Fire`, GQFE78 `base.elf`)**:
  native ELF32 big-endian PowerPC import and JVM-free e500 decompilation
  are verified with the matching vendored SLEIGH bundle. Prototype edits
  are applied through the worker and appear in decompiler tokens.
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
- **Historical real-binary measurement (`/usr/lib64/libc.so.6`, 2.48 MB,
  stripped, this machine)**: native import recovered 3,999 functions in 0.54 s (exported
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

## Code-function scoring

Raw SHA-keyed `oracle/*.json` references remain unchanged. The separately
versioned `oracle/scoring-v1/` views exclude only Ghidra synthetic external
placeholders with positive loader evidence: an artificial `EXTERNAL` block,
source `Elf Loader`, and a thunk to an external function. Each exclusion
records its reason and evidence; each view hashes its raw reference and exporter.
Permissions or address-range membership alone never exclude a function.
Executable PLT stubs, thunks and unreferenced code remain scored.

```sh
python3 scripts/gen_function_scoring.py --corpus-dir CORPUS \
  --check --report /tmp/function-scoring.json
python3 tests/m1-008b_pointer_seeds.py --corpus-dir CORPUS
```

Omit `--check` to regenerate evidence with pinned Ghidra. `--oracle-dir` and
`--output-dir` support isolated toolchain-specific references without replacing
the committed raw corpus. The policy covers all 20 ELF inputs; the m1-008b
discovery gate covers x86-64 `plain_o0` and `cpp_o2`, with recall >=0.98.
The CI M1 job builds the native console and separately generates a matching
corpus, raw oracles and scoring views before running `benchmarks/discovery_gate.py`
over all 20 inputs. Its reports and corpus manifest are retained in the
`m1-discovery-reports` artifact even when a step fails.

Native ELF32/ELF64 discovery shares `.init`, `.fini` and `.plt` section-start
seeds, alongside unwind-index entries, PLT metadata, flow-confirmed
initializer/data pointers and the existing batched flow walker.
Established function entries can seed pure direct-jump thunk destinations,
optionally after one contiguous instruction with no SLEIGH p-code operations.
Rebuild the console with `native/build_console.sh` to supply explicit `no_op`
and `pure_jump` evidence. Missing evidence fails closed. Multiple prefixes,
conditional/interior branches, effects, weak seeds and jump chains returning
into their own body do not establish additional functions.

ELF/PE discovery now uses the generic SLEIGH worklist over native mappings;
without the optional console, only structural facts are retained. The
`x86_decoder` discovery feature and hand-versus-console comparison scripts
are removed. The small instruction decoder remains for listing and graph
consumers, not as a discovery accelerator.

ELF PIE addresses use Ghidra's loaded coordinate system: a zero-based ELF64
receives bias `0x100000`, ELF32 `0x10000`; nonzero prelinked bases are preserved.
REL, RELA and RELR pointer words are materialized with ELF width/endianness.
Native memory, console images and both worker paths share those loaded bytes,
including BSS zero-fill. Scoring performs no address normalization.

The all-20 discovery gate reports **20 pass, 0 fail, 0 skipped**, with the
architecture check passing and precision/recall 1.0 on every x86-64, i386,
AArch64 and PowerPC BE32 row. The separate stripped-DOL acceptance matches
634/644 reference functions (recall 0.984472; precision 0.940653).
These are discovery results, not a claim of complete program-model parity.

## Support matrix

| Input | Structural native import | Native flow/decode/decompile |
|---|---|---|
| ELF x86-64 | supported | **supported and gated** |
| PE32+ x86-64 | supported | in progress |
| ELF AARCH64 LE64 | supported | discovery gated; decompile parity pending |
| ELF ARM LE32 | supported | selected SLEIGH bundle required; not parity-gated |
| ELF MIPS LE32 | supported | selected SLEIGH bundle required; not parity-gated |
| ELF RISC-V LE64 | supported | selected SLEIGH bundle required; not parity-gated |
| ELF PowerPC | supported | BE32 discovery gated; e500 parity verified; other configurations not gated |

The PE parser supports PE32+ (x86-64) and PE32 (i386). Non-x86 ELF
imports preserve mappings, symbols, and the entry point for a matching
`VENTRIS_LANGUAGE`, `VENTRIS_LANGUAGE_DIR`, and `VENTRIS_SLA` worker bundle;
the Agent Under Fire e500 bundle is the currently verified non-x86 target.
The catalog itself was exercised against the pinned Ghidra installation.

## Packaging and desktop status

`desktop/ventris-qt` contains the Qt 6 Widgets workstation and CPack TGZ
configuration. `packaging/sbom.py` emits an SPDX 2.3 dependency inventory;
`packaging/update_manifest.py` creates release artifact size/SHA-256 metadata;
`packaging/verify_update.py` verifies downloaded artifacts before use.
This workstation has Qt 6 development files; CMake configure and the
`ventris-qt` target build pass locally, and the app has an offscreen launch
smoke check. CI remains authoritative for the cross-platform package.
CMake configure and visual UI verification remain unavailable on machines
without the Qt development package.

Known limits remain: the all-input discovery gate is incomplete and PE
function-set parity is not claimed. The x86-64 worker needs `VENTRIS_SLA`
and a patched `ghidra_opt`; the API HTTP listener is localhost-oriented and
does not provide authentication; the Python plugin host is the capability
boundary for untrusted scripts. The live overlay was also smoke-tested against
Dolphin 2606a's real GDB stub using the Agent Under Fire RVZ. A live read at
0x80000000 returned the game ID bytes `GW7E69`.
