# Ventris

Ventris is a lightweight reverse-engineering platform that reuses Ghidra's
proven components (SLEIGH, p-code, the native decompiler) as compiler
technology rather than reimplementing them. It is **not** a Ghidra fork and
claims no drop-in compatibility.

## Architecture: staged migration to JVM-free

| Stage | Architecture | Status |
|---|---|---|
| 0 | Stock Ghidra + pinned reference | pinned: 12.1.3 |
| 1 | Rust core + SQLite store + tiny Java JSON-RPC bridge | **current — working** |
| 2 | Rust core owns all state; Java only on-demand compatibility | next |
| 3 | Native SLEIGH/decompiler C++ worker replaces the bridge | planned |
| 4 | Fully native, JVM-free supported workflow | goal |

The bridge is an implementation aid, not the final architecture. The Rust
core owns durable facts (functions, symbols, xrefs, renames) in SQLite with
provenance, so reopening and browsing a project never requires the JVM —
this is already true and tested. The bridge starts only when you ask for
capabilities that still live in Ghidra (decompilation, disassembly of a
saved program, fresh import).

## Layout

```text
service/           Java JSON-RPC stdio bridge over pinned Ghidra APIs
crates/lre-model   IDs, address-space+offset Address, API rows
crates/lre-db      SQLite durable store (WAL, FKs, schema versioning)
crates/lre-core    CoreService facade: store + bridge orchestration
crates/lre-cli     scriptable CLI over the facade
third_party/ghidra pinned Ghidra 12.1.3 decompiler C++ + language sources
.ghidra-java/      extracted Ghidra Java sources (untracked reference)
```

## Prerequisites

- Rust stable (tested 1.98)
- JDK 25 (the pinned Ghidra's build requirement)
- A Ghidra 12.1.3 installation; default lookup is `$VENTRIS_GHIDRA`, then
  `~/ghidra_12.1.3_PUBLIC`

## Build

```sh
cargo build --workspace
# Java service (one command; jars come from the Ghidra install)
CP=$(find ~/ghidra_12.1.3_PUBLIC/Ghidra -name '*.jar' | grep -vE 'src\.zip|Extension' | tr '\n' ':')
javac -cp "$CP:$HOME/ghidra_12.1.3_PUBLIC/Ghidra/Framework/Generic/lib/gson-2.13.2.jar" \
      -d service/build service/src/main/java/net/ventris/*.java
jar cf service/build/ventris-service.jar -C service/build net
```

## End-to-end

```sh
export VENTRIS_SERVICE_JAR=$PWD/service/build/ventris-service.jar
./target/debug/lre-cli import ./smoke_bin --project ./proj   # bridge: import+analyze+export
./target/debug/lre-cli functions smoke_bin --project ./proj  # store only
./target/debug/lre-cli xrefs smoke_bin --to 00400466 --project ./proj
./target/debug/lre-cli rename smoke_bin 00400466 my_add --project ./proj
./target/debug/lre-cli open smoke_bin --project ./proj       # store-only, no JVM
./target/debug/lre-cli decompile smoke_bin 0040047a --project ./proj  # bridge
./target/debug/lre-cli disasm smoke_bin 00400466 -n 8 --project ./proj
```

## Honest status

- Supported import target: x86-64 ELF (Ghidra loaders).
- Listing/decompile/call-graph work through the pinned Ghidra bridge and the
  decompiler; no capability is claimed native until Stage 3/4 parity tests pass.
- Memory targets (spec 21.4) are not yet measured; no lightness claim is made.
