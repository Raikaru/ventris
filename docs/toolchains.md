# Cross-Compilation Toolchains

Pinned toolchain configuration for multi-architecture corpus generation (`m1-006`).

## Host Toolchains (Fedora 44 baseline)

- **LLVM / Clang**: 22.1.8 (`clang`, `clang++`)
- **LLD Linker**: 22.1.8 (`ld.lld`, invoked via `-fuse-ld=lld`)
- **GNU C/C++ (Host x86-64)**: 16.2.1 (`gcc`, `g++`)
- **MinGW-w64 (PE32/PE32+)**: 16.1.1 (`x86_64-w64-mingw32-gcc`, `i686-w64-mingw32-gcc`)

## Target Sysroots

Non-x86 targets need per-target glibc and libgcc runtime objects. `clang --target=<triple>`
compiles without a sysroot, but the linker needs the target `crt*.o` and `libc.so`.

Install the pinned Debian bookworm sysroots:

```bash
python3 tools/fetch_cross_sysroots.py
```

This downloads the exact package versions below into `third_party/sysroots/` and runs a
PIE link smoke test for every architecture. The directory is `.gitignore`d; only the
script and this document are tracked.

| Target | Pinned packages |
|---|---|
| **aarch64** | `libc6-dev-arm64-cross 2.36-8cross1`, `libc6-arm64-cross 2.36-8cross1`, `linux-libc-dev-arm64-cross 6.1.4-1cross1`, `libgcc-12-dev-arm64-cross 12.2.0-14cross1`, `libgcc-s1-arm64-cross 12.2.0-14cross1` |
| **i386** | `libc6-dev-i386-cross 2.36-8cross1`, `libc6-i386-cross 2.36-8cross1`, `linux-libc-dev-i386-cross 6.1.4-1cross1`, `libgcc-12-dev-i386-cross 12.2.0-14cross1`, `libgcc-s1-i386-cross 12.2.0-14cross1` |
| **PowerPC 32-bit BE** | `libc6-dev-powerpc-cross 2.36-8cross1`, `libc6-powerpc-cross 2.36-8cross1`, `linux-libc-dev-powerpc-cross 6.1.4-1cross1`, `libgcc-12-dev-powerpc-cross 12.2.0-13cross1`, `libgcc-s1-powerpc-cross 12.2.0-13cross1` |

The C++ fixtures additionally use `libstdc++-12-dev-{arm64,i386}-cross` and
`libstdc++6-{arm64,i386}-cross` at `12.2.0-14cross1`, and the corresponding
PowerPC packages at `12.2.0-13cross1`. All six archive SHA-256 values are pinned
in `tools/fetch_cross_sysroots.py`. These are corpus toolchain dependencies,
not Rust crate runtime dependencies. Exception stubs and `-nostdlib++` are
not used.

The Linux gate requires `qemu-i386`, `qemu-aarch64` and `qemu-ppc` (Debian:
`qemu-user`). It executes positive TLS arithmetic and negative throw/catch
inputs on all four ELF targets, using `-L SYSROOT/usr/TARGET` for the cross
loaders and `LD_LIBRARY_PATH=SYSROOT/usr/TARGET/lib` for the target libraries
(preventing host loader-cache paths from selecting a host libc). Windows
executes the same checks natively for MSVC.

`cpp_o2` explicitly uses `-fno-pie -no-pie` on ELF targets. This avoids
host-dependent default PIE selection: Ubuntu 24.04 LLVM 18 PPC C++ PIE output
faulted on both runtime inputs, while its non-PIE output passed both.
The independent `plain_pie` variant remains `-fPIE -pie`.

## Target Architectures for Corpus (`m1-006`)

Each architecture builds the 5 corpus variants:
`{C -O0, C -O2, C++ exceptions+TLS, stripped, PIE}`.

| Architecture | Target Triple | Sysroot Path | C Compiler | C++ Compiler |
|---|---|---|---|---|
| **x86-64** | `x86_64-linux-gnu` | (host) | `clang --target=x86_64-linux-gnu` | `clang++ --target=x86_64-linux-gnu` |
| **x86-32** | `i686-linux-gnu` | `third_party/sysroots/i386` | `clang --target=i686-linux-gnu` | `clang++ --target=i686-linux-gnu` |
| **AArch64** | `aarch64-linux-gnu` | `third_party/sysroots/aarch64` | `clang --target=aarch64-linux-gnu` | `clang++ --target=aarch64-linux-gnu` |
| **PPC32-BE** | `powerpc-linux-gnu` | `third_party/sysroots/powerpc` | `clang --target=powerpc-linux-gnu` | `clang++ --target=powerpc-linux-gnu` |

## Example Invocations

### x86-64
```bash
clang --target=x86_64-linux-gnu -fuse-ld=lld -O2 -s src.c -o x86_64_o2.bin
clang --target=x86_64-linux-gnu -fuse-ld=lld -O2 -fPIE -pie src.c -o x86_64_pie.bin
```

### x86-32
```bash
clang --target=i686-linux-gnu \
  --sysroot=third_party/sysroots/i386 \
  -B third_party/sysroots/i386/usr/lib/gcc-cross/i686-linux-gnu/12 \
  -L third_party/sysroots/i386/usr/lib/gcc-cross/i686-linux-gnu/12 \
  -fuse-ld=lld -O2 -s src.c -o x86_32_o2.bin

clang --target=i686-linux-gnu \
  --sysroot=third_party/sysroots/i386 \
  -B third_party/sysroots/i386/usr/lib/gcc-cross/i686-linux-gnu/12 \
  -L third_party/sysroots/i386/usr/lib/gcc-cross/i686-linux-gnu/12 \
  -fuse-ld=lld -O2 -fPIE -pie src.c -o x86_32_pie.bin
```

### AArch64
```bash
clang --target=aarch64-linux-gnu \
  --sysroot=third_party/sysroots/aarch64 \
  -B third_party/sysroots/aarch64/usr/lib/gcc-cross/aarch64-linux-gnu/12 \
  -L third_party/sysroots/aarch64/usr/lib/gcc-cross/aarch64-linux-gnu/12 \
  -fuse-ld=lld -O2 -s src.c -o aarch64_o2.bin

clang --target=aarch64-linux-gnu \
  --sysroot=third_party/sysroots/aarch64 \
  -B third_party/sysroots/aarch64/usr/lib/gcc-cross/aarch64-linux-gnu/12 \
  -L third_party/sysroots/aarch64/usr/lib/gcc-cross/aarch64-linux-gnu/12 \
  -fuse-ld=lld -O2 -fPIE -pie src.c -o aarch64_pie.bin
```

### PowerPC 32-bit Big-Endian
```bash
clang --target=powerpc-linux-gnu \
  --sysroot=third_party/sysroots/powerpc \
  -B third_party/sysroots/powerpc/usr/lib/gcc-cross/powerpc-linux-gnu/12 \
  -L third_party/sysroots/powerpc/usr/lib/gcc-cross/powerpc-linux-gnu/12 \
  -fuse-ld=lld -O2 -s src.c -o ppc32_o2.bin

clang --target=powerpc-linux-gnu \
  --sysroot=third_party/sysroots/powerpc \
  -B third_party/sysroots/powerpc/usr/lib/gcc-cross/powerpc-linux-gnu/12 \
  -L third_party/sysroots/powerpc/usr/lib/gcc-cross/powerpc-linux-gnu/12 \
  -fuse-ld=lld -O2 -fPIE -pie src.c -o ppc32_pie.bin
```

## Corpus verification and lock maintenance

`bash tests/m1-006_corpus.sh` checks the full 25-entry matrix; only the five
MSVC entries may be skipped on a non-Windows host. `--msvc-only` requires all
five MSVC entries to build. The gate rebuilds the CLI and keeps its manifest,
report, binaries and import database in a temporary directory.

`--update-report` explicitly replaces `benchmarks/reports/m1-006.json`.
`python3 scripts/gen_corpus.py --update-lock` refreshes source digests only;
it preserves every recipe and matrix entry and does not build binaries.
Recipe changes are reviewed edits to `tests/corpus.lock.json`. Per-run binary
hashes belong in the generated manifest, not the cross-host recipe lock.

MSVC builds put `/Fo` objects and `/Fd` compiler state under the temporary
output directory. `/DEBUG:FULL /PDB:...` produces the separate linker PDB.
Validation checks MSF block/stream bounds, PDB Info and DBI ages, exact RSDS
GUID/age and filename association, and complete public function symbol records.
The primary has no debug-directory reference; every executable section retains
the twin's name, RVA, virtual/raw sizes and bytes.

## Ghidra corpus references (`m1-007`)

On Linux, install JDK 25 and the pinned Ghidra 12.1.3 release, then run:

```bash
python3 scripts/gen_corpus.py --architectures x86_64,i386,aarch64,powerpc --out-dir /tmp/ventris-corpus
python3 scripts/gen_oracle.py --corpus-dir /tmp/ventris-corpus --report /tmp/ventris-oracle-report.json
python3 tests/m1-007_oracle_test.py
```

`VENTRIS_GHIDRA` or `--ghidra` selects the installation; the default is
`~/ghidra_12.1.3_PUBLIC`. CI verifies the official release archive's SHA-256.
The generator rebuilds the existing Java bridge once when analysis is needed,
imports each stripped primary into an isolated temporary project, runs default
Ghidra analysis, and exports all non-external function entries. It never uses
the unstripped twins as analysis inputs.

References are `oracle/<binary-sha256>.json`; `--output-dir` selects another cache.
Each records the upstream version/revision, bridge source digest, selected
language, image base and sorted unique entries. Addresses remain **Ghidra
virtual addresses**, not RVAs or native-loader addresses. Automatic language
selection is preserved: Ghidra selects `PowerPC:BE:32:e500` for the local PPC
fixtures; the native corpus lock's `default` language is not an oracle override.
This task does not change discovery scoring or the existing libc reference.

Valid cache hits do not launch Java or rewrite references. `--check` validates
without generating; missing primaries and missing/invalid references are
reported as skipped with reasons and make the gate fail. Validation still
requires the pinned installation metadata and current bridge sources.
The m1-007 gate requires all **20 ELF entries**, with zero allowed skips; the
separate five MSVC entries are outside the original m1-007 acceptance scope.
The committed generation report is `benchmarks/reports/m1-007.json`.

## Native language selection (`m1-008`)

`python3 tests/m1-008_languages.py` checks six native imports against the pinned
Ghidra `.ldefs` entries and compiled SLA files: ELF32 i386, ARM little-endian,
ARM BE32, ARM BE8, the existing PE32 fixture, and an ELF64 x86-64 control.
It requires Clang/LLD, Rust and the Ghidra installation metadata; it does not
launch the Java bridge. Compiler probes and import databases are temporary;
the committed corpus matrix is unchanged.

ARM ELF `EF_ARM_BE8` (`0x00800000`, defined in the public ELF SDK header
`elf.h`) denotes big-endian data with little-endian instructions. Selection
uses this flag rather than `EI_DATA` alone: the pinned `ARM.ldefs` entry is
`ARM:LEBE:32:v7LEInstruction`, with `instructionEndian="little"`. Ordinary
big-endian ARM remains `ARM:BE:32:v7`; ELF32 i386 and PE32 remain
`x86:LE:32:default`. This verifies language selection, not ARM decompile parity.

`--update-report` explicitly writes `benchmarks/reports/m1-008.json`; normal
runs leave the working tree unchanged. All six cases must pass, with zero
allowed skips.
