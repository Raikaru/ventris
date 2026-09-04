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
