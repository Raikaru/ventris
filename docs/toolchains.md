# Cross-Compilation Toolchains

Pinned toolchain configuration for multi-architecture corpus generation (`m1-006`).

## Pinned Versions

- **LLVM / Clang**: 22.1.8 (`clang`, `clang++`)
- **LLD Linker**: 22.1.8 (`ld.lld`, invoked via `-fuse-ld=lld`)
- **GNU C/C++ (Host x86-64)**: 16.2.1 (`gcc`, `g++`)
- **MinGW-w64 (PE32/PE32+)**: 16.1.1 (`x86_64-w64-mingw32-gcc`, `i686-w64-mingw32-gcc`)

## Target Architectures for Corpus (`m1-006`)

Each architecture builds the 5 corpus variants:
`{C -O0, C -O2, C++ exceptions+TLS, stripped, PIE}`.

| Architecture | Target Triple | C Compiler | C++ Compiler | Linker Flags |
|---|---|---|---|---|
| **x86-64** | `x86_64-linux-gnu` | `clang --target=x86_64-linux-gnu` | `clang++ --target=x86_64-linux-gnu` | `-fuse-ld=lld` |
| **x86-32** | `i686-linux-gnu` | `clang --target=i686-linux-gnu` | `clang++ --target=i686-linux-gnu` | `-fuse-ld=lld` |
| **AArch64** | `aarch64-linux-gnu` | `clang --target=aarch64-linux-gnu` | `clang++ --target=aarch64-linux-gnu` | `-fuse-ld=lld` |
| **PPC32-BE** | `powerpc-linux-gnu` | `clang --target=powerpc-linux-gnu` | `clang++ --target=powerpc-linux-gnu` | `-fuse-ld=lld` |

## Example Invocations

### x86-64
```bash
clang --target=x86_64-linux-gnu -fuse-ld=lld -O2 -s src.c -o x86_64_o2.bin
clang --target=x86_64-linux-gnu -fuse-ld=lld -O2 -fPIE -pie src.c -o x86_64_pie.bin
```

### x86-32
```bash
clang --target=i686-linux-gnu -fuse-ld=lld -O2 -s src.c -o x86_32_o2.bin
clang --target=i686-linux-gnu -fuse-ld=lld -O2 -fPIE -pie src.c -o x86_32_pie.bin
```

### AArch64
```bash
clang --target=aarch64-linux-gnu -fuse-ld=lld -O2 -s src.c -o aarch64_o2.bin
clang --target=aarch64-linux-gnu -fuse-ld=lld -O2 -fPIE -pie src.c -o aarch64_pie.bin
```

### PowerPC 32-bit Big-Endian
```bash
clang --target=powerpc-linux-gnu -fuse-ld=lld -O2 -s src.c -o ppc32_o2.bin
clang --target=powerpc-linux-gnu -fuse-ld=lld -O2 -fPIE -pie src.c -o ppc32_pie.bin
```
