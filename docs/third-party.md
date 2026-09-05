# Third-party references and corpus toolchains

## GCC target runtime libraries

The m1-006 corpus links real libstdc++ and libgcc target runtimes from the
SHA-256-pinned Debian packages in `tools/fetch_cross_sysroots.py`. They are
build/test corpus dependencies, not new dependencies of the Rust application.
GCC runtime libraries are distributed under GPLv3 with the
[GCC Runtime Library Exception 3.1](https://www.gnu.org/licenses/gcc-exception-3.1.html).
The extracted Debian packages retain their copyright notices under `usr/share/doc`.

## MSF/PDB format reference

The corpus PDB validator follows the public LLVM format documentation:
[MSF](https://llvm.org/docs/PDB/MsfFile.html),
[PDB Info](https://llvm.org/docs/PDB/PdbStream.html),
[DBI](https://llvm.org/docs/PDB/DbiStream.html), and
[CodeView symbols](https://llvm.org/docs/PDB/CodeViewSymbols.html).
LLVM is licensed under Apache-2.0 with LLVM exceptions
([license](https://llvm.org/LICENSE.txt)). No proprietary tool output or leaked
source is used as an oracle.

## GameCube DOL format

The independent DOL parser follows the public section-table layout documented
by Dolphin's [DolReader.h](https://github.com/dolphin-emu/dolphin/blob/master/Source/Core/Core/Boot/DolReader.h)
and [DolReader.cpp](https://github.com/dolphin-emu/dolphin/blob/master/Source/Core/Core/Boot/DolReader.cpp)
(GPL-2.0-or-later). No Dolphin implementation code is copied or linked.
Sparse console images use the pinned Ghidra `LoadImageXml` implementation
(`third_party/ghidra/decompiler/loadimage_xml.cc`, Apache-2.0), without modifying
the upstream tree. The private game binary and matching symbol ELF are local
gate inputs, not redistributed repository fixtures.

## ELF unwind indexes and synthetic external evidence

The `.eh_frame_hdr` reader follows the published
[LSB DWARF extensions](https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/dwarfext.html)
and Ghidra 12.1.3's `ExceptionHandlerFrameHeader`, `FdeTable`,
`DwarfEHDataDecodeFormat` and `DwarfEHDataApplicationMode` (Apache-2.0).
The implementation reads metadata; it does not copy Ghidra implementation code.

The oracle-only `ExportFunctionScoring.java` API calls were checked against
the installed 12.1.3 Java sources. `ElfProgramBuilder.createExternalBlock`
and `evaluateElfSymbol` establish the positive synthetic-placeholder evidence:
an artificial `EXTERNAL` block sourced from `Elf Loader`, plus a thunk to an
external function. The exporter lives outside the runtime bridge and does not
change its fingerprint or the immutable raw oracle references.

## Minimal direct-jump thunks

The approved M1 prerequisite follows the single-jump case in Ghidra 12.1.3
`CreateThunkFunctionCmd.getSimpleFlow` (Apache-2.0), checked in the extracted
Java source. The native rule is narrower: an established entry must emit
exactly one direct SLEIGH `BRANCH` operation, with no additional p-code effects.
Its destination must independently decode and survive body-containment
reconciliation. Weak data/boundary candidates do not establish further entries.
Jump xrefs retain `native-import:thunk` provenance only for distinct retained
destinations. This is not the full multi-instruction, indirect or call-return
thunk analyzer.
