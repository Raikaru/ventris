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
