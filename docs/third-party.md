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

## Instruction flow metadata

`native/ventris_flow.hh` follows Ghidra 12.1.3
`SleighInstructionPrototype.walkTemplates`, `flowListToFlowType`,
`gatherFlags` and `convertFlowFlags` (Apache-2.0). The pinned-tree patch
collects template flow facts during ordinary SLEIGH p-code generation, not
through a second decode. Instruction-local labels and `inst_start`/`inst_next`
branches are not exported as machine flow references.

`FLOW` includes conditional/terminal classification, actual RETURN p-code
evidence, and individual delay-slot lengths. Total length includes slots;
slot effects do not alter the parent's prototype flow classification.
Discovery follows the reported fallthrough, including conditional returns,
and does not invent fallthrough after terminal calls. Console consumers require
the enriched protocol; rebuild both native binaries after this cutover.
Ordinary decompiler translation does not collect the optional flow metadata.

## Minimal direct-jump thunks

The approved M1 prerequisite follows the single-jump case in Ghidra 12.1.3
`CreateThunkFunctionCmd.getSimpleFlow` (Apache-2.0), checked in the extracted
Java source. The native rule is narrower: an established entry must emit
exactly one direct SLEIGH `BRANCH` operation, with no additional p-code effects,
optionally preceded by one contiguous empty-p-code instruction.
The approved prefix extension follows `getThunkedAddr` lines 567–572, which
skip one empty-p-code instruction and explicitly mention ENDBR64. The console
emits `no_op=1` only after successful decoding with an empty p-code operation
list; no mnemonic or opcode-byte matching is used in discovery. Further prefixes
and missing evidence are rejected.
Its destination must independently decode and survive body-containment
reconciliation. Weak data/boundary candidates do not establish further entries.
Jump xrefs retain `native-import:thunk` provenance only for distinct retained
destinations. This is not the full multi-instruction, indirect or call-return
thunk analyzer.

The bounded indirect-linkage prerequisite also follows `getThunkedAddr` and
`addRegisterUsage` in `CreateThunkFunctionCmd` (Apache-2.0), with stricter
fail-closed handling of unknown inputs and partial register aliases.
`native/ventris_linkage.hh` consumes SLEIGH p-code and reuses the decompiler's
registered `OpBehavior` constant evaluators. It tracks pointer-slot identity,
not invented external pointer values. Stores, calls, other control flow and
unused non-flag register writes are rejected. Bounds are 8 instructions,
128 operations per instruction and 64 live values. Unique temporaries are
discarded between instructions. A successful query alone does not create a
function; discovery must associate the slot with loader metadata.
Seeded ELF/PE imports and the DOL sweep share the same recognition rule:
an unconditional branch target can establish a separate entry only when
bounded SLEIGH linkage evidence resolves a loader-recorded external slot.
Conditional branches alone do not establish linkage entries. Local unresolved
inputs require independent caller evidence, not an assumed global register value.
For PIC linkage, the native evaluator follows at most 64 straight-line caller
instructions, accepting direct transfers only to the next instruction (PC
capture). Stores in this prefix do not supply memory values; only proven register
constants propagate. The linkage body retains the strict 8-instruction rule.
After strong and weak flow closure, every validated incoming caller must resolve
the same slot and length. Conditional or setup-bypassing entries, unknown inputs
and conflicting callers reject promotion. Already-decoded flow filters probes to
contiguous indirect-branch-ending sequences; successful promotion splits actual
instruction ownership rather than retaining the stub in its caller's body.

PLT boundaries use ELF `sh_entsize`, executable mapped sections, and the
canonical layouts documented by LLVM lld 19.1
([AArch64](https://github.com/llvm/llvm-project/blob/llvmorg-19.1.0/lld/ELF/Arch/AArch64.cpp),
Apache-2.0 WITH LLVM-exception): a 32-byte resolver header and 16-byte entries.
The [x86](https://github.com/llvm/llvm-project/blob/llvmorg-19.1.0/lld/ELF/Arch/X86.cpp)
and [x86-64](https://github.com/llvm/llvm-project/blob/llvmorg-19.1.0/lld/ELF/Arch/X86_64.cpp)
layouts use a 16-byte resolver header and 16-byte entries; `.plt.sec`
has no header. Missing entry widths are inferred only when `.rel[a].plt`
record counts account for the entire canonical table. Unknown layouts and
zero-width `.plt.got` sections are rejected.
These are untrusted candidates, not functions. The table-specific SLEIGH query
permits unused register setup but still rejects unknown inputs, stores, calls
and non-indirect terminal flow; its result must fit the entry and resolve a
loader-recorded external slot. Generic branch-target recognition remains strict.

## Native function-start pattern matching

`native/ventris_patterns.hh` follows Ghidra 12.1.3 BytePatterns (Apache-2.0):
`Patterns`, `Pattern`, `PatternPairSet`, `DittedBitSequence`, `AlignRule`,
`LanguageConstraint`, `CompilerConstraint`, and `generic.constraint.DecisionNode`.
The existing native XML parser reads installed `patternconstraints.xml` and the
selected pattern files. Selection uses the loaded language and resolved compiler
specification, including more-specific decision precedence; it does not infer a
compiler from opcode bytes.

The console command `functionstarts <start> <end> ...` accepts exclusive-end
mapped ranges and returns `PATTERNS` JSON: instruction alignment, shared source
rules with ordered action attributes, and address/rule matches. Matching preserves
hex/binary wildcards, explicit marks, pair fixed-bit thresholds and raw-start
alignment. XML integers retain `SpecXmlUtils.decodeInt` low-32-bit semantics.
Parsed sequences are shared across pairs; bounded scan windows retain lookahead.
These are raw matches, not functions. Consumers must enforce action prerequisites
and ownership; `validcode="function"` is never new-function evidence.

ELF imports carry the base compiler specification from the pinned processor
`.opinion` files (Apache-2.0): x86 and RISC-V use `gcc`; AArch64, ARM, MIPS
and PowerPC use `default`. Mapped console images retain this selection rather
than replacing it with the architecture default (Windows on x86). This is
base load-spec selection, not producer identification from Go/Swift metadata.


## Native instruction-flow facts

`native/ventris_flow.hh` follows Ghidra 12.1.3
`SleighInstructionPrototype.walkTemplates`, `flowListToFlowType` and
`convertFlowFlags` (Apache-2.0). It retains template distinctions that resolved
p-code alone loses: instruction-local labels and J_START/J_NEXT are not
independent machine branches.

The `flow <address> ...` response carries terminal/conditional flags, actual
RETURN p-code presence and delay-slot lengths. Parent instruction lengths
include their delay slots; slot instructions remain separately queryable.
Conditional returns preserve their fallthrough. The console flushes once per
batch, including error rows, rather than once per instruction.

## Function-start eligibility and scheduling

`crates/lre-core/src/native/discovery/patterns.rs` follows Ghidra 12.1.3
`FunctionStartAnalyzer`, `PseudoDisassembler`, `RepeatInstructionByteTracker`
and `PossibleDelayedFunctionCreator` (Apache-2.0). This is entry selection
against retained native facts, not a replacement for all BytePatterns
annotations or context analysis.

Creation requires alignment, a valid decoded instruction and the action's
preconditions. Numeric `validcode` counts contiguous parent instructions, not
delay slots; validation may cross existing instruction boundaries without
granting ownership of another function. Bounded validation rejects unavailable
bytes, zero prefixes, invalid/repeated decoding, overlapping instructions,
known pointer data and offcut references. Subroutine checks distinguish
terminal instructions from actual RETURN p-code and known callees.
`validcode="function"` only applies at an already-defined function.
Rules needing unavailable section/context facts abort selection rather than
silently dropping those prerequisites.

Loader-derived discovery settles first. Definite/possible pattern candidates
then form a separate creation batch; they are not merged as relocation roots.
Possible entries are checked again after their disassembly exposes references:
conditional targets and entries reached from established functions are not
new functions. Definite actions take precedence over possible actions at the
same address. Rejected bodies are reconciled with their surviving owner before
the existing PIC linkage pass.

## ELF loaded images and worker memory

ELF record layouts and relative-relocation constants are checked against the
public GNU C Library `elf.h` SDK header (LGPL-2.1-or-later). No implementation
code is copied. REL/RELA/RELR materialization uses ELF word size and byte order.
External GLOB_DAT/JUMP_SLOT records use the same public header constants.
Their linked dynamic symbol table supplies loaded GOT-slot identities for
ELF32/ELF64 REL/RELA in the image's byte order. Recording a slot does not
establish a function; that requires independent instruction/flow evidence.
Ghidra 12.1.3 `ElfLoaderOptionsFactory` and `ElfProgramBuilder` (Apache-2.0)
establish the default image-base policy: zero-based ET_DYN images receive
0x100000 for ELF64 or 0x10000 for ELF32; prelinked bases remain unchanged.

Worker short reads follow `DecompileCallback.getBytes` lines 150–171 and
`ArchitectureGhidra::getBytes` (`ghidra_arch.cc`, lines 723–759), Apache-2.0:
a mapped starting address may return available bytes followed by zeros in
the requested-size buffer; an unmapped start remains unavailable. Ordinary
Core memory reads retain their strict region-boundary contract.
