# Native-worker feasibility spike (Stage 1.5) — SUCCESS

## What was built (all from pinned Ghidra 12.1.3 sources)
- `third_party/ghidra/decompiler/ghidra_opt`  — protocol decompiler (Ghidra-frontend server)
- `third_party/ghidra/decompiler/sleigh_opt`  — SLEIGH compiler; compiled `x86-64.sla`
  from the install's `x86-64.slaspec` (same release as vendored tree)
- `/tmp/spike/decomp_native` — spike driver: console decompiler built from the
  pinned C++ WITHOUT libbfd (bfd only needed by the stock console loader; we used
  RawBinaryArchitecture: raw load image + SLEIGH, no JVM, no Java, no bfd)

## Proven (no JVM in process tree)
```
load file x86:LE:64:default smoke_bin
adjust vma 0x400000            # raw image maps at 0; ELF base 0x400000
map function 0x400466 add
load function add
decompile add                  # Decompilation complete
print C
  int4 add(void) { ... return unaff_ESI + unaff_EDI; }   # (no proto: raw loader has no syms)
map function 0x40047a main
load function main
decompile main
print C
  xunknown8 main(void) { func_0x00400466(); func_0x00400370(); return 0; }
```
Call target 0x400466 was recovered by SLEIGH flow analysis — semantically correct
(add(2,40)); variable names/signatures absent because the raw loader has no symbol/
type info, which the Stage 3 worker must supply via its program-provider callbacks
(spec 15.2). Address parsing note: console parses leading-zero numbers as octal;
worker protocol must pass addresses as explicit hex (0x…) or space-qualified.

## Notes for the production worker
- ghidra_opt (Ghidra-protocol server over stdio) is the right shell: it is how the
  Java side already drives the same objects; no bfd dependency.
- Program-provider services needed (confirmed by ArchitectureGhidra): bytes, memory
  map, symbols, function boundaries, context registers, types, callfixups, cpool,
  p-code injects, comments, options — exactly spec 15.1 item 5.
- RawLoadImage double-delete trap: on open() failure the destructor dereferences a
  dangling `thefile`; upstream bug, irrelevant for the worker (we supply our own loader).
