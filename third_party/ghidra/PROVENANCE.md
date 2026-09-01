# Provenance

Ghidra release **12.1.3**, taken from `/home/raikaru/ghidra_12.1.3_PUBLIC`.

`decompiler/` is `Ghidra/Features/Decompiler/src/decompile/cpp` verbatim. `languages/<target>/` is language
source only; the compiled `.sla` files are build products and are not vendored.

`typeinfo/generic_clib.gdt` is Ghidra's C library type archive, copied
as-is. It is data, not source: Ghidra applies its prototypes to functions by
name, so reproducing its output requires the same data.

Every file is hashed in `MANIFEST.sha256`. `tools/vendor_ghidra.py --verify`
checks the tree against it, and the gate runs that check: this project drives
Ghidra's C++ unmodified, so an edit to it has to be a build failure rather than a
review comment.

Ghidra is Apache License 2.0. See `NOTICE` and `THIRD_PARTY_NOTICES.md`.
