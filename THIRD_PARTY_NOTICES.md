# Third-party notices

Ventris's own source is licensed under Apache-2.0. The root `LICENSE` and
`NOTICE` files apply to the Ventris distribution itself.

## Ghidra-compatible formats and algorithms

`ventris-sleigh` implements the compiled-SLEIGH container, packed marshal
records, constructor decisions and context actions, and p-code templates
described by Ghidra 12.1.3 source. The compatibility reference is upstream tag
`Ghidra_12.1.3_build`, commit
`8b4c91d4d5bd1549622bfbade0df199585b98365`, primarily
`decompile/cpp/slaformat.cc`, `marshal.cc`, `slghpattern.cc`,
`slghpatexpress.cc`, `slghsymbol.cc`, `semantics.cc`, `context.cc`, and
`sleigh.cc`. Ghidra is licensed under Apache-2.0.

The bundled x86, ARM, AArch64, MIPS, PowerPC, RISC-V, 68020, SuperH, 6502,
and Z80 `.sla` files were built by that Ghidra release from its Apache-2.0
processor sources. The bundled `ppc_gekko_broadway.sla` was built with Ghidra
12.1.3 from Apache-2.0 Cuyler36/Ghidra-GameCube-Loader commit
`921504c9ddba6e8d9b3655b665a60f1a33306220`; its SHA-256 is
`aa25bde9ffb8f6366e1e490c6a488b1aced4665dc6c4f2fdca9cc598d5530975`.
The bundled `spu.sla` was built with Ghidra 12.1.3 from Apache-2.0
aerosoul94/GhidraSPU commit
`b85076dcecf30cf9db6ada506d69dd64972a00d7`; its SHA-256 is
`9c04f6f759962855c2f406a9f812cc886c621c634b3b5768ca350b6f67944d08`.

`tools/diff_ghidra.py` optionally compares Ventris output against a separately
installed Ghidra 12.1.3. The official release archive has SHA-256
`93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54`.

## Runtime crates

`ventris-sleigh` uses `miniz_oxide` (MIT OR Zlib OR Apache-2.0) to inflate the
zlib payload in compiled `.sla` files. Its transitive `adler2` dependency is
licensed under 0BSD OR MIT OR Apache-2.0.

## Optional corpus metadata

Development-only corpus checks consume source-backed metadata so maintainers
can reproduce smoke checks against images they obtained independently. The
repository does not ship those images or copied game source. Each entry records
its source commit and the license value observed for the source project:

| Project | Metadata use | Recorded license | Distribution boundary |
|---|---|---|---|
| `n64decomp/perfect_dark` | N64 symbols and function addresses | MIT | Metadata only; no ROM or source bundled |
| `ACreTeam/ac-decomp` | GameCube symbols and function addresses | CC0-1.0 | Metadata only; no image or source bundled |
| `crowded-street/3s-decomp` | PS2 symbols and function addresses | AGPL-3.0 | Metadata only; no image or source bundled |
| `pret/pokeemerald` | GBA symbols and function addresses | unspecified | Metadata only; no ROM or source bundled |

The `unspecified` value is intentional. It must not be changed to a guessed
license, and a release must not add the referenced ROM or source without a
separate provenance and redistribution review.

## Build-time tools

The VS Code integration uses development-only npm packages listed in
`integrations/vscode/package-lock.json`. They are not included in the runtime
