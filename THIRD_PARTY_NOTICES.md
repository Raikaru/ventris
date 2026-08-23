# Third-party notices

Ventris's own source is licensed under Apache-2.0. The root `LICENSE` and
`NOTICE` files apply to the Ventris distribution itself.

## Optional development oracle

`tools/diff_ghidra.py` can compare Ventris's native lift against a separately
installed Ghidra build. The repository includes no Ghidra binaries, Java
classes, native decompiler, or protocol implementation; the tool and
checked-in semantic fixtures are development-only.

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
