# Ventris

Ventris turns one native function into defensible C.

```text
binary + function address + target facts
                  |
          load -> lift -> analyze -> render
                  |
             C + diagnostics
```

The core is a Rust library pipeline. The CLI, Python package,
and editor integrations are adapters over that same implementation; they do not
own analysis logic.

## Status

Ventris is an early function decompiler, not a Ghidra replacement and not yet a
matching-C engine.

The useful, tested path is:

- bounded image loading and address-space-aware function selection;
- architecture-neutral p-code lifting;
- control-flow, SSA, call, type, and aggregate recovery;
- deterministic structured-C rendering;
- explicit unknowns, confidence, and provenance rather than invented types;
- optional target/SDK metadata supplied as evidence.

### The Ghidra decompiler port

`ARCHITECTURE.md` declares the migration order `SLEIGH -> p-code ->
Heritage/SSA -> ActionDatabase/Rule passes`. The lifter was a genuine port; the
back half was not, and could not be, because Ghidra's passes rewrite a mutable
p-code graph while Ventris built C expressions directly.

`ventris_decompiler::graph` is that back half, ported from Ghidra 12.1.3: the
mutable graph object model, location refinement, call/store/return guards,
Heritage with real `MULTIEQUAL` placement and renaming, the Action and Rule
framework, `ActionDeadCode` including dead frame stores, `ActionNonzeroMask`,
`SubvariableFlow` with the `RuleSubvar*` family, `ActionInferTypes`, `FuncProto`
argument recovery, `Cover` live ranges with `ActionMergeCopy`/`MergeAdjacent`/
`MergeType`, `ActionSetCasts`, 61 `ruleaction` expression rules,
`ActionDeterminedBranch`/`RedundBranch`/`Unreachable`/`DoNothing`/
`NormalizeBranches`/`Cse`/`MultiCse`, `ActionReturnRecovery`/`ActiveReturn`,
`ActionNameVars`, `JumpBasic` table recovery with `ActionSwitchNorm`,
`ActionStackPtrFlow`, `ActionConditionalConst`/`ConditionalExe`/`Deindirect`/
`ConstantPtr`, and `CollapseStructure` with natural-loop analysis
(`labelLoops`, `LoopBody::findBase`/`findExit`, `markExitsAsGotos`).

That is **125 of Ghidra's 162 live `Rule` subclasses (77%)** and **32 of its 72
live `Action` subclasses (44%)**. The port is **not** complete: 37 rules and 40
actions remain.

Both figures are counted mechanically and can be rechecked: strip `//` and
`/* */` comments from the pinned headers, match `class X : public Rule` and
`class X : public Action`, and intersect with `pub struct X` in
`crates/ventris-decompiler/src/graph`. Ghidra's headers also declare 6 rules and
3 actions entirely inside comments — `RuleRightShiftSub`, `RuleUndistribute`,
`RuleShiftLess`, `ActionCse` and others — which are not part of the build and so
are not counted. `ActionCse` is the one exception in the other direction: it is
ported here and registered, but Ghidra ships it commented out, so this
decompiler runs a pass Ghidra does not.

The count understates action coverage in one respect: `ActionHeritage`,
`ActionSetCasts`, `ActionDeadCode` and `ActionMapGlobals` are ported as the
`heritage`, `casts`, `deadcode` and `stackframe` modules and cited there against
the C++ they came from, but only `ActionDeadCode` also exists as a same-named
struct. Fifteen further actions are recorded in `CHANGELOG.md` as needing state
this graph does not carry — Ghidra's persistent mutable `BlockGraph`, its
`ScopeLocal` symbol table, `FuncProto` locks, the `LanedRegister` and `SegmentOp`
registries, or per-varnode flags such as a direct-write mark or a consumed-byte
mask.

Select it with `VENTRIS_PIPELINE=graph`. Measured against the Ghidra 12.1.3
decompiler on all 37 hash-verified corpus functions, the graph path leads the
shipping address-ordered path on seven of the census families and ties four:

| Family | Address-ordered | Graph |
|---|---:|---:|
| agrees | 19 | **22** |
| unstructured-control-flow | 15 | **11** |
| missing-loop-or-switch | 11 | **5** |
| excess-casts | 5 | **0** |
| oversized-expression | 3 | **0** |
| return-presence | 3 | **1** |
| unreduced-flag-expression | 1 | **0** |
| call-census | **3** | 4 |

It is still opt-in, and the reason is now understood rather than merely
measured. It fails `corpus-smoke`'s semantic comparison on five PS2 `alloc*`
functions, on two dimensions, and neither is a defect in this path:

- **`declaration_order`** expects no locals, because the C++ source writes
  `enemyEntities[enemyCount++]` and C has no post-increment expression. Ghidra
  declares a local here too — its oracle for `allocEnemyEntity` is
  `int iVar1; iVar1 = *(int *)(this + 0x4b0); ...`. The graph path matches
  Ghidra; the address-ordered path only scores better by duplicating the memory
  read, which is worse output. The baseline is source-derived and unreachable by
  either decompiler without that duplication.
- **`casts`** counts two against one, because the return type is `int64_t`
  where Ghidra says `GameWorld *`. A returned pointer is now reported at pointer
  width when type recovery says the value is a pointer, but it does not fire
  here: the returned expression is `arg0 + 0x4d0`, and the structure recovered
  from this function has only the one field it touches at `0x4b0`, so
  `down_chain` correctly declines to call `0x4d0` a member. Ghidra names it
  because it knows the whole program's `GameWorld`; single-function recovery
  cannot.

So the cutover is blocked on whole-program type information, not on this
pipeline. `agrees` counts functions with no classified difference at all, so it
is the aggregate to read.

| Defect family | Address-ordered | Ported graph |
|---|---:|---:|
| agrees (no classified difference) | 19 | 14 |
| unstructured-control-flow | 15 | 14 |
| missing-loop-or-switch | 11 | 4 |
| excess-casts | 5 | 7 |
| return-presence | 3 | 1 |
| oversized-expression | 3 | 0 |
| missing-conditional | 2 | 3 |
| unresolved-value | 1 | 0 |
| unreduced-flag-expression | 1 | 0 |
| call-census | 1 | 5 |
| missing-parameters | 1 | 3 |

The graph path leads on six families and trails on five. `agrees` requires zero
classified differences, so it lags until the remaining five close.

What the graph path already does that the address-ordered path cannot: name a
value that differs per path instead of dropping it, resolve a definition
independently of address order, propagate a type backwards from a dereference to
the argument it arrived in, and recover a construct from the edge conditions it
actually requires.

Supported containers include raw images, ELF, PE, COFF, Mach-O, Intel HEX,
Motorola S-records, and the named console containers exposed by `--loader`.
Explicit architecture paths include x86-32/64, ARM32/Thumb/AArch64, MIPS32
little- and big-endian, PS1, PS2, N64, RISC-V32/64, PowerPC32/64, GameCube,
6502, Z80, M68K, SH-2/SH-4, and SPU. Console profiles provide the loader, ABI,
address-space, and image-part defaults for common systems from Atari 2600
through PS3/Wii U/Vita/3DS.

This breadth is not a uniform quality claim. Target profiles distinguish a full
pipeline from lift-only support. Current quality evidence is function-specific:
the checked-in legal PS2 corpus has eight source-backed semantic baselines and
three per-function compiler-comparison floors, while the GameCube corpus has
one source-backed semantic baseline. These gates prevent a function from
silently regressing behind a global average.

`tools/quality_census.py` measures the remaining distance to Ghidra's
decompiler across every hash-verified corpus function and ranks the differences
by how many functions each affects. It drives the same public `decompile`
command a user runs, and supplies no metadata, so both sides rely on their own
inference.

On the 37 currently verified functions, 19 show no classified difference,
including 9 of the 10 PS2 functions.

The dominant remaining defect is structuring: 15 functions render explicit
labels and `goto` where Ghidra renders nested statements, and the 11 functions
that also lose a loop or switch are all within that set. The loop reducer itself
is not at fault — it reduces the same loops in isolation — but it requires a
single-entry, single-exit region, so one forward branch past a loop keeps a
whole function in label-and-goto form.

Frame slots are named locals when they are provably private scalars. The
remaining cast differences come from slots written a byte at a time and read as
a word, which one name cannot describe.

One limitation is deliberate. A label whose predecessors are translated after it
cannot be given a merged value, so a register that differs per path is dropped
rather than guessed. Such a function reports no return value instead of one
path's value; `getBuiltInTexture` is the current example.

## CLI

The public CLI has three analysis commands:

```text
ventris inspect <image> [--target <target>] [--loader <loader>] [--base <addr>] [--slice <n>] [--json]
ventris lift <image> <address> (--arch <arch>|--target <target>) [--loader <loader>] [--base <addr>] [--slice <n>] [--limit <n>] [--raw] [--json]
ventris decompile <image> <address> (--arch <arch>|--target <target>) [--metadata <file>] [--loader <loader>] [--base <addr>] [--slice <n>] [--limit <n>] [--raw] [--cache <dir>] [--json]
```

`ventris help` prints the accepted architecture, target, and loader names.

Examples:

```text
ventris inspect game.elf --target ps2
ventris lift game.elf ram::0x125100 --target ps2 --limit 64
ventris decompile game.elf ram::0x125100 --target ps2 --metadata facts.json
```

Addresses may be plain integers when unambiguous or qualified as
`<space>::<offset>`. Qualifying addresses is recommended for images with
multiple address spaces or overlays.

`--metadata` accepts source/user facts for names, nominal types, fields,
symbols, relocations, and object relations. These remain provenance-tagged;
they do not become machine-derived facts. `--cache` stores bounded native
analysis results keyed by image, function, target, and analyzer version.

`--json` returns a stable process envelope:

```json
{"ok":true,"command":"decompile","result":"..."}
```

Failures use a nonzero exit code, write diagnostics to stderr, and return
`{"ok":false,"error":"..."}` when JSON output was requested.

## Library pipeline

Front ends construct a `ventris::Pipeline` and call one of three operations:

- `inspect`: load an image and report loader/address-space facts;
- `lift`: resolve one function and return architecture-neutral p-code;
- `decompile`: lift, analyze, and render one `Decompilation`.

The result carries the rendered C, structured intermediate facts, warnings,
and verification metadata. See [ARCHITECTURE.md](ARCHITECTURE.md) for ownership
and invariants.

## Python

The `ventris-client` package is a dependency-free process adapter. It requires a
matching `ventris` executable on `PATH`, via `VENTRIS_BIN`, or passed explicitly.

```python
from ventris import decompile

source = decompile("game.elf", "ram::0x125100", target="ps2")
print(source)
```

The package exports only `inspect`, `lift`, `decompile`, `version`, and the
low-level `run` helper. It contains no parser or decompiler implementation.

## VS Code

`integrations/vscode` registers **Inspect Binary**, **Lift Function**, and
**Decompile Function**. It spawns the configured executable without a shell and
opens the result in an adjacent editor. The extension contains no server,
project database, or analysis implementation.

## Frozen desktop integration

`desktop/ventris-gpui` remains compatibility-tested and gates releases, but is
frozen: it is not a published artifact, a public analysis API, or a driver of
the core roadmap. Its project-oriented model stays outside the canonical
function pipeline.

## Build and verify

Rust 1.98.0 or newer is required; all crates use Rust edition 2024. The
repository's `rust-toolchain.toml` pins the release toolchain.

```text
cargo build --workspace --locked
cargo test --workspace
PYTHONPATH=python python -S -m unittest discover -s python/tests
```

Development-only corpus, compiler, oracle, packaging, and integration checks
live under `tools/`. They are regression infrastructure, not public product
commands. Corpus checks require independently obtained images
whose hashes match the checked-in metadata; no game image or copied game source
is distributed.

Ghidra differential development checks are pinned to Ghidra 12.1.3
(`Ghidra_12.1.3_build`). Set `GHIDRA_INSTALL_DIR` or pass `--ghidra` to
`tools/diff_ghidra.py`; other Ghidra versions are rejected so reference p-code
cannot drift silently.

To refresh an offline oracle, use `--write-ghidra-fixture <path>` together
with a strict live comparison. The fixture is written directly from Ghidra's
capsule before Ventris is invoked and records the pinned Ghidra release,
language, source-image hash, function range, and function-byte hash. Checked-in
GameCube p-code fixtures cover `TRK_memset`, a conditional branch,
paired-single storage, and load/store-multiple expansion. Separate
decompiler-stage fixtures cover `TRK_fill_mem`, `convert_partial_address`, and
`__FrameCallback`, including recovered prototypes, direct calls, branches,
loops, pointer arithmetic, globals, and mixed-width stores. Both fixture sets
run without Ghidra or the game image during ordinary tests.

## Limits

- A supported decoder or lifter does not imply mature C reconstruction.
- Recovery is bounded to one requested function. Direct callees may be decoded
  only to recover their call prototypes; Ventris does not manage a
  reverse-engineering project.
- Unknown types, unresolved indirect calls, irreducible control flow, and
  target-specific instructions may remain explicit in the output.
- Source reconstruction is semantic, not byte-identical matching C.
- The Python and VS Code packages require a separately installed native binary.

## License and provenance

Ventris is Apache-2.0 licensed. See [LICENSE](LICENSE), [NOTICE](NOTICE), and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Optional Ghidra comparison and
source-backed corpus metadata are development evidence only; their binaries,
source trees, and tools are not redistributed by Ventris.
