# Ventris

Ventris is named for Michael Ventris, who deciphered Linear B from surviving
inscriptions. The project is a dependency-free command-line, Python, and HTTP
surface for bounded binary analysis. The Rust executable is the source of
truth; the Python package forwards requests to it instead of duplicating
parsing or analysis logic.

The current release line is a **0.1.0 alpha**. The checked-in corpus and
integration gates prove the documented paths and fixtures; they do not claim
full Ghidra parity, complete game-type recovery, or matching-C output for
arbitrary binaries. Ghidra is an optional development oracle only and is not
required at runtime.

Ventris is now **game-first**. Generic lifting and C rendering remain the
substrate, but the product target is readable, ABI-correct, and eventually
byte-matchable console-game C/C++. Game analysis keeps console calling
conventions, nominal SDK/game types, field names, and source-level lifetimes
explicit instead of flattening them into semantically equivalent integers.

## Install

### Native executable

Build the executable from a checkout:

```text
cargo build --release --locked -p ventris-cli
```

For normal users, use the platform-specific native archive attached to a
release. A native executable is required by the Python client and editor
integrations.

### Python client

The Python distribution is a dependency-free forwarding client. It does not
bundle or download the Rust executable. The deliberate installation contract is
to install the matching native release archive separately, then expose its
binary through `VENTRIS_BIN` or `PATH`:

```text
python -m pip install ventris-client
set VENTRIS_BIN=C:\path\to\ventris.exe
```

On POSIX systems, put the matching `ventris` executable on `PATH` instead of
setting `VENTRIS_BIN`. The wrapper locates `ventris-rs` and `ventris-native` as
compatibility names, then raises a structured error if no executable exists.

The wrapper also locates the newest workspace `target/release` or
`target/debug` binary when run from a checkout. This checkout convenience is
not a substitute for installing a released executable. The client and native
archive must carry the same Ventris version; the release gate verifies this
pairing in a fresh virtual environment.

## Editor integrations

Build the VS Code extension without installing `vsce`:

```text
cd integrations/vscode
npm ci
npm run package
code --install-extension dist/ventris-binary-analysis-0.1.0.vsix
```

The Windows host smoke runner exercises the packaged extension's registered
commands, HTTP error handling, server restart, result documents, and JSONL
batch transport. Set `VENTRIS_ACCEPTANCE_BINARY`, `VENTRIS_ACCEPTANCE_FIXTURE`,
`VENTRIS_ACCEPTANCE_FUNCTION_ADDRESS`, and `VENTRIS_ACCEPTANCE_EXTENSION_PATH` to
the Ventris executable, a small PE fixture, its supported function address, and
the installed extension directory, then run:
```text
npm run acceptance
```
The VS Code integration forwards the `ventris.loader` setting (`auto`, `raw`,
`elf`, `pe`, `macho`, `coff`, `ihex`, or `srec`), optional `ventris.base`, and
optional universal Mach-O `ventris.slice` setting to the HTTP API. Command
arguments `{ loader, base, slice }` override those settings for one request.
Registered commands cover inspect, binary revision diffing, function discovery,
resolve, lift, native decompilation, game type recovery, source reconstruction,
and JSONL batch execution.


## CLI contract

```text
ventris corpus [--json]
ventris project init <image> <project> [options]
ventris project analyze <project> (--arch <arch>|--target <target>) [--limit <n>] [--json]
ventris project show <project> [--json]
ventris project runtime <project> <trace> [--json]
ventris project assets <project> <manifest> [--json]
ventris discover <image> (--arch <arch>|--target <target>) [options]
ventris diff <before> <after> [--target <target>] [--loader <loader>] [--base <addr>] [--slice <n>] [--region <name>] [--json]
ventris inspect <image> [--target <target>] [--loader <loader>] [--base <addr>] [--slice <n>] [--json]
ventris resolve <image> <address> [--target <target>] [--loader <loader>] [--base <addr>] [--slice <n>] [--json]
ventris lift <image> <address> (--arch <arch>|--target <target>) [--loader <loader>] [--base <addr>] [--slice <n>] [--limit <n>] [--raw] [--json]
ventris decompile-native <image> <address> (--arch <arch>|--target <target>) [options]
ventris decompile-native --project <project> --function <name-or-address> (--arch <arch>|--target <target>) [options]
ventris recover-types <image> <address> --target <target> [options]
ventris reconstruct-source <image> <address> --target <target> [options]
ventris batch --input <file|-> [--output <file|->] [--cache <dir>]
ventris serve [--bind <host:port>] [--once]
```

`project runtime` reads one JSON object per nonblank trace line. Each event has
`sequence`, `instruction`, and `kind`; memory events add `access`, `address`,
`width`, and optional `value`, calls add `target`, register events add
`register` and `value`, and markers add `text`. Addresses and values accept
decimal or hexadecimal strings. Ingested calls and memory accesses become
project cross-references; register values, markers, and memory widths/values
remain machine assertions with their sequence and instruction provenance.

`project assets` reads a manifest object with `assets`, `scripts`, and optional
`links` arrays. Assets use `id`, `name`, `kind`, `source`, and optional
`address`/`size`; scripts use `id`, `name`, `source`, and optional `entry` and
`language`. Explicit links name `code_address` plus `asset` or `script`;
project read/write references and calls also create automatic links when they
fall inside an asset range or target a script entry.

Supported native lifter names are `x86_64`, `x86_32`, `aarch64`, `arm32`,
`thumb`, `mips32`, `mips32be`, `ps1`, `n64`, `rv64`, `rv32`, `ppc32`,
`ppc64`, `gamecube`, `m68k`, `sh2`, `sh4`, `m6502`, `z80`, and `spu`. The
architecture is explicit; the image parser never guesses one from file-machine
facts. `--target` selects a console profile that supplies architecture, loader,
ABI, and any named image parts; `--arch` overrides only the architecture.
`--limit` bounds discovered instructions and must be greater than zero.

Supported image loaders are `auto`, `raw`, `elf`, `pe`, `macho`, `coff`,
`ihex`, `srec`, `dol`, `nds`, `ncch`, `psp-prx`, `vita-self`, `wiiu-rpl`, `xex`,
and `ps3-self`. `auto` recognizes the container from file bytes; use an explicit
loader for raw processor images or ambiguous input. `--base` sets the virtual
base for the raw loader. `--slice <n>` selects a zero-based slice from a
universal/fat Mach-O; auto detection refuses universal files without this
assertion. Native `--raw` keeps its existing convenience form, using the
command address as the raw image base.

Addresses accept qualified forms such as `ram::0x1000` and `image::0x1000`.
A bare offset is accepted only when exactly one addressable image space maps it.
Register, constant, and `unique` spaces are never candidates for bare offsets.

Successful commands write their result to stdout and return exit code `0`.
Invalid arguments, unsupported input, and analysis errors are written to stderr
and return exit code `2`. `--json` wraps single-command output in a stable
`ok`/`command`/`result` envelope. `batch` always emits one JSON object per
nonblank input line; each object carries `ok`, `index`, cache hit/miss totals,
and either `command`/`result` or `error`.

### Native analysis cache

`decompile-native --cache <dir>` enables a persistent bounded memo. Ventris writes
one versioned snapshot per input image under the supplied directory. The key
includes image content, analyzer code version, architecture/raw mode/address/
limit configuration, human-log digest, generation, and query identity. Corrupt
or truncated snapshots are rejected; the current byte budget is applied on load.

### Game recovery

`recover-types` requires `--target`; architecture alone is insufficient to
select a console ABI. It reports the selected ABI profile, register argument
and return classes, stack/frame rules, delay slots, caller/callee-save facts,
small-aggregate return rules, and p-code memory accesses.

Repeated base-plus-offset accesses become conservative struct candidates.
`PTRADD` accesses preserve observed array strides. Without metadata, fields are
reported as `unknown_bytes[N]`, not guessed integers or pointers. User
assertions and nominal type facts can replace that unknown with a named field
type, and every replacement retains confidence and provenance.

```text
ventris recover-types game.elf 0x80010000 --target ps2 --json
```

The current slice consumes lifted p-code and accepts symbols, relocations,
annotations, nominal types, and user assertions through the `ventris-game`
library. `reconstruct-source` combines those facts with native C output;
unsupported engine/runtime behavior remains explicit rather than silently
inferred.

### Cross-console game corpus

`ventris corpus` exposes source-backed function metadata without bundling game
images or copied game source. `--json` returns the same metadata inside the
normal CLI result envelope. Every entry carries a small set of functions so
the smoke runner exercises more than one code shape per target:

| Target | Public project | License field | Corpus functions |
|---|---|---|---|
| N64 | `n64decomp/perfect_dark` | MIT | `preamble` (`0x80001000`), `vm_boot` (`0x80001050`), `vm_init_vars` (`0x800010a0`) |
| GameCube | `ACreTeam/ac-decomp` | CC0-1.0 | `memset` (`0x800033a8`), `TRK_memset` (`0x800034e0`) |
| PS2 | `crowded-street/3s-decomp` | AGPL-3.0 | `flBeginRender` (`0x11c1d0`), `flEndRender` (`0x11c1f0`), `flPS2InitRenderState` (`0x11c210`) |
| PS2 | `glampert/ps2-homebrew` Dungeon Game | MIT | ten bounded `GameWorld` functions: eight semantic baselines plus menu and texture-lookup smoke |
| GBA | `pret/pokeemerald` | unspecified | `StartTimer1` (`0x08000554`), `SeedRngAndSetTrainerId` (`0x08000560`), `GetGeneratedTrainerIdLower` (`0x08000588`), `InitKeys` (`0x080005bc`) |

The manifest pins each source commit, symbol path, address, function size,
binary filename, and (for licensed reference images) SHA-256 digest, plus the
source repository's stated license when one exists. `unspecified` is kept as a
factual value for public repositories without an explicit license; Ventris
does not silently convert it to a different license. Obtain each image
independently, verify its revision, and run the normal target-specific command:

```text
ventris corpus --json
ventris inspect <image> --target <target>
ventris recover-types <image> <address> --target <target> --json
```

For the source-backed console entries, `ventris-corpus-smoke` is an opt-in
real-image gate. It reads the manifest from the Rust CLI, requires
manifest-named images, verifies each pinned SHA-256 or SHA-1 identity, resolves
and decompiles every listed function, and reports per-function results:

```text
ventris-corpus-smoke --image-dir <directory> --require-hashes
```

The default entries are `n64-perfect-dark-ntsc-final`,
`gamecube-animal-crossing-gafe01`, and `ps2-dungeon-game`. Use repeated `--id`
flags to select a subset. The PS2 image is the MIT-licensed
`source/demos/bin/dungeon_game.elf` checked into the pinned
[`glampert/ps2-homebrew`](https://github.com/glampert/ps2-homebrew) revision;
download it without modification as `dungeon_game.elf`.
Commercial references remain selectable, including
`ps2-street-fighter-iii-anniversary`, but their real-image semantic validation
is pending the exact pinned executable; no unexecuted expectations are emitted
for them. The hash gate rejects a different regional or rebuilt executable, and
the runner never bundles or extracts commercial images. Only
`ps2-dungeon-game` currently has source-backed expectations exercised against
its exact legal ELF. Reports distinguish exact, diverged, unsupported, and
unavailable dimensions instead of manufacturing a pass.

`ventris-compiler-check` is the separate compiler-backed PS2 gate. It
reconstructs the source-controlled semantic functions, compiles them for
`mipsel-none-elf` with Clang, disassembles both candidate objects and the pinned
retail windows, then reports exactness, normalized mnemonic LCS ratios,
instruction counts, call counts, and compiler diagnostics:

```text
ventris-compiler-check --image-dir <directory> --ventris <path> \
  --id ps2-dungeon-game
```

The default threshold is a regression gate, not a byte-matching claim.
`--require-exact` is available for functions expected to have identical
normalized mnemonic streams.

The `gba` target selects Thumb-1 and uses the raw ROM base `0x08000000`.

## Python API

```python
from ventris import (
    corpus,
    diff,
    ingest_runtime,
    link_assets,
    decompile_native,
    decompile_project_function,
    discover,
    inspect,
    project_references,
    recover_types,
    reconstruct_source,
    resolve,
)

print(corpus(as_json=True))
print(diff("before.bin", "after.bin", loader="raw", base=0x4000, as_json=True))
print(ingest_runtime("sample.vproj", "run.jsonl", as_json=True))
print(link_assets("sample.vproj", "assets.json", as_json=True))
print(inspect("sample.exe"))
print(discover("sample.exe", arch="x86_64", limit=4096))
print(lift("sample.exe", 0x140001000, arch="x86_64", limit=4096))
print(recover_types(
    "game.elf",
    0x80010000,
    target="ps2",
    metadata="game-types.json",
))
print(reconstruct_source(
    "game.elf",
    0x80010000,
    target="ps2",
    metadata="game-types.json",
    cache=".ventris-cache",
))
print(decompile_native(
    "sample.exe",
    0x140001000,
    arch="x86_64",
    cache=".ventris-cache",
))
print(decompile_project_function(
    "sample.vproj",
    "sub_140001000",
    arch="x86_64",
))
print(project_references("sample.vproj", 0x140001000))
```
The functions return the same text as the corresponding CLI command. `corpus`
returns the source-backed metadata manifest. A failed Rust command raises
`ventris.VentrisError`, carrying `returncode` and `stderr`. All path-like
arguments accept `str` and `os.PathLike[str]`; integer addresses are rendered
as hexadecimal.
`inspect`, `discover`, `diff`, `resolve`, `lift`, and `decompile_native`
accept `loader=`, `base=`, `slice=`, and `target=` keyword arguments.
`discover` requires `arch=` or `target=`. The
`decompile_project_function` helper selects a persisted discovered function by
name or address; `project_references` lists persisted incoming and outgoing
cross-references.
`ingest_runtime` forwards a JSONL emulator trace to `project runtime`.
`link_assets` forwards an asset/script manifest to `project assets`.
`reconstruct_source` combines native C with evidence-backed game structs.
Start the local server with:

```text
ventris serve --bind 127.0.0.1:8787
```

Endpoints return plain text unless noted:

| GET | `/inspect` | `file`; optional `target`, `loader`, `base`, `slice` | image facts |
| GET | `/diff` | `before`, `after`; optional `target`, `loader`, `base`, `slice`, `region` | changed image regions and byte hunks |
| GET | `/discover` | `file`; required `arch` or `target`; optional `limit`, `loader`, `base`, `slice` | discovered functions, calls, and failures |
| GET | `/resolve` | `file`, `address`; optional `target`, `loader`, `base`, `slice` | resolved address space |
| GET | `/recover-types` | `file`, `address`, `target`; optional `metadata`, `limit`, `loader`, `base`, `slice`, `raw` | game ABI and field recovery |
| GET | `/reconstruct-source` | `file`, `address`, `target`; optional `metadata`, `limit`, `loader`, `base`, `slice`, `raw`, `cache` | native C with recovered game structs |
| GET | `/lift` | `file`, `address`; optional `target`, `arch`, `limit`, `loader`, `base`, `slice` | lifted function |
| GET | `/decompile-native` | `file`, `address`; optional `target`, `arch`, `limit`, `loader`, `base`, `slice` | native C |
| POST | `/batch` | JSON Lines request body; `reconstruct-source` accepts `image`, `address`, `target`, `metadata`, `limit`, `loader`, `base`, `slice`, `raw` | JSON Lines batch results |

The server accepts GET for analysis endpoints and POST for `/batch`.
Malformed requests and endpoint errors use a 400 response; unsupported methods
use 405; unknown paths use 404; successful responses use 200.

The server is unauthenticated and has no TLS. It is intended for loopback
use only. A request can name a file readable by the server process, so do not
bind it to a non-loopback interface without an authenticated, access-controlled
TLS proxy.

## Development gates

```text
python -S tools/release_check.py --version 0.1.0
cargo test --workspace
cargo build --workspace --locked
cargo build --release --locked -p ventris-cli
cargo test -p ventris-decompiler public_native_corpus_matches_ghidra_oracles
PYTHONPATH=python python -S -m unittest discover -s python/tests
python -S tools/native_smoke.py --binary target/release/ventris.exe --fixture integrations/vscode/acceptance/fixture.exe --semantic-spec integrations/vscode/acceptance/semantic.json --version 0.1.0
python -S tools/clean_host_smoke.py --binary target/release/ventris.exe --fixture integrations/vscode/acceptance/fixture.exe --semantic-spec integrations/vscode/acceptance/semantic.json --version 0.1.0
python -S tools/http_smoke.py --binary target/release/ventris.exe
```

The native corpus gate compares the dependency-free SSA/decompiler renderer
with checked-in C captured from headless Ghidra. It covers zero-return,
arithmetic, direct-call, global-store, global-load, and two-arm conditional
functions across ten semantic bodies (nine x86-64 and one AArch64); the gate
requires an exact semantic body score after canonicalizing generated symbol
and local-variable names. The broader 24-body native corpus also exercises
MIPS32, PS1, N64, GameCube, x86-32, ARM Thumb, MIPS32 big-endian, RV32, M68k,
SH2, SH4, 6502, and Z80 paths. The separate 20-path instruction corpus adds
PPC32/PPC64 and SPU parity, including explicit unsupported-opcode checks.
A separate real-PE byte fixture pins 12
previously unsupported x86-64 instruction forms, including byte `TEST`,
REX-prefixed byte operations, SSE memory transfers, and indirect calls. The
real MinGW branch oracle also covers stack-frame setup, immediate `AND`,
conditional control flow, and both arms.

The current workspace includes ELF/PE/COFF/Mach-O parsing (thin and
universal/fat files with explicit slices), Nintendo DS/3DS, PSP, Vita, Wii U,
Xbox 360, and PS3 container parsing, explicit address resolution, progressive
native lifting for the twenty architecture paths, checked development-oracle
comparisons, a native SSA/decompiler pipeline, console-game ABI profiles,
evidence-backed p-code struct/field recovery, Python forwarding, HTTP serving,
bounded memoization, and installable VS Code clients. The optional GPUI desktop
workspace is built as a separate client with no privileged analysis access,
using `gpui-component` controls on the GPUI rendering foundation.
The automated VS Code extension-host smoke covers the packaged command path;
the GPUI project fixture has also been rendered in a manual desktop smoke, and
the release gate repeats the native CLI checks against the checked-in fixture.
