# Contributing to Ventris

## Before changing code

Read `README.md`, `ARCHITECTURE.md`, and the relevant crate or integration
README. Keep the dependency-free design intentional: add a dependency only
when the capability cannot be implemented safely and clearly with the
standard library.

Changes that alter binary parsing, address resolution, lifting, p-code, native
rendering, ABI recovery, or wire output must add or update a focused fixture or
regression test. Do not replace a failing semantic test with a looser string or
size assertion.

## Development checks

Run the applicable checks before submitting a change:

```text
cargo fmt --all -- --check
cargo test --workspace
cargo build --workspace --locked
PYTHONPATH=python python -S -m unittest discover -s python/tests
cd integrations/vscode
npm ci
npm run package
```

The real-image corpus smoke gate is opt-in because the images are not
redistributed by this repository. Follow the acquisition and hash instructions
in `README.md` and `RELEASING.md`.

## Setting up a second machine

The gate needs three things that are not in the repository: the pinned Rust
toolchain, a Ghidra installation carrying this project's loader extensions, and
the corpus images. Locations come from the environment, so nothing needs editing
per machine:

```text
export VENTRIS_IMAGE_DIR=$HOME/ventris-corpus         # corpus images
export VENTRIS_GHIDRA=$HOME/ghidra_12.1.3_PUBLIC      # Ghidra + Ghidra/Extensions
export VENTRIS_CENSUS_OUT=$HOME/ventris-census        # oracle cache and project
```

`tools/setup_workspace.sh` checks all of it and installs the pinned toolchain
through `rustup` if that is missing. It reports what is absent rather than
failing later inside a build. Then:

```text
cargo build --release
python3 tools/gate.py --fresh-oracle   # first run only: the oracle cache is cold
python3 tools/gate.py                  # subsequent runs reuse it
```

`tools/sync_workspace.py` copies Ghidra and the corpus to another host over SSH.
It is resumable and idempotent, which matters on a link that drops - it sends
only files whose size differs and works in bounded batches. Copying **from
Windows requires `--fix-exec-bits`**: NTFS has no executable bit, so both
`support/analyzeHeadless` and the native
`Ghidra/Features/Decompiler/os/*/decompile` arrive non-executable, and the
second failure appears only once a decompilation is attempted.

Two constraints worth knowing before debugging them again:

* Ghidra rejects any project path containing a dot-prefixed element, so the
  census directory cannot live under `~/.cache`.
* Headless `-loader` takes the loader's *class* name (`BinaryLoader`,
  `GBALoader`), not its display name ("Raw Binary", "GBA Loader").
  `tools/ListLoaders.java` prints every loader Ghidra actually discovered, which
  distinguishes a missing extension from a mistyped name.

## Licensing and provenance

Do not commit commercial game images, copied game source, generated artifacts,
credentials, or files with unclear redistribution rights. New third-party code
requires a license and provenance entry in `NOTICE` and
`THIRD_PARTY_NOTICES.md`. Preserve upstream attribution when adapting code.

## Pull requests

Describe the observable behavior changed, the fixtures used, the commands
run, and any platform or integration limitation. Keep unrelated formatting or
refactoring out of focused fixes. A maintainer must review release metadata,
license changes, and security-sensitive changes separately from ordinary code.
