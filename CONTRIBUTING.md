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
