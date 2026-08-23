# Releasing Ventris

This document defines the minimum bar for a **0.x public preview**. It does
not claim that Ventris is a drop-in replacement for Ghidra or that game
matching-C emission is complete. A stable 1.0 release has additional gates at
the end of this document.

## Release surfaces

A release may contain these independent artifacts:

1. source archive and checksum manifest;
2. native `ventris` binaries for each platform actually built and tested;
3. the Python forwarding package;
4. the VS Code VSIX;
5. crates.io packages, only after all workspace path dependencies have version
   requirements and every package has complete registry metadata.

Do not advertise an artifact that was not built and smoke-tested from the
release tag.

## Non-negotiable gates

- [ ] The release is made from a clean tagged commit; generated files, local
      images, debug logs, credentials, and machine-specific paths are absent.
- [ ] `VERSION`, Cargo, Python, and VS Code metadata agree exactly.
- [ ] Rust crates use edition 2024 with MSRV 1.98, and CI/release jobs use the
      pinned 1.98.0 toolchain.
- [ ] `LICENSE`, `NOTICE`, `SECURITY.md`, `CONTRIBUTING.md`, and
      `THIRD_PARTY_NOTICES.md` are present in source and relevant binary
      packages.
- [ ] The repository's real canonical URL, maintainers, and private security
      contact are configured before publishing registry metadata.
- [ ] All included code and fixtures have a documented license and provenance.
      Game images and copied game source remain outside the distribution.
- [ ] The full Rust, Python, VS Code, and frozen GPUI checks pass on the release
      commit.
- [ ] Each native binary passes `version`, `inspect`, `lift`, and semantic
      `decompile` smoke checks against a checked-in fixture, using
      `tools/native_smoke.py`.
- [ ] The same binary passes `tools/clean_host_smoke.py` from an isolated
      temporary working directory on every release runner.
- [ ] Development-only corpus and compiler gates enforce every checked-in
      per-function floor.
- [ ] The Python package is tested in a clean virtual environment with an
      explicit released binary. Its external-binary prerequisite is visible in
      the package documentation.
- [ ] The VSIX installs in a clean VS Code profile and its three commands reach
      the same native executable version as the release.
- [ ] SHA-256 checksums are generated for every artifact. The current preview
      release policy is unsigned artifacts plus a published `SHA256SUMS` file;
      no cryptographic signature is claimed.

## Local preflight

From the repository root:

```text
python -S tools/release_check.py --version 0.2.0
cargo fmt --all -- --check
cargo fmt --manifest-path desktop/ventris-gpui/Cargo.toml -- --check
cargo test --workspace
cargo test --manifest-path desktop/ventris-gpui/Cargo.toml --locked
cargo build --workspace --locked
cargo build --release --locked -p ventris-cli
PYTHONPATH=python python -S -m unittest discover -s python/tests
python -S tools/native_smoke.py --binary target/release/ventris.exe --fixture integrations/vscode/acceptance/fixture.exe --semantic-spec integrations/vscode/acceptance/semantic.json --version 0.2.0
python -S tools/clean_host_smoke.py --binary target/release/ventris.exe --fixture integrations/vscode/acceptance/fixture.exe --semantic-spec integrations/vscode/acceptance/semantic.json --version 0.2.0
```

Build and inspect the Python distribution in a fresh environment. The chosen
release model is an external binary pairing: the wheel never downloads or
embeds native code; it must be installed beside the same-version native
archive, with `VENTRIS_BIN` or `PATH` selecting that executable.

```text
python -m pip install --disable-pip-version-check build
python -m build --wheel --sdist --outdir .release/python
python -S tools/verify_python_artifact.py --wheel .release/python/ventris_client-0.2.0-py3-none-any.whl --version 0.2.0
python -S tools/verify_python_source.py --source .release/python/ventris_client-0.2.0.tar.gz --version 0.2.0
python -m venv .release/venv
.release/venv/Scripts/python -m pip install --no-deps .release/python/ventris_client-0.2.0-py3-none-any.whl
set VENTRIS_BIN=%CD%\target\release\ventris.exe
.release/venv/Scripts/python -c "from ventris import version; print(version())"
```

Build and verify the VSIX:

```text
cd integrations/vscode
npm ci
npm run package
```

Install the resulting `dist/ventris-binary-analysis-<version>.vsix` in a clean
profile and run the host acceptance suite with explicit paths:

```text
set VSCODE_EXECUTABLE=<path to Code.exe>
set VENTRIS_ACCEPTANCE_BINARY=<path to released ventris executable>
set VENTRIS_ACCEPTANCE_FIXTURE=<path to acceptance fixture.exe>
npm run acceptance
```


## Hosted release candidate

Manual dispatches build and verify every release artifact without publishing by
default:

```text
gh workflow run release.yml -f version=0.2.0 -f publish=false
```

Inspect the completed run and download every artifact before tagging. Setting
`publish=true` is an explicit publication request; normal releases should
instead be rebuilt from a clean `v<version>` tag.

## Registry publication

### crates.io

The CLI package is named `ventris-cli`; its installed binary is `ventris`.
The preliminary registry audit found `ventris` and the `ventris-*` names
unclaimed; recheck every name immediately before publication.

Publish workspace crates in dependency order, or publish only the explicitly
supported public package set. Every path dependency must also carry a matching
registry version requirement. Use `cargo publish --dry-run --locked` for each
package and inspect the generated archive before uploading. Do not publish
internal packages accidentally; set `publish = false` for packages that are
not part of the supported public API. Complete repository, homepage, and
description metadata before attempting registry publication.

### PyPI

The distribution name is `ventris-client`; the preliminary PyPI audit found
both `ventris` and `ventris-client` unclaimed. The package is a client wrapper,
not a self-contained binary wheel. Publish it only with documentation that
tells users to install a matching native executable and set `VENTRIS_BIN` or
put `ventris` on `PATH`.
If a one-command Python install is required, produce and test platform-specific
wheels that bundle the executable under a separately chosen distribution name.

### VS Code Marketplace

The VSIX must contain no development dependencies, local paths, acceptance
profiles, or test fixtures that are not intentionally part of the extension.
Use a publisher identity owned by the release maintainer; `ventris` is only a
local manifest value until that identity is registered.


## Stable 1.0 bar

Do not call Ventris stable until all of these are true:

- native semantic comparison covers representative real binaries for every
  advertised architecture family, with unsupported instructions reported
  explicitly;
- game ABI/type recovery and source rendering meet the documented oracle bar
  on multiple public console-game corpora, including calls, globals, casts,
  aggregate copies, declaration order, and nominal field names;
- real-image smoke checks compare semantic results, not only process success,
  addresses, sizes, or warning counts;
- all advertised native platforms have reproducible CI builds and clean-host
  smoke coverage;
- the Python and VS Code adapters have host-side acceptance evidence and a
  deliberate native-binary installation story;
- a security review covers file access, binary parsing, cache handling, and
  subprocess boundaries;
- the project has a maintained issue/support channel and a published private
  security contact.
