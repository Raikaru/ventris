"""Validate the files and metadata required for a Ventris release.

This checker intentionally uses only the Python standard library so it can run
before any build environment or package dependency is installed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


REQUIRED_FILES = (
    "README.md",
    "ARCHITECTURE.md",
    "CHANGELOG.md",
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_NOTICES.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "RELEASING.md",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "desktop/ventris-gpui/Cargo.toml",
    "desktop/ventris-gpui/Cargo.lock",
    "tools/native_smoke.py",
    "tools/compiler_check.py",
    "tools/clean_host_smoke.py",
    "tools/http_smoke.py",
    "tools/verify_release_archive.py",
    "tools/verify_python_artifact.py",
    "tools/verify_python_source.py",
    "tools/verify_vsix.py",
    "pyproject.toml",
    "MANIFEST.in",
    "integrations/vscode/package.json",
    "integrations/vscode/package-lock.json",
    "integrations/vscode/acceptance/semantic.json",
)

def fail(message: str) -> None:
    raise ValueError(message)


def read(root: Path, relative: str) -> str:
    path = root / relative
    if not path.is_file():
        fail(f"missing required file: {relative}")
    return path.read_text(encoding="utf-8")


def require_version(text: str, label: str, version: str) -> None:
    if version not in text:
        fail(f"{label} does not contain release version {version}")


def check_no_local_paths(root: Path) -> None:
    excluded = {
        "target",
        "build",
        "dist",
        ".release",
        ".git",
        "node_modules",
        "__pycache__",
        ".acceptance-user",
        ".acceptance-extensions",
        ".vscode-test",
    }
    suffixes = {".rs", ".py", ".js", ".json", ".toml", ".gradle", ".cmd", ".bat", ".md"}
    for path in root.rglob("*"):
        if path.name == "release_check.py":
            continue
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        if any(part in excluded for part in path.parts):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if re.search(r"(?:[A-Za-z]:[\\/]|/Users/)[^\n]*(?:thele|tmp|workspace)", text, re.IGNORECASE):
            fail(f"machine-specific path found in {path.relative_to(root)}")


def check(root: Path, version: str) -> None:
    for relative in REQUIRED_FILES:
        read(root, relative)
    version_file = read(root, "VERSION").strip()
    if version_file != version:
        fail(f"VERSION contains {version_file!r}, expected {version!r}")
    workspace_manifest = read(root, "Cargo.toml")
    if not re.search(r'^\s*edition\s*=\s*"2024"\s*$', workspace_manifest, re.MULTILINE):
        fail("Rust workspace edition is not 2024")
    if not re.search(r'^\s*rust-version\s*=\s*"1\.98"\s*$', workspace_manifest, re.MULTILINE):
        fail("Rust workspace MSRV is not 1.98")
    toolchain = read(root, "rust-toolchain.toml")
    if not re.search(r'^\s*channel\s*=\s*"1\.98\.0"\s*$', toolchain, re.MULTILINE):
        fail("Rust toolchain is not pinned to 1.98.0")
    cli_manifest = read(root, "crates/ventris-cli/Cargo.toml")
    if not re.search(r'^\s*name\s*=\s*"ventris-cli"\s*$', cli_manifest, re.MULTILINE):
        fail("Rust CLI crate name must be ventris-cli")
    gpui_manifest = read(root, "desktop/ventris-gpui/Cargo.toml")
    if not re.search(rf'^\s*version\s*=\s*"{re.escape(version)}"\s*$', gpui_manifest, re.MULTILINE):
        fail("GPUI desktop package version is not synchronized")
    if not re.search(r'^\s*edition\s*=\s*"2024"\s*$', gpui_manifest, re.MULTILINE):
        fail("GPUI desktop edition is not 2024")
    if not re.search(r'^\s*rust-version\s*=\s*"1\.98"\s*$', gpui_manifest, re.MULTILINE):
        fail("GPUI desktop MSRV is not 1.98")
    pyproject = read(root, "pyproject.toml")
    if not re.search(r'^\s*name\s*=\s*"ventris-client"\s*$', pyproject, re.MULTILINE):
        fail("Python distribution name must be ventris-client")
    if not re.search(rf"^\s*version\s*=\s*\"{re.escape(version)}\"\s*$", pyproject, re.MULTILINE):
        fail("pyproject version is not synchronized")
    if 'readme = "README.md"' not in pyproject:
        fail("Python package does not declare its README")
    if not re.search(r'^\s*license\s*=\s*"Apache-2\.0"\s*$', pyproject, re.MULTILINE):
        fail("Python package license is not Apache-2.0")
    if not re.search(r'^\s*license-files\s*=\s*\[[^\]]*"LICENSE"', pyproject, re.MULTILINE):
        fail("Python package does not include its license file")

    python_init = read(root, "python/ventris/__init__.py")
    require_version(python_init, "Python package", f'__version__ = "{version}"')

    vscode = json.loads(read(root, "integrations/vscode/package.json"))
    if vscode.get("version") != version:
        fail("VS Code package version is not synchronized")
    if vscode.get("license") != "Apache-2.0":
        fail("VS Code package license is not Apache-2.0")
    if vscode.get("preview") is not True:
        fail("0.x VS Code package must be marked preview")

    lock = json.loads(read(root, "integrations/vscode/package-lock.json"))
    if lock.get("version") != version or lock.get("packages", {}).get("", {}).get("version") != version:
        fail("VS Code lockfile version is not synchronized")

    release_workflow = read(root, ".github/workflows/release.yml")
    if "sha256sum --binary * > SHA256SUMS" not in release_workflow:
        fail("release checksums must use portable binary-mode markers")
    for manifest in sorted((root / "crates").glob("*/Cargo.toml")):
        text = manifest.read_text(encoding="utf-8")
        if "license.workspace = true" not in text and 'license = "Apache-2.0"' not in text:
            fail(f"crate does not declare an Apache license: {manifest}")
        for dependency in re.finditer(r"^ventris-[\w-]+\s*=\s*\{([^}]*)\}$", text, re.MULTILINE):
            if not re.search(rf"\bversion\s*=\s*\"{re.escape(version)}\"", dependency.group(1)):
                fail(f"path dependency lacks registry version in {manifest}")

    check_no_local_paths(root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--version", required=True)
    args = parser.parse_args(argv)
    try:
        check(args.root.resolve(), args.version)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"release-check: FAIL: {error}", file=sys.stderr)
        return 1
    print(f"release-check: PASS ({args.version})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
