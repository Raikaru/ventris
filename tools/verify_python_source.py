"""Verify the publishable contents of a Ventris Python source archive."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import tarfile


REQUIRED = {
    "LICENSE",
    "NOTICE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "THIRD_PARTY_NOTICES.md",
    "README.md",
    "CHANGELOG.md",
    "pyproject.toml",
    "python/ventris/__init__.py",
    "python/ventris/cli.py",
}


def _safe_names(names: list[str], stem: str) -> set[str]:
    if len(names) != len(set(names)):
        raise ValueError("source archive contains duplicate names")
    root = stem.removesuffix("/")
    relative: set[str] = set()
    for name in names:
        path = PurePosixPath(name)
        if name == root:
            continue
        if (
            not name.startswith(stem)
            or path.is_absolute()
            or "\\" in name
            or ".." in path.parts
        ):
            raise ValueError("source archive contains an unsafe or unrooted path")
        relative.add(name.removeprefix(stem))
    return relative


def verify(source: Path, version: str) -> None:
    if not source.is_file():
        raise ValueError(f"source archive not found: {source}")
    stem = f"ventris_client-{version}/"
    with tarfile.open(source, "r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        for member in members:
            if member.isdir():
                continue
            if (
                not member.isfile()
                or member.issym()
                or member.islnk()
            ):
                raise ValueError("source archive must contain regular files only")
        relative = _safe_names(names, stem)
    missing = REQUIRED - relative
    if missing:
        raise ValueError(
            f"source archive is missing: {', '.join(sorted(missing))}"
        )
    if any(name.startswith("tests/") for name in relative):
        raise ValueError("source archive contains test sources at its root")
    print(f"python-source: PASS {source}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args(argv)
    verify(args.source.resolve(), args.version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
