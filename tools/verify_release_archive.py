"""Verify a native Ventris release archive before upload."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import stat
import tarfile
import zipfile


REQUIRED = {
    "LICENSE",
    "NOTICE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "THIRD_PARTY_NOTICES.md",
    "README.md",
    "CHANGELOG.md",
}


def _safe_names(names: list[str], stem: str) -> set[str]:
    if len(names) != len(set(names)):
        raise ValueError("release archive contains duplicate names")
    for name in names:
        path = PurePosixPath(name)
        if (
            not name.startswith(stem)
            or path.is_absolute()
            or "\\" in name
            or ".." in path.parts
        ):
            raise ValueError("release archive contains an unsafe or unrooted path")
    return {name.removeprefix(stem) for name in names}


def verify(archive: Path, version: str, target: str) -> None:
    stem = f"ventris-{version}-{target}/"
    sizes: dict[str, int] = {}
    if archive.suffix.lower() == ".zip":
        with zipfile.ZipFile(archive) as handle:
            infos = handle.infolist()
            if handle.testzip() is not None:
                raise ValueError(f"corrupt ZIP: {archive}")
            names = [info.filename for info in infos]
            for info in infos:
                mode = (info.external_attr >> 16) & 0o170000
                if info.is_dir() or stat.S_ISLNK(mode) or mode not in (0, stat.S_IFREG):
                    raise ValueError("release archive must contain regular files only")
                sizes[info.filename] = info.file_size
    elif archive.name.endswith(".tar.gz"):
        with tarfile.open(archive, "r:gz") as handle:
            members = handle.getmembers()
            names = [member.name for member in members]
            for member in members:
                if not member.isfile() or member.issym() or member.islnk():
                    raise ValueError("release archive must contain regular files only")
                sizes[member.name] = member.size
    else:
        raise ValueError("archive must be .zip or .tar.gz")

    relative = _safe_names(names, stem)
    expected_binary = "ventris.exe" if "windows" in target.lower() else "ventris"
    expected = REQUIRED | {expected_binary}
    missing = expected - relative
    unexpected = relative - expected
    binary_name = f"{stem}{expected_binary}"
    if missing:
        raise ValueError(f"release archive is missing: {', '.join(sorted(missing))}")
    if unexpected:
        raise ValueError(
            "release archive contains unexpected files: "
            f"{', '.join(sorted(unexpected))}"
        )
    if sizes.get(binary_name, 0) <= 0:
        raise ValueError("release archive contains an empty native executable")
    print(f"release-archive: PASS {archive}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    args = parser.parse_args(argv)
    verify(args.archive.resolve(), args.version, args.target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
