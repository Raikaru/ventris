"""Verify the publishable contents of a Ventris Python wheel."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import stat
import zipfile


def verify(wheel: Path, version: str, distribution: str = "ventris-client") -> None:
    with zipfile.ZipFile(wheel) as archive:
        infos = archive.infolist()
        if archive.testzip() is not None:
            raise ValueError(f"corrupt wheel: {wheel}")
        names_list = [info.filename for info in infos]
        if len(names_list) != len(set(names_list)):
            raise ValueError("wheel contains duplicate names")
        for info in infos:
            path = PurePosixPath(info.filename)
            mode = (info.external_attr >> 16) & 0o170000
            if (
                info.is_dir()
                or path.is_absolute()
                or "\\" in info.filename
                or ".." in path.parts
                or stat.S_ISLNK(mode)
                or mode not in (0, stat.S_IFREG)
            ):
                raise ValueError("wheel contains an unsafe or non-file entry")
        names = set(names_list)
        normalized = distribution.replace("-", "_").lower()
        metadata = f"{normalized}-{version}.dist-info/"
        required = {
            "ventris/__init__.py",
            "ventris/cli.py",
            f"{metadata}METADATA",
            f"{metadata}RECORD",
        }
        missing = required - names
        if missing:
            raise ValueError(f"wheel is missing: {', '.join(sorted(missing))}")
        if any(name.startswith("tests/") for name in names):
            raise ValueError("wheel contains test sources")
        if not any(
            name.startswith(f"{metadata}licenses/") and name.endswith("LICENSE")
            for name in names
        ):
            raise ValueError("wheel does not contain a license file")
    print(f"python-artifact: PASS {wheel}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--distribution", default="ventris-client")
    args = parser.parse_args(argv)
    verify(args.wheel.resolve(), args.version, args.distribution)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
