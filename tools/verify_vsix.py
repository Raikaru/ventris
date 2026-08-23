"""Verify the publishable contents of a Ventris VSIX."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import stat
import zipfile


def verify(vsix: Path, version: str) -> None:
    with zipfile.ZipFile(vsix) as archive:
        infos = archive.infolist()
        if archive.testzip() is not None:
            raise ValueError(f"corrupt VSIX: {vsix}")
        names_list = [info.filename for info in infos]
        if len(names_list) != len(set(names_list)):
            raise ValueError("VSIX contains duplicate names")
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
                raise ValueError("VSIX contains an unsafe or non-file entry")
        names = set(names_list)
        required = {
            "extension/package.json",
            "extension/extension.js",
            "extension/README.md",
            "extension/LICENSE",
            "extension/NOTICE",
            "extension/SECURITY.md",
            "extension/THIRD_PARTY_NOTICES.md",
            "extension.vsixmanifest",
        }
        missing = required - names
        if missing:
            raise ValueError(f"VSIX is missing: {', '.join(sorted(missing))}")
        package = json.loads(archive.read("extension/package.json"))
        manifest = archive.read("extension.vsixmanifest").decode("utf-8")
        if package.get("version") != version:
            raise ValueError("VSIX package version does not match release")
        if f'Version="{version}"' not in manifest:
            raise ValueError("VSIX manifest version does not match release")
        if any("node_modules/" in name or ".acceptance-" in name for name in names):
            raise ValueError("VSIX contains development or acceptance state")
    print(f"vsix: PASS {vsix}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vsix", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args(argv)
    verify(args.vsix.resolve(), args.version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
