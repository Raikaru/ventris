"""Create a deterministic Ventris native release archive."""

from __future__ import annotations

import argparse
import gzip
import hashlib
from pathlib import Path
import tarfile
import zipfile


FILES = (
    "LICENSE",
    "NOTICE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "THIRD_PARTY_NOTICES.md",
    "README.md",
    "CHANGELOG.md",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def package(root: Path, version: str, target: str, binary: Path, output: Path) -> None:
    if not binary.is_file():
        raise ValueError(f"native binary not found: {binary}")
    for relative in FILES:
        if not (root / relative).is_file():
            raise ValueError(f"release file not found: {relative}")

    output.parent.mkdir(parents=True, exist_ok=True)
    stem = f"ventris-{version}-{target}"
    binary_name = "ventris.exe" if binary.suffix.lower() == ".exe" else "ventris"
    if output.suffix.lower() == ".zip":
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            entries = [(binary, f"{stem}/{binary_name}")]
            entries.extend((root / relative, f"{stem}/{relative}") for relative in FILES)
            for source, name in entries:
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o644 << 16
                archive.writestr(info, source.read_bytes())
    elif output.name.endswith(".tar.gz"):
        with output.open("wb") as stream:
            with gzip.GzipFile(fileobj=stream, mode="wb", mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as archive:
                    entries = [(binary, f"{stem}/{binary_name}")]
                    entries.extend((root / relative, f"{stem}/{relative}") for relative in FILES)
                    for source, name in entries:
                        info = tarfile.TarInfo(name)
                        info.size = source.stat().st_size
                        info.mode = 0o755 if source == binary else 0o644
                        info.mtime = 0
                        with source.open("rb") as source_stream:
                            archive.addfile(info, source_stream)
    else:
        raise ValueError("output must end in .zip or .tar.gz")

    print(f"{output} sha256={sha256(output)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    package(
        args.root.resolve(),
        args.version,
        args.target,
        args.binary.resolve(),
        args.output.resolve(),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
