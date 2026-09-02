#!/usr/bin/env python3
"""Create hash-addressed metadata for a Ventris release artifact set."""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--channel", default="stable")
    parser.add_argument("--product", default="ventris")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=Path("update.json"))
    parser.add_argument("artifacts", nargs="+", type=Path)
    args = parser.parse_args()

    root = args.root.resolve()
    rows = []
    for artifact in args.artifacts:
        path = artifact.resolve()
        if not path.is_file():
            parser.error(f"artifact is not a file: {artifact}")
        try:
            relative = path.relative_to(root)
        except ValueError:
            parser.error(f"artifact must be below --root: {artifact}")
        rows.append(
            {
                "path": relative.as_posix(),
                "size": path.stat().st_size,
                "sha256": sha256(path),
            }
        )

    document = {
        "schema": 1,
        "product": args.product,
        "version": args.version,
        "channel": args.channel,
        "generatedAt": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "artifacts": sorted(rows, key=lambda row: row["path"]),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {args.output} ({len(rows)} artifacts)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
