#!/usr/bin/env python3
"""Verify release artifact sizes and SHA-256 hashes from an update manifest."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--root", type=Path)
    args = parser.parse_args()

    manifest_path = args.manifest.resolve()
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    if document.get("schema") != 1 or not isinstance(document.get("artifacts"), list):
        parser.error("unsupported update manifest")
    root = (args.root or manifest_path.parent).resolve()
    failures = []
    for artifact in document["artifacts"]:
        relative = Path(artifact["path"])
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError:
            failures.append(f"{relative}: path escapes root")
            continue
        if not path.is_file():
            failures.append(f"{relative}: missing")
            continue
        if path.stat().st_size != artifact["size"]:
            failures.append(f"{relative}: size mismatch")
            continue
        if sha256(path) != artifact["sha256"]:
            failures.append(f"{relative}: SHA-256 mismatch")
    if failures:
        for failure in failures:
            print(failure)
        return 1
    print(f"verified {len(document['artifacts'])} artifacts for {document['product']} {document['version']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
