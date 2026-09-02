#!/usr/bin/env python3
"""Emit an SPDX 2.3 SBOM from the Cargo dependency graph."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _spdx_id(package_id: str) -> str:
    digest = hashlib.sha1(package_id.encode("utf-8")).hexdigest()[:16]
    return f"SPDXRef-Package-{digest}"


def build_document(manifest: Path) -> dict[str, Any]:
    completed = subprocess.run(
        [
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--manifest-path",
            str(manifest),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    metadata = json.loads(completed.stdout)
    packages = sorted(metadata["packages"], key=lambda package: package["id"])
    package_ids = {package["id"]: _spdx_id(package["id"]) for package in packages}
    digest = hashlib.sha256(
        "\n".join(package_ids).encode("utf-8")
    ).hexdigest()
    created = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )

    sbom_packages: list[dict[str, Any]] = []
    for package in packages:
        license_value = package.get("license") or "NOASSERTION"
        download = package.get("source") or package.get("repository") or "NOASSERTION"
        sbom_packages.append(
            {
                "SPDXID": package_ids[package["id"]],
                "name": package["name"],
                "versionInfo": package["version"],
                "downloadLocation": download,
                "filesAnalyzed": False,
                "licenseConcluded": license_value,
                "licenseDeclared": license_value,
                "copyrightText": "NOASSERTION",
                "supplier": "NOASSERTION",
            }
        )

    relationships: list[dict[str, str]] = []
    resolve = metadata.get("resolve") or {}
    for node in resolve.get("nodes", []):
        source_id = package_ids.get(node["id"])
        if source_id is None:
            continue
        for dependency in node.get("deps", []):
            target_id = package_ids.get(dependency.get("pkg"))
            if target_id is not None:
                relationships.append(
                    {
                        "spdxElementId": source_id,
                        "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": target_id,
                    }
                )

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "ventris-cargo-dependencies",
        "documentNamespace": f"https://ventris.dev/spdx/{digest}",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: ventris-sbom/1"],
        },
        "packages": sbom_packages,
        "relationships": relationships,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest-path",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "Cargo.toml",
    )
    parser.add_argument("--output", type=Path, default=Path("ventris.spdx.json"))
    args = parser.parse_args()
    document = build_document(args.manifest_path.resolve())
    rendered = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if str(args.output) == "-":
        sys.stdout.write(rendered)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(f"wrote {args.output} ({len(document['packages'])} packages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
