#!/usr/bin/env python3
"""Export a large, unselected Ghidra oracle sample from each corpus image.

The quality census measures 37 functions that a human pinned. That answers "did
this change regress a function I already cared about" and cannot answer "how
often do we agree with Ghidra", because the sample was chosen partly *because*
those functions were interesting. This exporter removes the choice: it asks
Ghidra for its own function list per image and takes a bounded prefix.

One headless run per image, reusing a single import and a single decompiler, so
the cost is dominated by Ghidra's analysis rather than by per-function startup.
Output is one directory per corpus entry holding `<id>.ghidra-decompile` files
in the same format `CensusDecompile.java` emits, plus `sweep-manifest.tsv`
naming every function that exported cleanly.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Sequence

sys.path.insert(0, os.fspath(Path(__file__).resolve().parent))

import quality_census as census


def sweep_one(
    ghidra: Path,
    image: Path,
    target: str,
    entry_id: str,
    out_root: Path,
    project_root: Path,
    limit: int,
    min_bytes: int,
    max_bytes: int,
) -> dict:
    """Runs one headless Ghidra sweep over one image."""
    import_args = census.GHIDRA_IMPORT.get(target)
    if import_args is None:
        return {"id": entry_id, "status": "skip", "error": f"no Ghidra import recipe for {target}"}
    out_dir = out_root / entry_id
    out_dir.mkdir(parents=True, exist_ok=True)
    project_dir = project_root / entry_id
    project_dir.mkdir(parents=True, exist_ok=True)
    command = [
        os.fspath(ghidra / "support" / "analyzeHeadless.bat"),
        os.fspath(project_dir),
        f"sweep-{entry_id}",
        "-import",
        os.fspath(image),
        *import_args,
        "-scriptPath",
        os.fspath(Path(__file__).resolve().parent),
        "-postScript",
        "CensusSweep.java",
        os.fspath(out_dir),
        str(limit),
        str(min_bytes),
        str(max_bytes),
        "-deleteProject",
    ]
    if os.name == "nt":
        command = ["cmd.exe", "/d", "/c", *command]
    else:
        command[0] = os.fspath(ghidra / "support" / "analyzeHeadless")
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if "VENTRIS sweep done" not in completed.stdout:
        tail = (completed.stdout[-1500:] + completed.stderr[-1500:]).strip()
        return {"id": entry_id, "status": "fail", "error": tail}
    # Ghidra prefixes every script `println` with a log level and the script
    # name, so these markers are never at the start of a line.
    exported = 0
    failed = 0
    for line in completed.stdout.splitlines():
        if "VENTRIS sweep exported=" in line:
            exported = int(line.split("exported=")[1].split()[0])
            failed = int(line.split("failed=")[1].split()[0])
    return {
        "id": entry_id,
        "status": "ok",
        "exported": exported,
        "oracle_failed": failed,
        "dir": os.fspath(out_dir),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-dir", required=True, type=Path)
    parser.add_argument("--ventris", required=True)
    parser.add_argument("--ghidra", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=400, help="functions per image")
    parser.add_argument("--min-bytes", type=int, default=32)
    parser.add_argument("--max-bytes", type=int, default=4096)
    parser.add_argument("--jobs", type=int, default=3, help="images swept in parallel")
    parser.add_argument("--id", action="append", dest="ids")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = census.read_manifest(args.ventris)
    entries = census.selected_entries(manifest, args.image_dir)
    if args.ids:
        entries = [e for e in entries if e["id"] in set(args.ids)]
    if not entries:
        print("no corpus entries with a verified local image", file=sys.stderr)
        return 2
    args.out.mkdir(parents=True, exist_ok=True)
    project_root = args.out / "_projects"

    def run(entry: dict) -> dict:
        return sweep_one(
            args.ghidra,
            args.image_dir / entry["binary_name"],
            entry["target"],
            entry["id"],
            args.out,
            project_root,
            args.limit,
            args.min_bytes,
            args.max_bytes,
        )

    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        results = list(pool.map(run, entries))

    for result in results:
        detail = result.get("error", "")
        line = f"{result['status']:5s} {result['id']:44s} {result.get('exported', 0):5d}"
        print(line + (f"  {detail[:120]}" if detail else ""))
    (args.out / "sweep-report.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8", newline="\n"
    )
    total = sum(r.get("exported", 0) for r in results)
    print(f"\ntotal oracle functions exported: {total}")
    return 0 if any(r["status"] == "ok" for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
