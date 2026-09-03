#!/usr/bin/env python3
"""Acceptance test for non-null UI gate metrics on libc."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / "benchmarks" / "ui_gate.py"
METRICS = (
    "ui.list.load_ms",
    "ui.list.filter_ms",
    "ui.sync_ms",
    "ui.graph.layout_ms",
    "ui.graph.paint_ms",
    "ui.install.ok",
)


def libc_path() -> Path:
    configured = os.environ.get("VENTRIS_UI_BINARY")
    for candidate in (
        Path(configured) if configured else None,
        Path("/usr/lib64/libc.so.6"),
        Path("/usr/lib/x86_64-linux-gnu/libc.so.6"),
        Path("/lib/x86_64-linux-gnu/libc.so.6"),
    ):
        if candidate is not None and candidate.is_file():
            return candidate
    raise SystemExit("libc is not available; pass --binary")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--binary", type=Path, default=libc_path())
    args = parser.parse_args()
    app = args.app.resolve()
    binary = args.binary.resolve()
    if not app.is_file():
        raise SystemExit(f"Qt app does not exist: {app}")
    if not binary.is_file():
        raise SystemExit(f"libc binary does not exist: {binary}")

    with TemporaryDirectory(prefix="ventris-ui-metrics-") as directory:
        report = Path(directory) / "ui-gate.json"
        result = subprocess.run(
            [
                sys.executable,
                str(GATE),
                "--app",
                str(app),
                "--binary",
                str(binary),
                "--program",
                "libc",
                "--runs",
                "1",
                "--output",
                str(report),
            ],
            cwd=ROOT,
            env={**os.environ, "QT_QPA_PLATFORM": "offscreen"},
            check=False,
        )
        assert result.returncode in (0, 1), result.returncode
        document = json.loads(report.read_text(encoding="utf-8"))
        metrics = document["corpus"][0]["metrics"]
        assert all(metric in metrics and metrics[metric] is not None for metric in METRICS)
        assert all(isinstance(metrics[metric], (int, float)) for metric in METRICS[:-1])
        assert isinstance(metrics["ui.install.ok"], bool)
    print("libc UI metrics acceptance: pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
