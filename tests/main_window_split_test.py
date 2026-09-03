#!/usr/bin/env python3
"""Acceptance test for m0-006: main_window.cpp split (<= 400 lines, *_dock.cpp files)."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "desktop" / "ventris-qt" / "src"
MAIN_WINDOW = SRC / "main_window.cpp"

EXPECTED_DOCKS = (
    "functions_dock.cpp",
    "decompiler_dock.cpp",
    "facts_dock.cpp",
    "memory_dock.cpp",
    "graph_dock.cpp",
    "analyst_dock.cpp",
    "types_dock.cpp",
    "xrefs_dock.cpp",
    "jobs_dock.cpp",
    "vtables_dock.cpp",
)


def main() -> int:
    if not MAIN_WINDOW.is_file():
        sys.exit(f"FAIL: {MAIN_WINDOW} does not exist")

    lines = len(MAIN_WINDOW.read_text(encoding="utf-8").splitlines())
    if lines > 400:
        sys.exit(f"FAIL: main_window.cpp has {lines} lines; must be <= 400 lines")

    missing_docks = [dock for dock in EXPECTED_DOCKS if not (SRC / dock).is_file()]
    if missing_docks:
        sys.exit(f"FAIL: missing dock implementations: {', '.join(missing_docks)}")

    print(f"m0-006 acceptance: pass (main_window.cpp has {lines} lines <= 400; all {len(EXPECTED_DOCKS)} docks present)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
