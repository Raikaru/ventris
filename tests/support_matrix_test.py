#!/usr/bin/env python3
"""Acceptance test for m0-010: support matrix generator and staleness check."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "gen_support_matrix.py"


def main() -> int:
    if not SCRIPT.is_file():
        sys.exit(f"FAIL: {SCRIPT} does not exist")

    # Run generator check: fails if README matrix is stale or unparseable
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        sys.exit(f"FAIL: support matrix staleness check failed: {detail}")

    print("m0-010 acceptance: pass (support matrix generator exists and README matrix is in sync)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
