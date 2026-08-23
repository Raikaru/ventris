"""Run Ventris's compiler-backed native comparison gate from a source checkout."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from ventris.compiler_gate import main


if __name__ == "__main__":
    raise SystemExit(main())
