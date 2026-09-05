#!/usr/bin/env python3
"""Acceptance test for m0-010: support matrix generator and staleness check."""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "gen_support_matrix.py"


def verify_discovery_scope() -> None:
    with tempfile.TemporaryDirectory(prefix="support-matrix-") as temporary:
        root = Path(temporary)
        script = root / "scripts" / SCRIPT.name
        script.parent.mkdir()
        shutil.copyfile(SCRIPT, script)
        reports = root / "benchmarks" / "reports"
        reports.mkdir(parents=True)
        readme = root / "README.md"
        readme.write_text("## Support matrix\n\n| stale |\n")

        def generate():
            subprocess.run([sys.executable, str(script)], cwd=root,
                           capture_output=True, text=True, check=True)
            rows = {}
            for line in readme.read_text().splitlines():
                if line.startswith("| ELF "):
                    _, name, _, status, _ = line.split("|")
                    rows[name.strip()] = status.strip()
            return rows

        before = generate()
        lock = json.loads((ROOT / "tests/corpus.lock.json").read_text())
        corpus = [{"id": f"{row['architecture']}_{row['variant']}", "status": "pass"}
                  for row in lock["entries"] if row["format"] == "elf"]
        (reports / "discovery-gate.json").write_text(json.dumps({
            "milestone": "M1", "passed": True, "corpus": corpus,
        }))
        after = generate()
        for target in ("ELF ARM LE32", "ELF MIPS LE32", "ELF RISC-V LE64"):
            assert after[target] == before[target], (
                f"M1 does not measure {target}, but its support claim changed"
            )
        assert "discovery gated" in after["ELF AARCH64 LE64"]
        ppc_name = next(name for name in after if name.startswith("ELF PowerPC"))
        assert "LE32/LE64" not in ppc_name, "BE32 evidence cannot gate LE configurations"
        assert "BE32" in after[ppc_name] and "discovery gated" in after[ppc_name]


def main() -> int:
    if not SCRIPT.is_file():
        sys.exit(f"FAIL: {SCRIPT} does not exist")
    verify_discovery_scope()

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
