#!/usr/bin/env python3
"""Acceptance test for the UI gate report contract."""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / "benchmarks" / "ui_gate.py"
BINARY = ROOT / "tests" / "fixtures-src" / "tiny_bin"


def main() -> int:
    with TemporaryDirectory(prefix="ventris-ui-gate-test-") as directory:
        temp = Path(directory)
        fake_app = temp / "fake_gate_app.py"
        fake_app.write_text(
            "#!/usr/bin/env python3\n"
            "import json\n"
            "import sys\n"
            "assert '--gate' in sys.argv\n"
            "print(json.dumps({'metrics': {\n"
            "    'ui.list.load_ms': 12.5,\n"
            "    'ui.list.filter_ms': 4.0,\n"
            "    'ui.sync_ms': 2.0,\n"
            "    'ui.graph.layout_ms': 10.0,\n"
            "    'ui.graph.paint_ms': 3.0,\n"
            "    'ui.install.ok': True,\n"
            "}}))\n",
            encoding="utf-8",
        )
        fake_app.chmod(fake_app.stat().st_mode | stat.S_IXUSR)
        report = temp / "ui-gate.json"
        project = temp / "project"
        subprocess.run(
            [
                sys.executable,
                str(GATE),
                "--app",
                str(fake_app),
                "--binary",
                str(BINARY),
                "--project",
                str(project),
                "--runs",
                "1",
                "--program",
                "tiny",
                "--output",
                str(report),
            ],
            check=True,
            cwd=ROOT,
            env={**os.environ, "SOURCE_DATE_EPOCH": "0"},
        )
        document = json.loads(report.read_text(encoding="utf-8"))
        assert document["gate"] == "ui"
        assert document["milestone"] == "M0"
        assert len(document["commit"]) == 40
        assert len(document["date"]) == 10
        assert set(document["machine"]) == {"os", "cpu", "ram_gb"}
        assert document["corpus"] and len(document["corpus"]) == 1
        entry = document["corpus"][0]
        assert entry["id"] == "tiny"
        assert len(entry["sha256"]) == 64
        assert entry["status"] == "pass"
        assert set(entry["metrics"]) == {
            "ui.list.load_ms",
            "ui.list.filter_ms",
            "ui.sync_ms",
            "ui.graph.layout_ms",
            "ui.graph.paint_ms",
            "ui.install.ok",
        }
        assert set(entry["thresholds"]) == {
            "ui.list.load_ms",
            "ui.list.filter_ms",
            "ui.sync_ms",
            "ui.graph.layout_ms",
            "ui.graph.paint_ms",
        }
        assert entry["runs"] == 1
        assert document["summary"] == {"pass": 1, "fail": 0, "skipped": 0}
        assert document["passed"] is True
    print("ui gate schema acceptance: pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
