#!/usr/bin/env python3
"""m1-008b: x86-64 plain_o0/cpp_o2 recall using approved code-functions-v1 views."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import sqlite3
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from gen_oracle import digest, provenance, validate_reference
from gen_function_scoring import POLICY, expected_view, validate_view


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--update-report", action="store_true")
    args = parser.parse_args()
    subprocess.run(["cargo", "build", "-q", "-p", "lre-cli"], cwd=ROOT, check=True)
    lock = json.loads((ROOT / "tests/corpus.lock.json").read_text())
    manifest = json.loads((args.corpus_dir / "manifest.json").read_text())
    assert manifest["sources"] == lock["sources"], "Corpus source manifest mismatch"
    for name, info in lock["sources"].items():
        assert digest(ROOT / "tests/corpus-src" / name) == info["sha256"]
    producer = provenance(Path(os.environ.get("VENTRIS_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC"))))
    rows = []
    with tempfile.TemporaryDirectory(prefix="m1-008b-gate-") as temporary:
        work = Path(temporary)
        for variant in ("plain_o0", "cpp_o2"):
            row = {"id": f"x86_64_{variant}", "status": "skipped", "metrics": {},
                   "thresholds": {"fn.recall": 0.98}, "runs": 1}
            try:
                recipe = next(r for r in lock["entries"] if r["architecture"] == "x86_64" and r["variant"] == variant)
                items = [r for r in manifest["entries"] if r["architecture"] == "x86_64" and r["variant"] == variant]
                assert len(items) == 1, "Missing or duplicate required corpus row"
                item = items[0]
                assert item["status"] == "ok", "Required corpus input was skipped"
                assert item["command"] == recipe["command"] and item["binary"] == recipe["binary"]
                binary = args.corpus_dir / recipe["binary"]
                sha = digest(binary)
                assert sha == item["binary_sha256"], "Primary hash mismatch"
                row["sha256"] = sha
                reference_path = ROOT / "oracle" / f"{sha}.json"
                reference = json.loads(reference_path.read_text())
                validate_reference(reference, {"schema_version": 1, "sha256": sha,
                    "binary_size": binary.stat().st_size, **producer, "address_basis": "ghidra"})
                row["oracle"] = str(reference_path.relative_to(ROOT))
                row["oracle_sha256"] = digest(reference_path)
                view_path = ROOT / "oracle/scoring-v1" / reference_path.name
                view = json.loads(view_path.read_text())
                validate_view(view, reference, expected_view(binary, reference_path))
                row.update(scoring_policy=POLICY, scoring_view=str(view_path.relative_to(ROOT)),
                           scoring_view_sha256=digest(view_path),
                           raw_oracle_functions=len(reference["entries"]),
                           excluded_functions=len(view["excluded"]))
                oracle = {int(a, 16) for a in view["entries"]}
                # Keep every scored entry, including unreferenced code and real PLT stubs.
                data = binary.read_bytes()
                assert data[:6] == b"\x7fELF\x02\x01"
                shoff = struct.unpack_from("<Q", data, 40)[0]
                stride, count = struct.unpack_from("<HH", data, 58)
                sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * stride) for i in range(count)]
                executable = [(s[3], s[3] + s[5]) for s in sections if s[2] & 4]
                row["oracle_entries_outside_executable_sections"] = [f"{a:08x}" for a in sorted(oracle)
                    if not any(start <= a < end for start, end in executable)]
                project = work / variant
                result = subprocess.run([str(ROOT / "target/debug/lre-cli"), "import-native", str(binary),
                    "--name", variant, "--project", str(project)], capture_output=True, text=True, timeout=180)
                assert result.returncode == 0, result.stdout + result.stderr
                with sqlite3.connect(project / "project.sqlite") as db:
                    native = {int(r[0], 16) for r in db.execute("SELECT entry FROM functions")}
                matched = native & oracle
                row.update(native_functions=len(native), oracle_functions=len(oracle), matched_functions=len(matched),
                           missing_entries=[f"{a:08x}" for a in sorted(oracle-native)],
                           extra_entries=[f"{a:08x}" for a in sorted(native-oracle)])
                row["metrics"] = {"fn.recall": len(matched)/len(oracle),
                                  "fn.precision": len(matched)/len(native) if native else 0.0}
                row["status"] = "pass" if row["metrics"]["fn.recall"] >= 0.98 else "fail"
            except (OSError, subprocess.SubprocessError) as error:
                row["reason"] = str(error)
            except (AssertionError, ValueError, KeyError, struct.error, sqlite3.Error) as error:
                row.update(status="fail", reason=str(error))
            rows.append(row)
        report = {"gate": "m1-008b", "milestone": "M1", "scoring_policy": POLICY,
                  "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                  "date": datetime.now(timezone.utc).date().isoformat(),
                  "machine": {"os": platform.platform(), "cpu": platform.machine()},
                  "corpus": rows, "summary": {s: sum(r["status"] == s for r in rows) for s in ("pass", "fail", "skipped")},
                  "passed": all(r["status"] == "pass" for r in rows)}
        destination = ROOT / "benchmarks/reports/m1-008b-v1.json" if args.update_report else work / "report.json"
        destination.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
        return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
