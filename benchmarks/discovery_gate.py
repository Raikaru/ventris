#!/usr/bin/env python3
"""m1-010: exact-entry discovery precision/recall on all 20 locked ELF inputs."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import sqlite3
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from gen_oracle import digest, provenance, validate_reference
from gen_function_scoring import POLICY, expected_view, validate_view


def architecture_check():
    # The roadmap explicitly requires a source check as well as set metrics.
    # Checking only the new module would miss the still-active legacy routes.
    core = ROOT / "crates/lre-core/src/native/discovery.rs"
    native = ROOT / "crates/lre-core/src/native.rs"
    legacy = re.findall(r"(?m)^(?:pub(?:\([^)]*\))?\s+)?fn\s+((?:sweep_calls|sweep_ppc_calls|flow_discover)\w*)\s*[<(]",
                        native.read_text())
    isa_lines = [{"line": n, "text": line.strip()}
                 for n, line in enumerate(core.read_text().splitlines(), 1)
                 if re.search(r"x86|PowerPC|AARCH64|disasm::", line, re.IGNORECASE)]
    decoder = ROOT / "crates/lre-core/src/disasm.rs"
    retired = re.findall(r"(?m)^pub fn (discover)\s*[<(]", decoder.read_text())
    switches = [str(path.relative_to(ROOT)) for path in (
        ROOT / "crates/lre-core/Cargo.toml", ROOT / "crates/lre-cli/Cargo.toml")
        if re.search(r"(?m)^x86_decoder\s*=", path.read_text())]
    return {"passed": not legacy and not isa_lines and not retired and not switches,
            "core": str(core.relative_to(ROOT)), "core_sha256": digest(core),
            "legacy_source_sha256": digest(native),
            "retired_decoder_discovery": retired, "retired_feature_switches": switches,
            "legacy_discovery_definitions": legacy, "isa_specific_lines": isa_lines}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--oracle-dir", type=Path, default=ROOT / "oracle")
    parser.add_argument("--scoring-dir", type=Path, default=ROOT / "oracle/scoring-v1")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    subprocess.run(["cargo", "build", "-q", "-p", "lre-cli"], cwd=ROOT, check=True)
    lock = json.loads((ROOT / "tests/corpus.lock.json").read_text())
    required = [r for r in lock["entries"] if r["format"] == "elf"]
    setup_error = None
    actual = {}
    try:
        manifest = json.loads((args.corpus_dir / "manifest.json").read_text())
        if manifest["sources"] != lock["sources"]:
            raise ValueError("Corpus source manifest mismatch")
        for name, info in lock["sources"].items():
            if digest(ROOT / "tests/corpus-src" / name) != info["sha256"]:
                raise ValueError(f"Corpus source changed: {name}")
        for item in manifest["entries"]:
            key = (item["architecture"], item["variant"])
            if key in actual:
                raise ValueError("Duplicate corpus row")
            actual[key] = item
        producer = provenance(Path(os.environ.get("VENTRIS_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC"))))
    except (OSError, ValueError, KeyError, TypeError) as error:
        setup_error = error
    rows = []
    with tempfile.TemporaryDirectory(prefix="discovery-gate-") as temporary:
        for recipe in required:
            key = (recipe["architecture"], recipe["variant"])
            row = {"id": "_".join(key), "status": "skipped", "metrics": {},
                   "thresholds": {"fn.precision": 0.98, "fn.recall": 0.98}, "runs": 1}
            try:
                if setup_error:
                    raise setup_error
                item = actual.get(key)
                if not item or item.get("status") != "ok":
                    raise FileNotFoundError("Required corpus input missing or skipped")
                if item["command"] != recipe["command"] or item["binary"] != recipe["binary"]:
                    raise ValueError("Corpus recipe mismatch")
                binary = (args.corpus_dir / recipe["binary"]).resolve()
                sha = digest(binary)
                if sha != item["binary_sha256"]:
                    raise ValueError("Corpus binary hash mismatch")
                row["sha256"] = sha
                reference_path = args.oracle_dir / f"{sha}.json"
                raw = json.loads(reference_path.read_text())
                validate_reference(raw, {"schema_version": 1, "sha256": sha,
                    "binary_size": binary.stat().st_size, **producer, "address_basis": "ghidra"})
                view_path = args.scoring_dir / reference_path.name
                view = json.loads(view_path.read_text())
                validate_view(view, raw, expected_view(binary, reference_path))
                oracle = {int(a, 16) for a in view["entries"]}
                if not oracle:
                    raise ValueError("No scored oracle functions")
                row.update(oracle_sha256=digest(reference_path), scoring_view_sha256=digest(view_path),
                           raw_oracle_functions=len(raw["entries"]), excluded_functions=len(view["excluded"]))
                project = Path(temporary) / row["id"]
                result = subprocess.run([str(ROOT / "target/debug/lre-cli"), "import-native", str(binary),
                    "--name", row["id"], "--project", str(project)], capture_output=True, text=True, timeout=180)
                if result.returncode:
                    raise ValueError(result.stdout + result.stderr)
                with sqlite3.connect(project / "project.sqlite") as db:
                    native = {int(r[0], 16) for r in db.execute("SELECT entry FROM functions")}
                matched = native & oracle
                row.update(native_functions=len(native), oracle_functions=len(oracle), matched_functions=len(matched),
                           missing_entries=[f"{a:08x}" for a in sorted(oracle - native)],
                           extra_entries=[f"{a:08x}" for a in sorted(native - oracle)])
                row["metrics"] = {"fn.precision": len(matched) / len(native) if native else 0.0,
                                  "fn.recall": len(matched) / len(oracle)}
                row["status"] = "pass" if all(row["metrics"][k] >= v for k, v in row["thresholds"].items()) else "fail"
            except (OSError, subprocess.SubprocessError) as error:
                row["reason"] = str(error)
            except (ValueError, KeyError, TypeError, sqlite3.Error) as error:
                row.update(status="fail", reason=str(error))
            rows.append(row)
            print(f"{row['status'].upper()} {row['id']}: {row.get('reason', row['metrics'])}", flush=True)
    architecture = architecture_check()
    report = {"gate": "discovery", "milestone": "M1", "scoring_policy": POLICY,
              "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "date": datetime.now(timezone.utc).date().isoformat(),
              "machine": {"os": platform.platform(), "cpu": platform.machine()},
              "architecture_check": architecture, "corpus": rows,
              "summary": {s: sum(r["status"] == s for r in rows) for s in ("pass", "fail", "skipped")},
              "passed": len(rows) == 20 and all(r["status"] == "pass" for r in rows) and architecture["passed"]}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"summary": report["summary"], "architecture_check": architecture, "passed": report["passed"]}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
