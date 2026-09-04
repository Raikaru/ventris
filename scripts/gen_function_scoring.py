#!/usr/bin/env python3
"""Generate code-functions-v1 views without rewriting raw m1-007 references."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import tempfile

from gen_oracle import ROOT, address, digest, provenance, validate_reference, write_reference

POLICY = "code-functions-v1"
EXPORTER = ROOT / "scripts/ExportFunctionScoring.java"
REASON = "elf-loader-synthetic-external"


def is_synthetic_external(evidence):
    # Positive loader provenance plus a real external thunk target. Neither
    # permissions, function names nor unmapped addresses alone are exclusions.
    return (evidence.get("block_name") == "EXTERNAL"
            and evidence.get("block_artificial") is True
            and evidence.get("block_source") == "Elf Loader"
            and evidence.get("thunk_external") is True)


def validate_view(view, raw, expected):
    for key, value in expected.items():
        if view.get(key) != value:
            raise ValueError(f"Scoring {key} mismatch")
    entries = view["entries"]
    excluded = view["excluded"]
    if entries != sorted(set(entries), key=lambda a: int(a, 16)):
        raise ValueError("Scored entries are not unique and sorted")
    removed = []
    for item in excluded:
        if item["reason"] != REASON or not is_synthetic_external(item["evidence"]):
            raise ValueError("Exclusion lacks positive loader evidence")
        if item["entry"] != address(item["entry"]):
            raise ValueError("Noncanonical excluded entry")
        evidence = item["evidence"]
        if not int(address(evidence["block_start"]), 16) <= int(item["entry"], 16) <= int(address(evidence["block_end"]), 16):
            raise ValueError("Excluded entry is outside its evidence block")
        removed.append(item["entry"])
    if len(removed) != len(set(removed)) or set(entries) & set(removed):
        raise ValueError("Scoring partitions overlap or contain duplicates")
    if set(entries) | set(removed) != set(raw["entries"]):
        raise ValueError("Scoring partition changed the raw oracle set")


def expected_view(binary, reference):
    return {"schema_version": 1, "policy": POLICY, "sha256": digest(binary),
            "raw_reference_sha256": digest(reference), "exporter_sha256": digest(EXPORTER)}


def export_evidence(install, binary, work, timeout):
    output = work / "evidence.json"
    result = subprocess.run([str(install / "support/analyzeHeadless"), str(work), "scoring",
                             "-import", str(binary), "-scriptPath", str(EXPORTER.parent),
                             "-postScript", EXPORTER.name, str(output), "-deleteProject"],
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode or not output.is_file():
        raise ValueError(f"Evidence export failed: {result.stdout[-4000:]} {result.stderr[-4000:]}")
    return json.loads(output.read_text())


def make_view(raw, expected, evidence):
    observed = [address(row["entry"]) for row in evidence]
    if len(observed) != len(set(observed)) or set(observed) != set(raw["entries"]):
        raise ValueError("Fresh evidence function set differs from immutable raw oracle")
    entries, excluded = [], []
    for row in evidence:
        entry = address(row["entry"])
        if is_synthetic_external(row):
            excluded.append({"entry": entry, "reason": REASON,
                             "evidence": {k: v for k, v in row.items() if k != "entry"}})
        else:
            entries.append(entry)
    view = {**expected, "upstream_version": raw["upstream_version"],
            "upstream_revision": raw["upstream_revision"],
            "entries": sorted(entries, key=lambda a: int(a, 16)),
            "excluded": sorted(excluded, key=lambda r: int(r["entry"], 16))}
    validate_view(view, raw, expected)
    return view


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--oracle-dir", type=Path, default=ROOT / "oracle")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "oracle/scoring-v1")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--ghidra", type=Path, default=Path(os.environ.get("VENTRIS_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC"))))
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    args.corpus_dir = args.corpus_dir.resolve()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    lock = json.loads((ROOT / "tests/corpus.lock.json").read_text())
    required = [r for r in lock["entries"] if r["format"] == "elf"]
    setup_error = None
    actual = {}
    try:
        manifest = json.loads((args.corpus_dir / "manifest.json").read_text())
        if manifest["sources"] != lock["sources"]:
            raise ValueError("Corpus sources mismatch")
        for name, item in lock["sources"].items():
            if digest(ROOT / "tests/corpus-src" / name) != item["sha256"]:
                raise ValueError(f"Corpus source changed: {name}")
        for row in manifest["entries"]:
            key = (row["architecture"], row["variant"])
            if key in actual:
                raise ValueError("Duplicate corpus row")
            actual[key] = row
        producer = provenance(args.ghidra)
    except (OSError, ValueError, KeyError) as error:
        setup_error = error
    rows = []
    for recipe in required:
        key = (recipe["architecture"], recipe["variant"])
        row = {"id": "_".join(key), "status": "skipped"}
        try:
            if setup_error:
                raise setup_error
            item = actual.get(key)
            if not item or item.get("status") != "ok":
                raise FileNotFoundError("Required corpus row missing or skipped")
            if item["command"] != recipe["command"] or item["binary"] != recipe["binary"]:
                raise ValueError("Corpus recipe mismatch")
            binary = args.corpus_dir / recipe["binary"]
            sha = digest(binary)
            if sha != item["binary_sha256"]:
                raise ValueError("Corpus binary hash mismatch")
            row["sha256"] = sha
            reference = args.oracle_dir / f"{sha}.json"
            raw = json.loads(reference.read_text())
            validate_reference(raw, {"schema_version": 1, "sha256": sha,
                               "binary_size": binary.stat().st_size, **producer, "address_basis": "ghidra"})
            expected = expected_view(binary, reference)
            destination = args.output_dir / reference.name
            if destination.resolve() == reference.resolve():
                raise ValueError("Scoring destination must not replace a raw oracle")
            if args.check:
                view = json.loads(destination.read_text())
                validate_view(view, raw, expected)
            else:
                with tempfile.TemporaryDirectory(prefix="function-scoring-") as work:
                    view = make_view(raw, expected, export_evidence(args.ghidra, binary, Path(work), args.timeout))
                if digest(reference) != expected["raw_reference_sha256"] or digest(binary) != sha:
                    raise ValueError("Input changed during evidence export")
                write_reference(destination, view)
            row.update(status="pass", raw_functions=len(raw["entries"]),
                       scored_functions=len(view["entries"]), excluded_functions=len(view["excluded"]),
                       view_sha256=digest(destination))
        except (OSError, subprocess.SubprocessError) as error:
            row["reason"] = str(error)
        except (ValueError, KeyError, TypeError) as error:
            row.update(status="fail", reason=str(error))
        rows.append(row)
        print(f"{row['status'].upper()} {row['id']}: {row.get('reason', row.get('scored_functions'))}", flush=True)
    summary = {s: sum(r["status"] == s for r in rows) for s in ("pass", "fail", "skipped")}
    report = {"gate": "m1-008b-scoring", "policy": POLICY,
              "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "date": datetime.now(timezone.utc).date().isoformat(), "corpus": rows,
              "summary": summary, "passed": len(rows) == 20 and summary["pass"] == 20}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"summary": summary, "passed": report["passed"]}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
