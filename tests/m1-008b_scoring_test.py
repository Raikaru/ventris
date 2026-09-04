#!/usr/bin/env python3
"""Approved code-functions-v1 partition, provenance, and immutable raw references."""
import copy
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


class ScoringAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="scoring-acceptance-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.work = Path(cls.temp.name)
        cls.corpus = Path(os.environ.get("CORPUS_DIR", str(cls.work / "corpus")))
        if "CORPUS_DIR" not in os.environ:
            subprocess.run([sys.executable, "scripts/gen_corpus.py", "--architectures",
                            "x86_64,i386,aarch64,powerpc", "--out-dir", str(cls.corpus)], cwd=ROOT, check=True)
        cls.oracles = Path(os.environ.get("ORACLE_DIR", str(cls.work / "oracle")))
        if "ORACLE_DIR" not in os.environ:
            subprocess.run([sys.executable, "scripts/gen_oracle.py", "--corpus-dir",
                            str(cls.corpus), "--output-dir", str(cls.oracles),
                            "--report", str(cls.work / "oracles.json")], cwd=ROOT, check=True)
        cls.before = {p: p.read_bytes() for directory in (ROOT / "oracle", cls.oracles)
                      for p in directory.glob("*.json")}
        cls.command = [sys.executable, str(ROOT / "scripts/gen_function_scoring.py"),
                       "--corpus-dir", str(cls.corpus), "--output-dir", str(cls.work / "views"),
                       "--oracle-dir", str(cls.oracles),
                       "--report", str(cls.work / "report.json")]
        result = subprocess.run(cls.command, cwd=ROOT, text=True, capture_output=True, timeout=900)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        cls.report = json.loads((cls.work / "report.json").read_text())

    def test_all_twenty_inputs_partition_without_rewriting_raw_references(self):
        self.assertEqual(self.report["summary"], {"pass": 20, "fail": 0, "skipped": 0})
        from gen_oracle import digest
        for row in self.report["corpus"]:
            raw = self.oracles / (row["sha256"] + ".json")
            view = json.loads((self.work / "views" / raw.name).read_text())
            entries = set(json.loads(raw.read_text())["entries"])
            kept = set(view["entries"])
            excluded = {r["entry"] for r in view["excluded"]}
            self.assertEqual(kept | excluded, entries)
            self.assertFalse(kept & excluded)
            self.assertEqual(view["raw_reference_sha256"], digest(raw))
            for item in view["excluded"]:
                evidence = item["evidence"]
                self.assertEqual(evidence["block_name"], "EXTERNAL")
                self.assertIs(evidence["block_artificial"], True)
                self.assertEqual(evidence["block_source"], "Elf Loader")
                self.assertIs(evidence["thunk_external"], True)
        for path, content in self.before.items():
            self.assertEqual(path.read_bytes(), content, str(path))

    def test_check_rejects_a_dropped_real_function(self):
        row = self.report["corpus"][0]
        path = self.work / "views" / (row["sha256"] + ".json")
        original = path.read_bytes()
        view = json.loads(original)
        view["entries"].pop()
        path.write_text(json.dumps(view))
        try:
            result = subprocess.run(self.command + ["--check"], cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(json.loads((self.work / "report.json").read_text())["passed"])
        finally:
            path.write_bytes(original)

    def test_rejects_output_over_raw_oracles(self):
        result = subprocess.run(self.command + ["--output-dir", str(self.oracles)],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        for path, content in self.before.items():
            self.assertEqual(path.read_bytes(), content, str(path))


class ScoringPolicy(unittest.TestCase):
    def test_only_positive_loader_evidence_excludes_a_function(self):
        policy = importlib.import_module("gen_function_scoring").is_synthetic_external
        external = {"block_name": "EXTERNAL", "block_artificial": True,
                    "block_source": "Elf Loader", "thunk_external": True}
        self.assertTrue(policy(external))
        # Name collision, genuine PLT thunk, non-executable real code, and
        # incomplete evidence must not become exclusions.
        for field, value in (("block_artificial", False), ("block_name", ".plt"),
                             ("block_source", "input file"), ("thunk_external", False)):
            real = copy.deepcopy(external)
            real[field] = value
            self.assertFalse(policy(real))
        self.assertFalse(policy({"block_execute": False}))
        self.assertFalse(policy({}))


if __name__ == "__main__":
    unittest.main()
