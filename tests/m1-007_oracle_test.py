#!/usr/bin/env python3
"""m1-007 acceptance: real bridge oracles for all 20 ELF corpus entries."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "scripts/gen_oracle.py"
ARCHITECTURES = "x86_64,i386,aarch64,powerpc"


class OracleAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="m1-007-acceptance-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.work = Path(cls.temp.name)
        cls.corpus = cls.work / "corpus"
        cls.cache = cls.work / "oracle"
        cls.report = cls.work / "report.json"
        subprocess.run([sys.executable, str(ROOT / "scripts/gen_corpus.py"),
                        "--architectures", ARCHITECTURES, "--out-dir", str(cls.corpus)],
                       check=True, cwd=ROOT)
        cls.command = [sys.executable, str(GENERATOR), "--corpus-dir", str(cls.corpus),
                       "--output-dir", str(cls.cache), "--report", str(cls.report)]
        result = subprocess.run(cls.command, capture_output=True, text=True, timeout=900)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        cls.initial_report = json.loads(cls.report.read_text())
        cls.manifest = json.loads((cls.corpus / "manifest.json").read_text())

    def run_generator(self, *args):
        return subprocess.run(self.command + list(args), capture_output=True, text=True, timeout=900)

    def test_every_primary_has_a_complete_bridge_reference(self):
        self.assertTrue(self.initial_report["passed"])
        self.assertEqual(self.initial_report["summary"], {"pass": 20, "fail": 0, "skipped": 0})
        for entry in self.manifest["entries"]:
            binary = self.corpus / entry["binary"]
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            oracle = json.loads((self.cache / f"{digest}.json").read_text())
            self.assertEqual(oracle["sha256"], digest)
            self.assertEqual(oracle["address_basis"], "ghidra")
            self.assertEqual(oracle["producer"], "ghidra-bridge")
            self.assertEqual(oracle["upstream_version"], "12.1.3")
            self.assertEqual(len(oracle["bridge_sources_sha256"]), 64)
            int(oracle["image_base"], 16)
            entries = oracle["entries"]
            self.assertGreater(len(entries), 0)
            self.assertEqual(len(entries), oracle["imported_function_count"])
            self.assertEqual(entries, sorted(set(entries), key=lambda value: int(value, 16)))

    def test_cache_hit_does_not_launch_java_or_rewrite_references(self):
        snapshots = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.cache.iterdir()}
        result = self.run_generator("--java", str(self.work / "missing-java"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(self.report.read_text())
        self.assertEqual(report["cache_hits"], 20)
        self.assertEqual(report["generated"], 0)
        for path, original in snapshots.items():
            self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), original)

    def test_invalid_reference_is_not_counted_as_a_cache_hit(self):
        entry = self.manifest["entries"][0]
        path = self.cache / f"{entry['binary_sha256']}.json"
        original = path.read_bytes()
        for field, value in (("sha256", "0" * 64), ("entries", []),
                             ("bridge_sources_sha256", "0" * 64)):
            with self.subTest(field=field):
                broken = json.loads(original)
                broken[field] = value
                path.write_text(json.dumps(broken))
                try:
                    result = self.run_generator("--check")
                    self.assertNotEqual(result.returncode, 0)
                    report = json.loads(self.report.read_text())
                    self.assertFalse(report["passed"])
                    self.assertEqual(report["summary"]["skipped"], 1)
                finally:
                    path.write_bytes(original)

    def test_missing_primary_remains_skipped_even_with_cached_oracle(self):
        entry = self.manifest["entries"][0]
        primary = self.corpus / entry["binary"]
        moved = primary.with_suffix(".held")
        primary.rename(moved)
        try:
            result = self.run_generator("--check")
            self.assertNotEqual(result.returncode, 0)
            report = json.loads(self.report.read_text())
            self.assertFalse(report["passed"])
            skipped = [row for row in report["corpus"] if row["status"] == "skipped"]
            self.assertEqual(len(skipped), 1)
            self.assertIn("missing", skipped[0]["reason"].lower())
        finally:
            moved.rename(primary)


if __name__ == "__main__":
    unittest.main()
