#!/usr/bin/env python3
"""Reject corrupt corpus manifests using real generated ELF artifacts."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CorpusIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="m1-006-integrity-")
        cls.directory = Path(cls.temp.name)
        cls.out = cls.directory / "corpus"
        subprocess.run([sys.executable, str(ROOT / "scripts/gen_corpus.py"),
                        "--out-dir", str(cls.out)], check=True, cwd=ROOT)
        cls.manifest = json.loads((cls.out / "manifest.json").read_text())
        cls.lock = json.loads((ROOT / "tests/corpus.lock.json").read_text())
        cls.verifier = (ROOT / "tests/m1-006_corpus.sh").read_text().split(
            "<<'EOF'\n", 1)[1].split("\nEOF", 1)[0]
        cls.cli = ROOT / "target/debug/lre-cli"
        cls.addClassCleanup(cls.temp.cleanup)

    def verify(self, manifest, mode="normal"):
        path = self.directory / "manifest.json"
        path.write_text(json.dumps(manifest))
        return subprocess.run([
            sys.executable, "-c", self.verifier,
            str(ROOT / "tests/corpus.lock.json"), str(path), str(self.out),
            str(self.cli), str(self.directory / "report.json"), mode,
        ], cwd=self.directory, capture_output=True, text=True)

    def test_real_artifacts_pass(self):
        result = self.verify(self.manifest)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_manifest_corruption_is_rejected(self):
        def skip_required(m):
            m["entries"][0].update(status="skipped", reason="missing required binary")

        def duplicate(m):
            m["entries"].append(copy.deepcopy(m["entries"][0]))

        def hash_mismatch(m):
            m["entries"][0]["binary_sha256"] = "0" * 64

        def twin_hash_mismatch(m):
            m["entries"][0]["unstripped_twin_sha256"] = "0" * 64

        def recipe_mismatch(m):
            m["entries"][0]["command"] = "not the committed recipe"

        def symbol_count_mismatch(m):
            m["entries"][0]["symbol_count"] = 999999

        def artifact_substitution(m):
            other = m["entries"][1]
            for field in ("binary", "binary_sha256", "unstripped_twin",
                          "unstripped_twin_sha256", "symbol_count"):
                m["entries"][0][field] = other[field]

        def claim_msvc_mode(m):
            m["selected_architectures"] = ["msvc"]
            m["entries"] = [e for e in m["entries"] if e["architecture"] == "msvc"]

        for mutate in (skip_required, duplicate, hash_mismatch, twin_hash_mismatch,
                       recipe_mismatch, symbol_count_mismatch, artifact_substitution,
                       claim_msvc_mode):
            with self.subTest(mutation=mutate.__name__):
                data = copy.deepcopy(self.manifest)
                mutate(data)
                result = self.verify(data)
                self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_update_lock_preserves_all_recipes_and_matrix(self):
        path = self.directory / "lock.json"
        path.write_text(json.dumps(self.lock))
        result = subprocess.run([
            sys.executable, str(ROOT / "scripts/gen_corpus.py"), "--lock", str(path),
            "--out-dir", str(self.directory / "unused"), "--msvc-only", "--update-lock",
        ], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        updated = json.loads(path.read_text())
        for field in ("expected_architectures", "expected_variants", "entries"):
            self.assertEqual(updated.get(field), self.lock[field], field)


if __name__ == "__main__":
    unittest.main()
