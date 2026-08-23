import hashlib
import json
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ventris import corpus_smoke


def envelope(command: str, result: str) -> str:
    return json.dumps({"ok": True, "command": command, "result": result})


class CorpusSmokeTests(unittest.TestCase):
    def manifest_output(self, *, expected_hash: str, functions=None) -> str:
        manifest = [
            {
                "id": "ps2-test",
                "title": "PS2 test",
                "target": "ps2",
                "binary_name": "test.elf",
                "binary_sha256": expected_hash,
                "functions": functions
                or [{"name": "Game_Task", "address": "0x250190", "size": "0x1f0"}],
            }
        ]
        return envelope("corpus", json.dumps(manifest))

    def test_parse_manifest_reads_nested_cli_envelope(self):
        digest = "a" * 64
        entries = corpus_smoke.parse_manifest(self.manifest_output(expected_hash=digest))

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].functions[0].size, 0x1F0)
        self.assertEqual(entries[0].binary_sha256, digest)

    def test_smoke_runs_every_manifest_function(self):
        data = b"real image"
        digest = hashlib.sha256(data).hexdigest()
        functions = [
            {"name": "first", "address": "0x250190", "size": "0x1f0"},
            {"name": "second", "address": "0x250380", "size": "0x20"},
        ]
        calls = []

        def fake_runner(command, args):
            calls.append(list(args))
            if args[0] == "corpus":
                return self.manifest_output(expected_hash=digest, functions=functions), ""
            if args[0] == "resolve":
                address = args[2].split("::")[-1]
                return envelope("resolve", f"space: ram\noffset: {address}\n"), ""
            if args[0] == "decompile-native":
                return envelope("decompile-native", "void sub(void) {}\n"), ""
            raise AssertionError(args)

        with tempfile.TemporaryDirectory() as directory:
            image_dir = Path(directory)
            (image_dir / "test.elf").write_bytes(data)
            report = corpus_smoke.run_smoke(
                image_dir,
                ids=("ps2-test",),
                command=("ventris",),
                limit=64,
                require_hashes=True,
                command_runner=fake_runner,
            )

        self.assertTrue(report["ok"])
        entry = report["entries"][0]
        self.assertEqual(entry["function_count"], 2)
        self.assertEqual([item["name"] for item in entry["functions"]], ["first", "second"])
        analysis_calls = [call for call in calls if call[0] in ("resolve", "decompile-native")]
        self.assertEqual(len(analysis_calls), 4)
        self.assertEqual(
            [call[2] for call in analysis_calls],
            ["ram::0x250190", "ram::0x250190", "ram::0x250380", "ram::0x250380"],
        )

    def test_function_failure_does_not_skip_remaining_functions(self):
        data = b"real image"
        digest = hashlib.sha256(data).hexdigest()
        functions = [
            {"name": "first", "address": "0x250190", "size": "0x1f0"},
            {"name": "second", "address": "0x250380", "size": "0x20"},
        ]
        decompile_addresses = []

        def fake_runner(command, args):
            if args[0] == "corpus":
                return self.manifest_output(expected_hash=digest, functions=functions), ""
            if args[0] == "resolve":
                address = args[2].split("::")[-1]
                return envelope("resolve", f"space: ram\noffset: {address}\n"), ""
            if args[0] == "decompile-native":
                decompile_addresses.append(args[2])
                if args[2].endswith("250190"):
                    return json.dumps({"ok": False, "error": "broken function"}), ""
                return envelope("decompile-native", "void sub(void) {}\n"), ""
            raise AssertionError(args)

        with tempfile.TemporaryDirectory() as directory:
            image_dir = Path(directory)
            (image_dir / "test.elf").write_bytes(data)
            report = corpus_smoke.run_smoke(
                image_dir,
                ids=("ps2-test",),
                command=("ventris",),
                require_hashes=True,
                command_runner=fake_runner,
            )

        self.assertFalse(report["ok"])
        self.assertEqual(decompile_addresses, ["ram::0x250190", "ram::0x250380"])
        self.assertEqual([item["status"] for item in report["entries"][0]["functions"]], ["fail", "pass"])

    def test_text_mode_reports_passed_functions(self):
        report = {
            "ok": True,
            "entries": [
                {
                    "id": "ps2-test",
                    "status": "pass",
                    "function_count": 1,
                    "sha256": "a" * 64,
                    "hash_status": "verified",
                    "functions": [
                        {
                            "name": "first",
                            "address": "0x250190",
                            "status": "pass",
                        }
                    ],
                }
            ],
        }

        with patch.object(corpus_smoke, "run_smoke", return_value=report):
            with patch("sys.stdout", new_callable=StringIO) as output:
                result = corpus_smoke.main(
                    ["--image-dir", ".", "--ventris", "ventris", "--limit", "64"]
                )

        self.assertEqual(result, 0)
        self.assertIn("corpus-smoke: PASS (1 entries)", output.getvalue())
        self.assertIn("PASS first 0x250190", output.getvalue())


    def test_smoke_checks_hash_resolves_manifest_address_and_decompiles(self):
        data = b"real image"
        digest = hashlib.sha256(data).hexdigest()
        calls = []

        def fake_runner(command, args):
            calls.append(list(args))
            if args[0] == "corpus":
                return self.manifest_output(expected_hash=digest), ""
            if args[0] == "resolve":
                return envelope("resolve", "space: ram\noffset: 0x250190\n"), ""
            if args[0] == "decompile-native":
                return envelope("decompile-native", "void sub_250190(void) {}\n"), "warning\n"
            raise AssertionError(args)

        with tempfile.TemporaryDirectory() as directory:
            image_dir = Path(directory)
            (image_dir / "test.elf").write_bytes(data)
            report = corpus_smoke.run_smoke(
                image_dir,
                ids=("ps2-test",),
                command=("ventris",),
                limit=64,
                require_hashes=True,
                command_runner=fake_runner,
            )

        self.assertTrue(report["ok"])
        self.assertEqual(report["entries"][0]["hash_status"], "verified")
        self.assertIn("ram::0x250190", calls[1])
        self.assertIn("ram::0x250190", calls[2])
        self.assertEqual(report["entries"][0]["warnings"], ["warning"])

    def test_hash_mismatch_fails_entry_without_running_analysis(self):
        calls = []

        def fake_runner(command, args):
            calls.append(list(args))
            if args[0] == "corpus":
                return self.manifest_output(expected_hash="0" * 64), ""
            raise AssertionError("analysis should not run after a hash mismatch")

        with tempfile.TemporaryDirectory() as directory:
            image_dir = Path(directory)
            (image_dir / "test.elf").write_bytes(b"different image")
            report = corpus_smoke.run_smoke(
                image_dir,
                ids=("ps2-test",),
                command=("ventris",),
                command_runner=fake_runner,
            )

        self.assertFalse(report["ok"])
        self.assertIn("SHA-256 mismatch", report["entries"][0]["error"])
        self.assertEqual([call[0] for call in calls], ["corpus"])

    def test_unknown_id_is_reported_as_failed_entry(self):
        def fake_runner(command, args):
            return self.manifest_output(expected_hash="a" * 64), ""

        with tempfile.TemporaryDirectory() as directory:
            report = corpus_smoke.run_smoke(
                Path(directory),
                ids=("missing",),
                command=("ventris",),
                command_runner=fake_runner,
            )

        self.assertFalse(report["ok"])
        self.assertEqual(report["entries"][0]["status"], "fail")
        self.assertEqual(report["entries"][0]["error"], "unknown corpus id")


if __name__ == "__main__":
    unittest.main()
