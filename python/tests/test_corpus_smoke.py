import hashlib
import json
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import corpus_smoke


def envelope(command: str, result: str) -> str:
    return json.dumps({"ok": True, "command": command, "result": result})


class CorpusSmokeTests(unittest.TestCase):
    def manifest_output(
        self,
        *,
        expected_hash: str,
        functions=None,
        semantic=None,
        metadata=None,
        target="ps2",
        toolchain=None,
        base=None,
        address_space=None,
    ) -> str:
        manifest_functions = functions or [
            {"name": "Game_Task", "address": "0x250190", "size": "0x1f0"}
        ]
        manifest_functions = [
            {**function, "source_path": function.get("source_path", "src/test.c")}
            for function in manifest_functions
        ]
        if semantic is not None:
            manifest_functions = [
                {**function, "semantic": semantic} for function in manifest_functions
            ]
        manifest = [
            {
                "id": "ps2-test",
                "title": "PS2 test",
                "target": target,
                "source_url": "https://example.invalid/repo",
                "source_commit": "1" * 40,
                "source_license": "AGPL-3.0",
                "binary_name": "test.elf",
                "binary_sha256": expected_hash,
                "binary_sha1": None,
                "base": base,
                "address_space": address_space,
                "metadata": metadata,
                "toolchain": toolchain,
                "functions": manifest_functions,
            }
        ]
        return envelope("corpus", json.dumps(manifest))

    def test_parse_manifest_reads_nested_cli_envelope(self):
        digest = "a" * 64
        entries = corpus_smoke.parse_manifest(self.manifest_output(expected_hash=digest))

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].functions[0].size, 0x1F0)
        self.assertEqual(entries[0].binary_sha256, digest)


    def test_parse_manifest_retains_raw_image_base_override(self):
        entry = corpus_smoke.parse_manifest(
            self.manifest_output(expected_hash="a" * 64, target="ps1", base="0x8000f800")
        )[0]
        self.assertEqual(entry.base, 0x8000F800)

    def test_manifest_address_space_qualifies_function_commands(self):
        entry = corpus_smoke.parse_manifest(
            self.manifest_output(
                expected_hash="a" * 64,
                address_space="ram",
            )
        )[0]

        self.assertEqual(
            corpus_smoke.function_address(entry, entry.functions[0]),
            "ram::0x250190",
        )

    def test_parse_manifest_retains_embedded_source_metadata(self):
        metadata = {
            "provenance": {
                "url": "https://example.invalid/repo",
                "commit": "1" * 40,
                "license": "MIT",
                "path": "src/game.hpp",
            }
        }
        entry = corpus_smoke.parse_manifest(
            self.manifest_output(expected_hash="a" * 64, metadata=metadata)
        )[0]
        self.assertEqual(entry.metadata, metadata)
    def test_parse_manifest_reads_typed_toolchain_for_non_ps2_targets(self):
        toolchain = {
            "id": "llvm-arm-thumb",
            "compiler": {"program": "clang", "args": ["-c", "{source}", "-o", "{object}"]},
            "disassembler": {
                "program": "llvm-objdump",
                "args": ["-d", "--start-address={start}", "--stop-address={stop}", "{input}"],
            },
            "disassembly_format": "llvm",
            "mnemonic_aliases": [{"from": "b", "to": "bl"}],
            "call_mnemonics": ["bl", "blx"],
            "retail_input": "image",
        }
        entry = corpus_smoke.parse_manifest(
            self.manifest_output(
                expected_hash="a" * 64,
                target="wii",
                toolchain=toolchain,
            )
        )[0]
        self.assertEqual(entry.target, "wii")
        self.assertEqual(entry.toolchain.disassembly_format, "llvm")
        self.assertEqual(entry.toolchain.call_mnemonics, ("bl", "blx"))
        self.assertEqual(entry.toolchain.mnemonic_aliases[0].to_mnemonic, "bl")

    def test_manifest_rejects_toolchain_profile_target_mismatch(self):
        toolchain = {
            "id": "bad",
            "target": "ps2",
            "compiler": {"program": "cc", "args": ["{source}", "{object}"]},
            "disassembler": {"program": "objdump", "args": ["{input}"]},
            "disassembly_format": "gnu",
            "mnemonic_aliases": [],
            "call_mnemonics": ["bl"],
            "retail_input": "image",
        }
        with self.assertRaisesRegex(corpus_smoke.SmokeError, "does not match target"):
            corpus_smoke.parse_manifest(
                self.manifest_output(
                    expected_hash="a" * 64,
                    target="wii",
                    toolchain=toolchain,
                )
            )

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
                return self.manifest_output(
                    expected_hash=digest,
                    functions=functions,
                    target="ps1",
                    base="0x8000f800",
                ), ""
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
            ["0x250190", "0x250190", "0x250380", "0x250380"],
        )
        self.assertTrue(
            all(
                call[call.index("--base") + 1] == "0x8000f800"
                for call in analysis_calls
            )
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
        self.assertEqual(decompile_addresses, ["0x250190", "0x250380"])
        self.assertEqual([item["status"] for item in report["entries"][0]["functions"]], ["fail", "pass"])

    def test_semantic_exact_match_is_distinguished(self):
        digest = "a" * 64
        semantic = {
            "control_flow": [],
            "calls": ["callee@0x3000"],
            "globals": ["gValue"],
            "access_types": ["u32"],
            "casts": 0,
            "aggregate_copies": 0,
            "declaration_order": [],
            "nominal_fields": ["gValue.field"],
            "source_structure": ["call"],
        }
        entry = corpus_smoke.parse_manifest(
            self.manifest_output(expected_hash=digest, semantic=semantic)
        )[0]
        report = corpus_smoke._semantic_report(
            entry,
            entry.functions[0],
            resolved="space: ram\noffset: 0x250190\n",
            lift="bytes: 496\ncalls: {12288}\n",
            recovery="type: u32\nglobal: gValue\n",
            source="void Game_Task(void) { gValue.field = callee(); return; }\n",
        )

        self.assertEqual(report["status"], "exact")
        self.assertTrue(
            all(item["status"] == "exact" for item in report["dimensions"])
        )

    def test_source_metadata_is_reported_as_applied_not_machine_exact(self):
        semantic = {
            "control_flow": [],
            "calls": [],
            "globals": [],
            "access_types": ["u8"],
            "casts": 1,
            "aggregate_copies": 0,
            "declaration_order": [],
            "nominal_fields": ["GameWorld.fadeAlpha"],
            "source_structure": [],
        }
        metadata = {
            "provenance": {
                "url": "https://example.invalid/repo",
                "commit": "1" * 40,
                "license": "MIT",
                "path": "src/game_world.hpp",
            }
        }
        entry = corpus_smoke.parse_manifest(
            self.manifest_output(
                expected_hash="a" * 64, semantic=semantic, metadata=metadata
            )
        )[0]
        report = corpus_smoke._semantic_report(
            entry,
            entry.functions[0],
            resolved="space: ram\noffset: 0x250190\n",
            lift="bytes: 496\ncalls: {}\n",
            recovery="type: u8\n",
            source=(
                "typedef struct GameWorld { uint8_t fadeAlpha; } GameWorld;\n"
                "void Game_Task(GameWorld * this_) "
                "{ this_->fadeAlpha = (uint8_t)1; return; }\n"
            ),
        )
        self.assertEqual(report["status"], "exact")
        applied = {
            item["dimension"]: item
            for item in report["dimensions"]
            if item["status"] == "applied"
        }
        self.assertEqual(
            set(applied), {"recovered_accesses_types", "casts", "nominal_fields"}
        )
        self.assertEqual(
            applied["nominal_fields"]["observed_evidence"]["metadata"],
            metadata["provenance"],
        )

    def test_source_body_uses_address_name_when_source_symbol_is_unavailable(self):
        source = (
            "#include <stdint.h>\n"
            "uint32_t sub_800034e0(uint32_t arg0) "
            "{ callee(); return arg0; }\n"
        )
        self.assertEqual(
            corpus_smoke._source_structure(source, "TRK_memset"),
            (["return"], ["call", "return"]),
        )
        self.assertEqual(
            corpus_smoke._source_declarations(source, "TRK_memset"),
            [],
        )
        self.assertEqual(corpus_smoke._source_globals(source, "TRK_memset"), [])

    def test_source_declaration_order_ignores_materialized_call_results(self):
        source = (
            "uint32_t f(void) {\n"
            "uint32_t first = 1;\n"
            "uint32_t call_800034f4 = callee();\n"
            "uint32_t second = call_800034f4;\n"
            "return second;\n"
            "}\n"
        )
        self.assertEqual(
            corpus_smoke._source_declaration_order(source, "f"),
            ["first", "second"],
        )
        self.assertEqual(
            corpus_smoke._source_declarations(source, "f"),
            ["first", "call_800034f4", "second"],
        )

    def test_source_structure_ignores_only_unlabelled_terminal_void_return(self):
        plain = "void f(void) { value = 0; return; }"
        labelled = "void f(void) { if (value) goto loc_10; loc_10: return; }"
        self.assertEqual(corpus_smoke._source_structure(plain, "f"), ([], []))
        self.assertEqual(
            corpus_smoke._source_structure(labelled, "f"),
            (["if", "goto", "return"], ["if", "goto", "return"]),
        )

    def test_semantic_regression_names_function_and_dimension(self):
        data = b"real image"
        digest = hashlib.sha256(data).hexdigest()
        semantic = {
            "control_flow": ["return"],
            "calls": ["callee@0x3000"],
            "globals": ["gValue"],
            "access_types": ["u32"],
            "casts": 0,
            "aggregate_copies": 0,
            "declaration_order": [],
            "nominal_fields": ["gValue.field"],
            "source_structure": ["call", "return"],
        }
        calls = []

        def fake_runner(command, args):
            calls.append(list(args))
            if args[0] == "corpus":
                return self.manifest_output(
                    expected_hash=digest,
                    semantic=semantic,
                    target="ps1",
                    base="0x8000f800",
                ), ""
            if args[0] == "resolve":
                return envelope("resolve", "space: ram\noffset: 0x250190\n"), ""
            if args[0] == "decompile-native":
                return envelope("decompile-native", "void Game_Task(void) { return; }\n"), ""
            if args[0] == "lift":
                return envelope("lift", "bytes: 496\ncalls: {}\n"), ""
            if args[0] == "recover-types":
                return envelope("recover-types", "type: u32\nglobal: gValue\n"), ""
            if args[0] == "reconstruct-source":
                return envelope(
                    "reconstruct-source",
                    "void Game_Task(void) { gValue.field = callee(); return; }\n",
                ), ""
            raise AssertionError(args)

        with tempfile.TemporaryDirectory() as directory:
            image_dir = Path(directory)
            (image_dir / "test.elf").write_bytes(data)
            report = corpus_smoke.run_smoke(
                image_dir,
                ids=("ps2-test",),
                command=("ventris",),
                command_runner=fake_runner,
            )

        function = report["entries"][0]["functions"][0]
        self.assertEqual(function["status"], "fail")
        self.assertIn("calls", function["error"])
        call_dimension = next(
            item
            for item in function["semantic"]["dimensions"]
            if item["dimension"] == "calls"
        )
        self.assertEqual(call_dimension["status"], "diverged")
        self.assertEqual(call_dimension["expected"], ["0x3000"])
        self.assertEqual(
            call_dimension["expected_evidence"]["commit"], "1" * 40
        )
        self.assertEqual(
            call_dimension["observed_evidence"]["commands"],
            ["lift"],
        )
        self.assertEqual(call_dimension["observed"], [])
        lift_call = next(call for call in calls if call[0] == "lift")
        self.assertEqual(lift_call[lift_call.index("--base") + 1], "0x8000f800")

    def test_valid_lift_without_calls_line_observes_an_empty_call_set(self):
        size, calls = corpus_smoke._lift_summary(
            "architecture: Mips32\n"
            "entry: 0x124058\n"
            "instructions: 10\n"
            "bytes: 40\n"
            "edges: {(1, 2)}\n"
        )
        self.assertEqual(size, 40)
        self.assertEqual(calls, [])

    def test_call_observation_is_not_derived_from_expected_symbol(self):
        digest = "a" * 64
        semantic = {
            "control_flow": ["return"],
            "calls": ["callee@0x3000"],
            "globals": [],
            "access_types": [],
            "casts": 0,
            "aggregate_copies": 0,
            "declaration_order": [],
            "nominal_fields": [],
            "source_structure": ["return"],
        }
        entry = corpus_smoke.parse_manifest(
            self.manifest_output(expected_hash=digest, semantic=semantic)
        )[0]
        report = corpus_smoke._semantic_report(
            entry,
            entry.functions[0],
            resolved="space: ram\noffset: 0x250190\n",
            lift="bytes: 496\ncalls: {16384}\n",
            recovery="memory_accesses: 0\n",
            source="void Game_Task(void) { return; }\n",
        )
        call_dimension = next(
            item for item in report["dimensions"] if item["dimension"] == "calls"
        )
        self.assertEqual(call_dimension["status"], "diverged")
        self.assertEqual(call_dimension["expected"], ["0x3000"])
        self.assertEqual(call_dimension["observed"], ["0x4000"])

    def test_missing_call_facts_are_unavailable_not_an_empty_exact_set(self):
        digest = "a" * 64
        semantic = {
            "control_flow": [],
            "calls": [],
            "globals": [],
            "access_types": [],
            "casts": 0,
            "aggregate_copies": 0,
            "declaration_order": [],
            "nominal_fields": [],
            "source_structure": [],
        }
        entry = corpus_smoke.parse_manifest(
            self.manifest_output(expected_hash=digest, semantic=semantic)
        )[0]
        report = corpus_smoke._semantic_report(
            entry,
            entry.functions[0],
            resolved="space: ram\noffset: 0x250190\n",
            lift="bytes: 496\n",
            recovery="memory_accesses: 0\n",
            source="void Game_Task(void) {}\n",
        )
        call_dimension = next(
            item for item in report["dimensions"] if item["dimension"] == "calls"
        )
        self.assertEqual(call_dimension["status"], "unavailable")
        self.assertIsNone(call_dimension["observed"])
        self.assertIsNone(call_dimension["observed_evidence"])

    def test_unsupported_analysis_is_explicit_not_diverged(self):
        data = b"real image"
        digest = hashlib.sha256(data).hexdigest()
        semantic = {
            "control_flow": [],
            "calls": [],
            "globals": [],
            "access_types": [],
            "casts": 0,
            "aggregate_copies": 0,
            "declaration_order": [],
            "nominal_fields": [],
            "source_structure": [],
        }

        def fake_runner(command, args):
            if args[0] == "corpus":
                return self.manifest_output(expected_hash=digest, semantic=semantic), ""
            if args[0] == "resolve":
                return envelope("resolve", "space: ram\noffset: 0x250190\n"), ""
            if args[0] in {
                "decompile-native",
                "lift",
                "recover-types",
                "reconstruct-source",
            }:
                raise corpus_smoke.SmokeError("unsupported Mips32 opcode 0x0")
            raise AssertionError(args)

        with tempfile.TemporaryDirectory() as directory:
            image_dir = Path(directory)
            (image_dir / "test.elf").write_bytes(data)
            report = corpus_smoke.run_smoke(
                image_dir,
                ids=("ps2-test",),
                command=("ventris",),
                command_runner=fake_runner,
            )

        function = report["entries"][0]["functions"][0]
        self.assertEqual(function["semantic"]["status"], "unsupported")
        self.assertTrue(
            all(
                item["status"] == "unsupported"
                for item in function["semantic"]["dimensions"]
            )
        )
        self.assertIn("unsupported Mips32 opcode", function["error"])

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
        self.assertIn("0x250190", calls[1])
        self.assertIn("0x250190", calls[2])
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
