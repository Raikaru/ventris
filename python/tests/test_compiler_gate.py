import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from subprocess import CompletedProcess
from unittest.mock import patch

from tools.compiler_gate import (
    FixtureGateError,
    FixtureUnavailableError,
    _lcs_ratio,
    _mnemonics,
    _ratio_floor,
    expand_command_args,
    normalize_mnemonics,
    parse_disassembly,
    run_fixture_gate,
)
from tools.corpus_smoke import ManifestFunction, MnemonicAlias, SmokeError


class CompilerGateTests(unittest.TestCase):
    def test_objdump_parser_normalizes_control_flow_aliases(self):
        disassembly = """
00000000 <candidate>:
       0:       addiu   $sp, $sp, -16
       4:       move    $2, $4
       8:       beqz    $2, 0x10
       c:       jr      $ra
"""
        self.assertEqual(
            _mnemonics(
                disassembly,
                aliases={"move": "addu", "beqz": "beq"},
            ),
            ["addiu", "addu", "beq", "jr"],
        )

    def test_lcs_ratio_rewards_ordered_overlap(self):
        self.assertEqual(_lcs_ratio([], []), 1.0)
        self.assertEqual(_lcs_ratio(["jr"], []), 0.0)
        self.assertEqual(_lcs_ratio(["lw", "addu", "jr"], ["lw", "jr"]), 0.8)

    def test_gnu_parser_returns_exact_mnemonics_and_rejects_unparsed_output(self):
        disassembly = (
            "candidate.o:     file format elf32-littlemips\n"
            "Disassembly of section .text:\n"
            "00000000 <candidate>:\n"
            "       0: 27bdfff0       addiu   $sp, $sp, -16\n"
            "       4: 00801025       move    $2, $4\n"
        )
        self.assertEqual(parse_disassembly(disassembly, "gnu"), ["addiu", "move"])
        with self.assertRaisesRegex(SmokeError, "unparsed output"):
            parse_disassembly(disassembly + "not disassembly\n", "gnu")

    def test_llvm_parser_handles_byte_columns_exactly(self):
        disassembly = (
            "candidate.o:\tfile format elf32-littlemips\n"
            "00000000 <candidate>:\n"
            "       0: 27 bd ff f0              addiu $sp, $sp, -16\n"
            "       4: 00 80 10 25              move  $2, $4\n"
        )
        self.assertEqual(parse_disassembly(disassembly, "llvm"), ["addiu", "move"])

    def test_manifest_aliases_are_applied_separately_from_parsing(self):
        raw = ["move", "bl", "jr"]
        aliases = (MnemonicAlias("move", "or"), MnemonicAlias("bl", "call"))
        self.assertEqual(raw, ["move", "bl", "jr"])
        self.assertEqual(normalize_mnemonics(raw, aliases), ["or", "call", "jr"])

    def test_unknown_dialect_and_empty_disassembly_fail_closed(self):
        with self.assertRaisesRegex(SmokeError, "unknown disassembly dialect"):
            parse_disassembly("0: jr $ra\n", "wat")
        with self.assertRaisesRegex(SmokeError, "empty"):
            parse_disassembly("", "gnu")

    def test_command_placeholders_expand_as_literal_argv(self):
        expanded = expand_command_args(
            ["--source={source}", "--object", "{object}", "--flag", "a b"],
            {"source": "fixtures/source file.c", "object": "build/candidate.o"},
            field="compiler",
        )
        self.assertEqual(
            expanded,
            [
                "--source=fixtures/source file.c",
                "--object",
                "build/candidate.o",
                "--flag",
                "a b",
            ],
        )
        with self.assertRaisesRegex(SmokeError, "missing placeholder"):
            expand_command_args(["{input}"], {}, field="disassembler")

    def test_function_baseline_is_the_regression_floor(self):
        function = ManifestFunction(
            name="f",
            address="0x1000",
            size=4,
            semantic=None,
            source_path="f.c",
            compiler_baseline={"minimum_mnemonic_lcs_ratio": 0.5},
        )
        self.assertEqual(_ratio_floor(function, None), 0.5)
        self.assertEqual(_ratio_floor(function, 0.4), 0.5)
        self.assertEqual(_ratio_floor(function, 0.7), 0.7)

    def test_invalid_function_baseline_is_rejected(self):
        function = ManifestFunction(
            name="f",
            address="0x1000",
            size=4,
            semantic=None,
            source_path="f.c",
            compiler_baseline={"minimum_mnemonic_lcs_ratio": 2},
        )
        with self.assertRaises(SmokeError):
            _ratio_floor(function, None)
    def test_fixture_gate_constructs_argv_and_reports_exact_bytes(self):
        source = b"void fixture(void) { return; }\n"
        expected = b"\x01\x02\x03\x04"
        source_hash = hashlib.sha256(source).hexdigest()
        expected_hash = hashlib.sha256(expected).hexdigest()
        sidecar = {
            "fixture": "fixture",
            "target_profiles": ["gba"],
            "compiler_version": "fake compiler",
            "source_sha256": source_hash,
            "expected_bytes_sha256": expected_hash,
            "compiler": {
                "program": "compiler-from-sidecar",
                "args": ["--source={source}", "--object", "{object}"],
            },
            "objcopy": {
                "program": "objcopy-from-sidecar",
                "args": ["{object}", "{binary}"],
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            fixture_dir = Path(directory)
            (fixture_dir / "fixture.c").write_bytes(source)
            (fixture_dir / "fixture.hex").write_text(expected.hex(), encoding="ascii")
            (fixture_dir / "fixture.json").write_text(json.dumps(sidecar), encoding="utf-8")
            commands = []

            def fake_run(command, **kwargs):
                commands.append(list(command))
                if command[0] == "fake-compiler":
                    object_path = Path(command[-1])
                    object_path.write_bytes(b"object")
                elif command[0] == "fake-objcopy":
                    Path(command[-1]).write_bytes(expected)
                return CompletedProcess(command, 0, "", "")

            with patch("tools.compiler_gate._run", side_effect=fake_run):
                report = run_fixture_gate(
                    fixture_dir,
                    compiler="fake-compiler",
                    objcopy="fake-objcopy",
                )

        self.assertTrue(report["ok"])
        item = report["fixtures"][0]
        self.assertTrue(item["exact"])
        self.assertEqual(item["actual_bytes_sha256"], expected_hash)
        self.assertEqual(commands[0][0], "fake-compiler")
        self.assertEqual(
            commands[0][1],
            f"--source={fixture_dir / 'fixture.c'}",
        )
        self.assertEqual(commands[0][2], "--object")
        self.assertEqual(Path(commands[0][3]).name, "fixture.o")
        self.assertEqual(commands[1][0], "fake-objcopy")
        self.assertEqual(Path(commands[1][1]).name, "fixture.o")
        self.assertEqual(Path(commands[1][2]).name, "fixture.bin")

    def test_fixture_gate_reports_exact_byte_mismatch(self):
        source = b"void fixture(void) { return; }\n"
        expected = b"\x01\x02"
        source_hash = hashlib.sha256(source).hexdigest()
        sidecar = {
            "fixture": "fixture",
            "target_profiles": ["ps1"],
            "compiler_version": "fake",
            "source_sha256": source_hash,
            "expected_bytes_sha256": hashlib.sha256(expected).hexdigest(),
            "compiler": {"program": "cc", "args": ["{source}", "{object}"]},
            "objcopy": {"program": "objcopy", "args": ["{object}", "{binary}"]},
        }
        with tempfile.TemporaryDirectory() as directory:
            fixture_dir = Path(directory)
            (fixture_dir / "fixture.c").write_bytes(source)
            (fixture_dir / "fixture.hex").write_text(expected.hex(), encoding="ascii")
            (fixture_dir / "fixture.json").write_text(json.dumps(sidecar), encoding="utf-8")

            def fake_run(command, **kwargs):
                if command[0] == "cc":
                    Path(command[-1]).write_bytes(b"object")
                else:
                    Path(command[-1]).write_bytes(b"\xff")
                return CompletedProcess(command, 0, "", "")

            with patch("tools.compiler_gate._run", side_effect=fake_run):
                report = run_fixture_gate(fixture_dir)

        self.assertFalse(report["ok"])
        self.assertFalse(report["fixtures"][0]["exact"])
        self.assertNotEqual(
            report["fixtures"][0]["actual_bytes_sha256"],
            report["fixtures"][0]["expected_bytes_sha256"],
        )

    def test_fixture_gate_rejects_missing_placeholder_and_unavailable_tool(self):
        source = b"void fixture(void) { return; }\n"
        expected = b"\x01"
        sidecar = {
            "fixture": "fixture",
            "target_profiles": ["gamecube"],
            "compiler_version": "fake",
            "source_sha256": hashlib.sha256(source).hexdigest(),
            "expected_bytes_sha256": hashlib.sha256(expected).hexdigest(),
            "compiler": {"program": "cc", "args": ["{source}", "{object}"]},
            "objcopy": {"program": "objcopy", "args": ["{object}"]},
        }
        with tempfile.TemporaryDirectory() as directory:
            fixture_dir = Path(directory)
            (fixture_dir / "fixture.c").write_bytes(source)
            (fixture_dir / "fixture.hex").write_text(expected.hex(), encoding="ascii")
            (fixture_dir / "fixture.json").write_text(json.dumps(sidecar), encoding="utf-8")
            with self.assertRaisesRegex(FixtureGateError, "missing required placeholder"):
                run_fixture_gate(fixture_dir)
            sidecar["objcopy"]["args"] = ["{object}", "{binary}"]
            (fixture_dir / "fixture.json").write_text(json.dumps(sidecar), encoding="utf-8")
            with patch(
                "tools.compiler_gate._run",
                side_effect=SmokeError("cannot execute cc: unavailable"),
            ):
                with self.assertRaises(FixtureUnavailableError):
                    run_fixture_gate(fixture_dir)




if __name__ == "__main__":
    unittest.main()
