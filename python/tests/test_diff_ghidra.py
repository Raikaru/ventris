import argparse
import hashlib
from pathlib import Path
from subprocess import CompletedProcess
import tempfile
import unittest
from unittest.mock import patch

from tools.diff_ghidra import Capsule, run_ghidra, run_native, write_ghidra_fixture


class DiffGhidraTests(unittest.TestCase):
    @staticmethod
    def args(image: Path) -> argparse.Namespace:
        return argparse.Namespace(
            arch="gamecube",
            entry=0x800034E0,
            function="0x800034e0",
            ghidra=None,
            image=image,
            length=0x30,
            limit=4096,
            processor=None,
            raw=False,
            ventris=None,
        )

    def test_gamecube_import_disables_interactive_map_prompt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "support").mkdir()
            (root / "support" / "analyzeHeadless.bat").touch()
            image = root / "fixture.dol"
            image.write_bytes(b"DOL")
            capsule = root / "capsule.txt"
            capsule.write_text("capsule\n", encoding="utf-8")
            with (
                patch("tools.diff_ghidra.find_ghidra", return_value=root),
                patch(
                    "tools.diff_ghidra.subprocess.run",
                    return_value=CompletedProcess([], 0, "", ""),
                ) as run,
            ):
                run_ghidra(self.args(image), capsule)
            command = run.call_args.args[0]
            option = command.index("-loader-autoloadMaps")
            self.assertEqual(command[option : option + 2], ["-loader-autoloadMaps", "false"])

    def test_gamecube_native_comparison_selects_dol_loader(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "fixture.dol"
            image.write_bytes(b"DOL")
            with (
                patch("tools.diff_ghidra.find_ventris", return_value=["ventris"]),
                patch(
                    "tools.diff_ghidra.subprocess.run",
                    return_value=CompletedProcess([], 0, "lifted", ""),
                ) as run,
            ):
                self.assertEqual(run_native(self.args(image), 0x800034E0, 12), "lifted")
            command = run.call_args.args[0]
            option = command.index("--loader")
            self.assertEqual(command[option : option + 2], ["--loader", "dol"])

    def test_fixture_writer_uses_ghidra_capsule_and_pins_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "fixture.dol"
            image.write_bytes(b"complete image")
            capsule_path = root / "capsule.txt"
            capsule_path.write_text(
                "function f\nlanguage PowerPC:BE:32:Gekko_Broadway\n"
                "entry 4096\nlength 1\nbytes aa\n"
                "inst 4096 1 1\n  op 1 register:0:4 const:1:4\n"
                "reg r0 register 0 4\nuserop 0 example\n",
                encoding="utf-8",
            )
            destination = root / "fixture.ghidra-capsule"
            write_ghidra_fixture(
                self.args(image),
                capsule_path,
                Capsule("f", "PowerPC:BE:32:Gekko_Broadway", 4096, 1, b"\xaa", []),
                destination,
            )
            fixture = destination.read_text(encoding="utf-8")
            self.assertIn("# oracle=Ghidra\n", fixture)
            self.assertIn(
                f"# source_image_sha256={hashlib.sha256(b'complete image').hexdigest()}\n",
                fixture,
            )
            function_hash = hashlib.sha256(bytes([0xAA])).hexdigest()
            self.assertIn(
                f"# function_bytes_sha256={function_hash}\n",
                fixture,
            )
            self.assertIn("  op 1 register:0:4 const:1:4\n", fixture)
            self.assertNotIn("reg r0", fixture)
            self.assertNotIn("userop 0", fixture)


if __name__ == "__main__":
    unittest.main()
