import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import ventris
from ventris import cli


class PythonApiContractTests(unittest.TestCase):
    @staticmethod
    def completed(*, returncode=0, stdout="ok\n", stderr=""):
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    def test_package_exports_only_function_pipeline(self):
        self.assertEqual(
            set(ventris.__all__),
            {"VentrisError", "decompile", "inspect", "lift", "run", "version"},
        )
        self.assertTrue(set(ventris.__all__) <= set(dir(ventris)))

    @patch("ventris.cli.subprocess.run")
    def test_inspect_forwards_image_options(self, run):
        run.return_value = self.completed(stdout="facts\n")
        result = cli.inspect(
            "fixture.bin",
            target="ps2",
            loader="raw",
            base=0x4000,
            slice=2,
            as_json=True,
            binary="ventris.exe",
        )
        self.assertEqual(result, "facts\n")
        self.assertEqual(
            run.call_args.args[0],
            [
                "ventris.exe",
                "inspect",
                "fixture.bin",
                "--target",
                "ps2",
                "--loader",
                "raw",
                "--base",
                "0x4000",
                "--slice",
                "0x2",
                "--json",
            ],
        )

    @patch("ventris.cli.subprocess.run")
    def test_lift_uses_target_without_inventing_architecture(self, run):
        run.return_value = self.completed(stdout="lifted\n")
        cli.lift("fixture.elf", 0x1000, target="ps3-ppu", binary="ventris.exe")
        self.assertEqual(
            run.call_args.args[0],
            [
                "ventris.exe",
                "lift",
                "fixture.elf",
                "0x1000",
                "--limit",
                "4096",
                "--target",
                "ps3-ppu",
            ],
        )

    @patch("ventris.cli.subprocess.run")
    def test_decompile_forwards_analysis_and_metadata_options(self, run):
        run.return_value = self.completed(stdout="#include <stdint.h>\n")
        result = cli.decompile(
            Path("sample.bin"),
            0x1000,
            target="ps2",
            metadata=Path("facts.json"),
            loader="raw",
            base=0x4000,
            limit=16,
            raw=True,
            cache=Path("cache"),
            as_json=True,
            binary="ventris.exe",
        )
        self.assertEqual(result, "#include <stdint.h>\n")
        self.assertEqual(
            run.call_args.args[0],
            [
                "ventris.exe",
                "decompile",
                os.fspath(Path("sample.bin")),
                "0x1000",
                "--target",
                "ps2",
                "--loader",
                "raw",
                "--base",
                "0x4000",
                "--metadata",
                os.fspath(Path("facts.json")),
                "--limit",
                "16",
                "--raw",
                "--cache",
                os.fspath(Path("cache")),
                "--json",
            ],
        )

    def test_lift_requires_architecture_or_target(self):
        with self.assertRaisesRegex(ValueError, "arch or target"):
            cli.lift("fixture.bin", 0x1000)

    def test_decompile_requires_architecture_or_target(self):
        with self.assertRaisesRegex(ValueError, "arch or target"):
            cli.decompile("fixture.bin", 0x1000)

    def test_metadata_requires_target(self):
        with self.assertRaisesRegex(ValueError, "metadata requires target"):
            cli.decompile("fixture.bin", 0x1000, arch="x86_64", metadata="facts.json")

    @patch("ventris.cli.subprocess.run")
    def test_run_raises_structured_error(self, run):
        run.return_value = self.completed(returncode=2, stderr="bad input\n")
        with self.assertRaises(cli.VentrisError) as raised:
            cli.run(["inspect", "missing"], binary="ventris.exe")
        self.assertEqual(raised.exception.returncode, 2)
        self.assertEqual(str(raised.exception), "bad input")

    @patch("ventris.cli.subprocess.run")
    def test_run_returns_stdout_verbatim(self, run):
        run.return_value = self.completed(stdout="exact output\n")
        self.assertEqual(
            cli.run(["version"], binary="ventris.exe"),
            "exact output\n",
        )


if __name__ == "__main__":
    unittest.main()
