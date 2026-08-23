import json
import os
import sys
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


    @patch("ventris.cli.subprocess.run")
    def test_corpus_forwards_json_flag(self, run):
        run.return_value = self.completed(stdout="corpus\n")

        self.assertEqual(cli.corpus(as_json=True, binary="ventris.exe"), "corpus\n")
        self.assertEqual(run.call_args.args[0], ["ventris.exe", "corpus", "--json"])

    def test_package_exports_are_bound(self):
        self.assertTrue(set(ventris.__all__) <= set(dir(ventris)))

    @patch("ventris.cli.subprocess.run")
    def test_diff_forwards_revision_paths_and_region(self, run):
        run.return_value = self.completed(stdout="changed=1\n")

        result = cli.diff(
            "before.bin",
            Path("after.bin"),
            target="ps2",
            loader="raw",
            base=0x4000,
            region=".text",
            as_json=True,
            binary="ventris.exe",
        )

        self.assertEqual(result, "changed=1\n")
        self.assertEqual(
            run.call_args.args[0],
            [
                "ventris.exe",
                "diff",
                "before.bin",
                os.fspath(Path("after.bin")),
                "--target",
                "ps2",
                "--loader",
                "raw",
                "--base",
                "0x4000",
                "--region",
                ".text",
                "--json",
            ],
        )

    @patch("ventris.cli.subprocess.run")
    def test_ingest_runtime_forwards_project_and_trace(self, run):
        run.return_value = self.completed(stdout="events: 4\n")

        result = cli.ingest_runtime(
            Path("sample.vproj"),
            "trace.jsonl",
            as_json=True,
            binary="ventris.exe",
        )

        self.assertEqual(result, "events: 4\n")
        self.assertEqual(
            run.call_args.args[0],
            [
                "ventris.exe",
                "project",
                "runtime",
                os.fspath(Path("sample.vproj")),
                "trace.jsonl",
                "--json",
            ],
        )

    @patch("ventris.cli.subprocess.run")
    def test_link_assets_forwards_project_and_manifest(self, run):
        run.return_value = self.completed(stdout="links: 2\n")

        result = cli.link_assets(
            "sample.vproj",
            Path("assets.json"),
            as_json=True,
            binary="ventris.exe",
        )

        self.assertEqual(result, "links: 2\n")
        self.assertEqual(
            run.call_args.args[0],
            [
                "ventris.exe",
                "project",
                "assets",
                "sample.vproj",
                os.fspath(Path("assets.json")),
                "--json",
            ],
        )

    @patch("ventris.cli.subprocess.run")
    def test_reconstruct_source_forwards_game_options(self, run):
        run.return_value = self.completed(stdout="#include <stdint.h>\n")

        result = cli.reconstruct_source(
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
                "reconstruct-source",
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

    @patch("ventris.cli.subprocess.run")
    def test_discover_forwards_architecture_and_image_options(self, run):
        run.return_value = self.completed(stdout="functions: 1\n")

        result = cli.discover(
            "fixture.bin",
            arch="x86_64",
            loader="raw",
            base=0x4000,
            limit=32,
            as_json=True,
            binary="ventris.exe",
        )

        self.assertEqual(result, "functions: 1\n")
        self.assertEqual(
            run.call_args.args[0],
            [
                "ventris.exe",
                "discover",
                "fixture.bin",
                "--arch",
                "x86_64",
                "--loader",
                "raw",
                "--base",
                "0x4000",
                "--limit",
                "32",
                "--json",
            ],
        )

    @patch("ventris.cli.subprocess.run")
    def test_image_helpers_forward_loader_and_base(self, run):
        run.return_value = self.completed(stdout="facts\n")

        result = cli.inspect(
            "fixture.bin",
            loader="raw",
            base=0x4000,
            binary="ventris.exe",
        )

        self.assertEqual(result, "facts\n")
        self.assertEqual(
            run.call_args.args[0],
            ["ventris.exe", "inspect", "fixture.bin", "--loader", "raw", "--base", "0x4000"],
        )

    @patch("ventris.cli.subprocess.run")
    def test_image_helpers_forward_universal_slice(self, run):
        run.return_value = self.completed(stdout="facts\n")

        cli.inspect("fixture.macho", slice=2, binary="ventris.exe")

        self.assertEqual(
            run.call_args.args[0],
            ["ventris.exe", "inspect", "fixture.macho", "--slice", "0x2"],
        )

    @patch("ventris.cli.subprocess.run")
    def test_target_profile_forwards_without_inventing_an_architecture(self, run):
        run.return_value = self.completed(stdout="lifted\n")

        cli.lift(
            "fixture.elf",
            0x1000,
            target="ps3-ppu",
            binary="ventris.exe",
        )

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
    def test_recover_types_forwards_target_metadata_and_flags(self, run):
        run.return_value = self.completed(stdout="recovered\n")

        result = cli.recover_types(
            "fixture.elf",
            0x1000,
            target="ps2",
            metadata=Path("types.json"),
            loader="elf",
            base=0x100000,
            slice=2,
            limit=64,
            raw=True,
            as_json=True,
            binary="ventris.exe",
        )

        self.assertEqual(result, "recovered\n")
        self.assertEqual(
            run.call_args.args[0],
            [
                "ventris.exe",
                "recover-types",
                "fixture.elf",
                "0x1000",
                "--target",
                "ps2",
                "--loader",
                "elf",
                "--base",
                "0x100000",
                "--slice",
                "0x2",
                "--metadata",
                "types.json",
                "--limit",
                "64",
                "--raw",
                "--json",
            ],
        )


    @patch("ventris.cli.subprocess.run")
    def test_project_function_decompile_forwards_record_selector(self, run):
        run.return_value = self.completed(stdout="native\n")

        result = cli.decompile_project_function(
            "project.vproj",
            "sub_1000",
            arch="x86_64",
            limit=32,
            cache="cache",
            as_json=True,
            binary="ventris.exe",
        )

        self.assertEqual(result, "native\n")
        self.assertEqual(
            run.call_args.args[0],
            [
                "ventris.exe",
                "decompile-native",
                "--project",
                "project.vproj",
                "--function",
                "sub_1000",
                "--arch",
                "x86_64",
                "--limit",
                "32",
                "--cache",
                "cache",
                "--json",
            ],
        )

    @patch("ventris.cli.subprocess.run")
    def test_project_references_forwards_direction_and_json(self, run):
        run.return_value = self.completed(stdout="references\n")

        result = cli.project_references(
            Path("project.vproj"),
            0x1006,
            incoming=True,
            as_json=True,
            binary="ventris.exe",
        )

        self.assertEqual(result, "references\n")
        self.assertEqual(
            run.call_args.args[0],
            [
                "ventris.exe",
                "project",
                "refs",
                os.fspath(Path("project.vproj")),
                "0x1006",
                "--incoming",
                "--json",
            ],
        )

    @patch("ventris.cli.subprocess.run")
    def test_native_helpers_render_paths_addresses_and_json_flags(self, run):
        run.return_value = self.completed(stdout="native\n")

        result = cli.decompile_native(
            Path("fixture.exe"),
            0x140001450,
            arch="x86_64",
            limit=32,
            raw=True,
            cache=Path("cache"),
            as_json=True,
            binary=Path("ventris.exe"),
            cwd=Path("workspace"),
        )

        self.assertEqual(result, "native\n")
        command = run.call_args.args[0]
        self.assertEqual(
            command,
            [
                os.fspath(Path("ventris.exe")),
                "decompile-native",
                os.fspath(Path("fixture.exe")),
                "0x140001450",
                "--arch",
                "x86_64",
                "--limit",
                "32",
                "--raw",
                "--cache",
                os.fspath(Path("cache")),
                "--json",
            ],
        )
        self.assertEqual(run.call_args.kwargs["cwd"], os.fspath(Path("workspace")))

    @patch("ventris.cli.subprocess.run")
    def test_batch_iterable_is_json_lines_and_preserves_paths(self, run):
        run.return_value = self.completed(stdout='{"ok":true}\n')

        result = cli.batch(
            [{"command": "inspect", "image": Path("fixture.exe")}],
            cache=Path("cache"),
            output=Path("results.jsonl"),
            binary="ventris.exe",
        )

        self.assertEqual(result, '{"ok":true}\n')
        command = run.call_args.args[0]
        self.assertEqual(
            command,
            [
                "ventris.exe",
                "batch",
                "--input",
                "-",
                "--cache",
                "cache",
                "--output",
                "results.jsonl",
            ],
        )
        self.assertEqual(
            run.call_args.kwargs["input"],
            json.dumps({"command": "inspect", "image": "fixture.exe"}, separators=(",", ":")) + "\n",
        )

    @patch("ventris.cli.subprocess.run")
    def test_failed_process_raises_structured_error(self, run):
        run.return_value = self.completed(returncode=2, stdout="", stderr="bad input\n")

        with self.assertRaises(cli.VentrisError) as raised:
            cli.inspect("missing.bin", binary=sys.executable)

        self.assertEqual(raised.exception.returncode, 2)
        self.assertEqual(raised.exception.stderr, "bad input\n")
        self.assertEqual(str(raised.exception), "bad input")


if __name__ == "__main__":
    unittest.main()
