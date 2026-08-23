"""Run native smoke checks from an isolated temporary working directory."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def smoke(binary: Path, fixture: Path, semantic_spec: Path, version: str) -> None:
    for path, label in (
        (binary, "native binary"),
        (fixture, "smoke fixture"),
        (semantic_spec, "semantic spec"),
    ):
        if not path.is_file():
            raise ValueError(f"{label} not found: {path}")

    smoke_script = Path(__file__).with_name("native_smoke.py").resolve()
    with tempfile.TemporaryDirectory(prefix="ventris-clean-host-") as directory:
        root = Path(directory)
        isolated_binary = root / binary.name
        isolated_fixture = root / fixture.name
        isolated_semantics = root / semantic_spec.name
        shutil.copy2(binary, isolated_binary)
        shutil.copy2(fixture, isolated_fixture)
        shutil.copy2(semantic_spec, isolated_semantics)

        environment = os.environ.copy()
        environment.pop("VENTRIS_BIN", None)
        environment.pop("PYTHONPATH", None)
        environment["PYTHONNOUSERSITE"] = "1"
        completed = subprocess.run(
            [
                sys.executable,
                "-S",
                str(smoke_script),
                "--binary",
                str(isolated_binary),
                "--fixture",
                str(isolated_fixture),
                "--semantic-spec",
                str(isolated_semantics),
                "--version",
                version,
            ],
            cwd=root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise ValueError(f"isolated native smoke failed: {detail}")
        print(completed.stdout, end="")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--semantic-spec", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args(argv)
    try:
        smoke(
            args.binary.resolve(),
            args.fixture.resolve(),
            args.semantic_spec.resolve(),
            args.version,
        )
    except (OSError, ValueError) as error:
        print(f"clean-host-smoke: FAIL: {error}", file=sys.stderr)
        return 1
    print(f"clean-host-smoke: PASS {args.binary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
