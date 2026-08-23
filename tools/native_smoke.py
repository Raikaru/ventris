"""Run the required native Ventris release smoke checks."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys


def run(binary: Path, args: list[str]) -> str:
    completed = subprocess.run(
        [str(binary), *args],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise ValueError(
            f"native smoke command failed ({completed.returncode}): "
            f"{' '.join(args)}{': ' + detail if detail else ''}"
        )
    return completed.stdout


def run_json(binary: Path, args: list[str]) -> dict[str, object]:
    output = run(binary, [*args, "--json"])
    try:
        result = json.loads(output)
    except json.JSONDecodeError as error:
        raise ValueError(
            "native smoke command returned invalid JSON: "
            f"{' '.join(args)}"
        ) from error
    if result.get("ok") is not True:
        raise ValueError(f"native smoke command returned an error: {' '.join(args)}")
    return result


def compare_semantics(body: str, spec: dict[str, object]) -> None:
    return_type = spec.get("return_type")
    operator = spec.get("operator")
    operands = spec.get("operands")
    if not isinstance(return_type, str) or not isinstance(operator, str):
        raise ValueError("semantic spec needs string return_type and operator")
    if not isinstance(operands, list) or not all(isinstance(item, str) for item in operands):
        raise ValueError("semantic spec needs a string operands list")

    return_line = next(
        (line.strip() for line in body.splitlines() if line.strip().startswith("return ")),
        "",
    )
    if return_type not in body or not return_line:
        raise ValueError("real-image decompile has no expected typed return")
    if operator not in return_line:
        raise ValueError(
            f"real-image decompile return does not contain operator {operator!r}: {return_line}"
        )
    missing = [operand for operand in operands if operand not in return_line]
    if missing:
        raise ValueError(
            f"real-image decompile return is missing operands {missing!r}: {return_line}"
        )

def smoke(
    binary: Path,
    fixture: Path,
    version: str,
    address: str,
    architecture: str,
    semantic_spec: Path | None = None,
) -> None:
    if not binary.is_file():
        raise ValueError(f"native binary not found: {binary}")
    if not fixture.is_file():
        raise ValueError(f"smoke fixture not found: {fixture}")
    if semantic_spec is not None and not semantic_spec.is_file():
        raise ValueError(f"semantic spec not found: {semantic_spec}")

    expected_semantics = None
    if semantic_spec is not None:
        try:
            expected_semantics = json.loads(semantic_spec.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"invalid semantic spec: {semantic_spec}") from error
        if not isinstance(expected_semantics, dict):
            raise ValueError("semantic spec root must be an object")
        if str(expected_semantics.get("address", "")).lower() != address.lower():
            raise ValueError("semantic spec address does not match --address")
        if expected_semantics.get("architecture") != architecture:
            raise ValueError("semantic spec architecture does not match --arch")

    version_output = run(binary, ["version"]).strip()
    expected_version = f"ventris {version}"
    if version_output != expected_version:
        raise ValueError(
            f"native binary reported {version_output!r}, "
            f"expected {expected_version!r}"
        )

    inspect = run_json(binary, ["inspect", str(fixture)])
    if "PE32+" not in str(inspect.get("result", "")):
        raise ValueError("inspect smoke did not identify the checked-in PE fixture")


    lift = run_json(binary, ["lift", str(fixture), address, "--arch", architecture])
    if "instructions:" not in str(lift.get("result", "")):
        raise ValueError("lift smoke did not return an instruction listing")

    decompile = run_json(
        binary,
        ["decompile", str(fixture), address, "--arch", architecture],
    )
    body = str(decompile.get("result", ""))
    if "#include" not in body or "return" not in body:
        raise ValueError("decompile smoke did not return native C")
    if expected_semantics is not None:
        compare_semantics(body, expected_semantics)

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--address", default="0x140001450")
    parser.add_argument("--arch", default="x86_64")
    parser.add_argument("--semantic-spec", type=Path)
    args = parser.parse_args(argv)
    try:
        smoke(
            args.binary.resolve(),
            args.fixture.resolve(),
            args.version,
            args.address,
            args.arch,
            args.semantic_spec.resolve() if args.semantic_spec else None,
        )
    except (OSError, ValueError) as error:
        print(f"native-smoke: FAIL: {error}", file=sys.stderr)
        return 1
    print(f"native-smoke: PASS {args.binary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
