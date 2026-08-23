"""Run the source-backed real-image corpus smoke contract.

The runner deliberately keeps game images outside the repository. It loads the
checked-in corpus manifest through ``ventris corpus --json``, verifies each local
image's SHA-256, resolves every manifest function address, and runs bounded
native decompilation for each selected target.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Callable, Iterable, Sequence


DEFAULT_IDS = (
    "n64-perfect-dark-ntsc-final",
    "gamecube-animal-crossing-gafe01",
    "ps2-street-fighter-iii-anniversary",
)


class SmokeError(RuntimeError):
    """Raised when the corpus manifest or a smoke command is invalid."""


@dataclass(frozen=True)
class ManifestFunction:
    name: str
    address: str
    size: int


@dataclass(frozen=True)
class ManifestEntry:
    id: str
    title: str
    target: str
    binary_name: str
    binary_sha256: str | None
    functions: tuple[ManifestFunction, ...]


CommandRunner = Callable[[Sequence[str], Sequence[str]], tuple[str, str]]


def _parse_int(value: object, field: str) -> int:
    if isinstance(value, bool):
        raise SmokeError(f"{field} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as error:
            raise SmokeError(f"{field} is not an address or integer: {value!r}") from error
    raise SmokeError(f"{field} must be an integer or hexadecimal string")


def _envelope(text: str, command: str) -> str:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise SmokeError(f"{command} returned invalid JSON: {error}") from error
    if not isinstance(value, dict) or value.get("ok") is not True:
        detail = value.get("error", "unknown error") if isinstance(value, dict) else "invalid envelope"
        raise SmokeError(f"{command} failed: {detail}")
    result = value.get("result")
    if not isinstance(result, str):
        raise SmokeError(f"{command} returned no textual result")
    return result


def parse_manifest(text: str) -> tuple[ManifestEntry, ...]:
    """Decode the nested JSON returned by ``ventris corpus --json``."""
    manifest_text = _envelope(text, "corpus")
    try:
        raw_entries = json.loads(manifest_text)
    except json.JSONDecodeError as error:
        raise SmokeError(f"corpus result is invalid JSON: {error}") from error
    if not isinstance(raw_entries, list):
        raise SmokeError("corpus result must be an array")

    entries: list[ManifestEntry] = []
    for raw in raw_entries:
        if not isinstance(raw, dict):
            raise SmokeError("corpus entry must be an object")
        entry_id = raw.get("id")
        title = raw.get("title")
        target = raw.get("target")
        binary_name = raw.get("binary_name")
        expected_hash = raw.get("binary_sha256")
        functions_raw = raw.get("functions")
        if not all(isinstance(value, str) for value in (entry_id, title, target, binary_name)):
            raise SmokeError("corpus entry is missing string identity fields")
        if expected_hash is not None and not isinstance(expected_hash, str):
            raise SmokeError(f"{entry_id}: binary_sha256 must be a string or null")
        if not isinstance(functions_raw, list) or not functions_raw:
            raise SmokeError(f"{entry_id}: corpus entry has no representative function")

        functions: list[ManifestFunction] = []
        for raw_function in functions_raw:
            if not isinstance(raw_function, dict):
                raise SmokeError(f"{entry_id}: function must be an object")
            name = raw_function.get("name")
            address = raw_function.get("address")
            size = raw_function.get("size")
            if not isinstance(name, str) or not isinstance(address, str):
                raise SmokeError(f"{entry_id}: function is missing name/address")
            functions.append(ManifestFunction(name, address, _parse_int(size, f"{entry_id}.function.size")))

        entries.append(
            ManifestEntry(
                id=entry_id,
                title=title,
                target=target,
                binary_name=binary_name,
                binary_sha256=expected_hash,
                functions=tuple(functions),
            )
        )
    return tuple(entries)


def find_ventris(explicit: str | os.PathLike[str] | None = None) -> list[str]:
    """Find a built Ventris executable or fall back to ``cargo run``."""
    if explicit:
        return [os.fspath(explicit)]
    env_binary = os.environ.get("VENTRIS_BIN")
    if env_binary:
        return [env_binary]

    root = Path(__file__).resolve().parents[2]
    executable = "ventris.exe" if os.name == "nt" else "ventris"
    for candidate in (root / "target" / "debug" / executable, root / "target" / "release" / executable):
        if candidate.is_file():
            return [os.fspath(candidate)]

    cargo = shutil.which("cargo")
    if cargo:
        return [cargo, "run", "--quiet", "-p", "ventris-cli", "--"]
    raise SmokeError("Ventris executable not found; build it or pass --ventris")


def run_command(command: Sequence[str], args: Sequence[str]) -> tuple[str, str]:
    completed = subprocess.run(
        [*command, *args],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip() or "command failed"
        raise SmokeError(f"{' '.join(args[:2])}: {detail}")
    return completed.stdout, completed.stderr


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def function_address(entry: ManifestEntry, function: ManifestFunction) -> str:
    address = function.address
    # The PS2 ELF exposes overlapping address spaces; qualify the manifest
    # address so the runner checks the same EE RAM space every time.
    return address if "::" in address or entry.target != "ps2" else f"ram::{address}"


def _hash_status(entry: ManifestEntry, actual: str, require_hashes: bool) -> str:
    expected = entry.binary_sha256
    if expected is None:
        if require_hashes:
            raise SmokeError(f"{entry.id}: manifest has no binary_sha256")
        return "unverified"
    if len(expected) != 64 or any(character not in "0123456789abcdefABCDEF" for character in expected):
        raise SmokeError(f"{entry.id}: manifest binary_sha256 is not a SHA-256 digest")
    if actual.lower() != expected.lower():
        raise SmokeError(f"{entry.id}: SHA-256 mismatch (expected {expected}, got {actual})")
    return "verified"


def smoke_entry(
    entry: ManifestEntry,
    image_dir: Path,
    command: Sequence[str],
    *,
    limit: int,
    require_hashes: bool,
    command_runner: CommandRunner = run_command,
) -> dict[str, object]:
    image = image_dir / entry.binary_name
    if not image.is_file():
        raise SmokeError(f"{entry.id}: image does not exist: {image}")
    actual_hash = sha256_file(image)
    hash_status = _hash_status(entry, actual_hash, require_hashes)
    target_args = ["--target", entry.target, "--json"]
    function_results: list[dict[str, object]] = []
    warnings: list[str] = []

    for function in entry.functions:
        address = function_address(entry, function)
        try:
            resolve_stdout, resolve_stderr = command_runner(
                command,
                ["resolve", os.fspath(image), address, *target_args],
            )
            resolve_result = _envelope(resolve_stdout, "resolve")
            expected_offset = f"offset: {function.address}"
            if expected_offset.lower() not in resolve_result.lower():
                raise SmokeError(
                    f"resolve returned the wrong manifest offset; expected {function.address}"
                )

            decompile_stdout, decompile_stderr = command_runner(
                command,
                [
                    "decompile-native",
                    os.fspath(image),
                    address,
                    *target_args[:2],
                    "--limit",
                    str(limit),
                    "--json",
                ],
            )
            decompile_result = _envelope(decompile_stdout, "decompile-native")
            if not decompile_result.strip():
                raise SmokeError("decompile-native returned empty C output")

            function_warnings = [
                line
                for line in (resolve_stderr + decompile_stderr).splitlines()
                if line.strip()
            ]
            warnings.extend(function_warnings)
            function_results.append(
                {
                    "name": function.name,
                    "address": function.address,
                    "size": function.size,
                    "warnings": function_warnings,
                    "status": "pass",
                }
            )
        except SmokeError as error:
            function_results.append(
                {
                    "name": function.name,
                    "address": function.address,
                    "size": function.size,
                    "warnings": [],
                    "status": "fail",
                    "error": f"{entry.id}/{function.name}: {error}",
                }
            )

    failed = [result for result in function_results if result["status"] != "pass"]
    result: dict[str, object] = {
        "id": entry.id,
        "title": entry.title,
        "target": entry.target,
        "image": os.fspath(image),
        "function": entry.functions[0].name,
        "address": entry.functions[0].address,
        "functions": function_results,
        "function_count": len(function_results),
        "sha256": actual_hash,
        "hash_status": hash_status,
        "warnings": warnings,
        "status": "pass" if not failed else "fail",
    }
    if failed:
        result["error"] = "; ".join(str(item["error"]) for item in failed)
    return result


def run_smoke(
    image_dir: Path,
    *,
    ids: Iterable[str] = DEFAULT_IDS,
    command: Sequence[str] | None = None,
    limit: int = 4096,
    require_hashes: bool = False,
    command_runner: CommandRunner = run_command,
) -> dict[str, object]:
    if limit <= 0:
        raise SmokeError("--limit must be greater than zero")
    image_dir = image_dir.resolve()
    command = list(command or find_ventris())
    manifest_stdout, _ = command_runner(command, ["corpus", "--json"])
    entries = {entry.id: entry for entry in parse_manifest(manifest_stdout)}
    selected_ids = tuple(ids)
    if not selected_ids:
        raise SmokeError("at least one --id is required")

    results: list[dict[str, object]] = []
    for entry_id in selected_ids:
        entry = entries.get(entry_id)
        if entry is None:
            results.append({"id": entry_id, "status": "fail", "error": "unknown corpus id"})
            continue
        try:
            results.append(
                smoke_entry(
                    entry,
                    image_dir,
                    command,
                    limit=limit,
                    require_hashes=require_hashes,
                    command_runner=command_runner,
                )
            )
        except SmokeError as error:
            results.append({"id": entry.id, "title": entry.title, "target": entry.target, "status": "fail", "error": str(error)})

    return {
        "ok": all(result.get("status") == "pass" for result in results),
        "image_dir": os.fspath(image_dir),
        "limit": limit,
        "entries": results,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-dir", required=True, type=Path, help="directory containing manifest-named images")
    parser.add_argument("--ventris", help="Ventris executable; defaults to VENTRIS_BIN or the workspace build")
    parser.add_argument("--id", action="append", dest="ids", help="corpus id to run; repeat for multiple entries")
    parser.add_argument("--limit", type=int, default=4096, help="maximum instructions per native decompilation")
    parser.add_argument("--require-hashes", action="store_true", help="reject manifest entries without pinned SHA-256 hashes")
    parser.add_argument("--json", action="store_true", help="emit a machine-readable report")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = run_smoke(
            args.image_dir,
            ids=args.ids or DEFAULT_IDS,
            command=find_ventris(args.ventris),
            limit=args.limit,
            require_hashes=args.require_hashes,
        )
    except SmokeError as error:
        if args.json:
            print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        else:
            print(f"corpus-smoke: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        status = "PASS" if report["ok"] else "FAIL"
        print(f"corpus-smoke: {status} ({len(report['entries'])} entries)")
        for result in report["entries"]:
            if result["status"] == "pass":
                print(
                    f"  PASS {result['id']} ({result['function_count']} functions) "
                    f"sha256={result['sha256']} ({result['hash_status']})"
                )
            else:
                print(f"  FAIL {result['id']}: {result['error']}")
            for function in result.get("functions", []):
                function_status = function["status"].upper()
                suffix = f": {function['error']}" if function_status == "FAIL" else ""
                print(f"    {function_status} {function['name']} {function['address']}{suffix}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
