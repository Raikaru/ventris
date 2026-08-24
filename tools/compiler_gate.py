"""Compile reconstructed C and compare normalized disassembly.

The gate consumes an entry-level toolchain profile from Ventris's corpus
manifest.  Tool commands are argv templates: placeholders are expanded
without a shell, and the configured disassembler dialect controls strict
parsing before target-provided mnemonic aliases are applied.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Iterable, Mapping, Sequence

from .corpus_smoke import (
    ManifestEntry,
    ManifestCommand,
    ManifestFunction,
    ManifestToolchain,
    MnemonicAlias,
    SmokeError,
    _envelope,
    parse_manifest,
    function_address,
)

_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_-]*)\}")
_ADDRESS = re.compile(r"^\s*(?:0x)?[0-9A-Fa-f]+:\s*(.*)$")
_SYMBOL = re.compile(r"^\s*(?:0x)?[0-9A-Fa-f]+\s+<[^>]+>:\s*$")
_RAW_WORD = re.compile(r"^(?:[0-9A-Fa-f]{2}|[0-9A-Fa-f]{4}|[0-9A-Fa-f]{8}|[0-9A-Fa-f]{16})$")
_MNEMONIC = re.compile(r"^[A-Za-z_.][A-Za-z0-9_.]*$")
_LIFT_INSTRUCTION = re.compile(
    r"^\s*(?:0x)?[0-9A-Fa-f]+:\s+\d+\s+([0-9A-Fa-f]+)\s+flow=\S+"
)
_ALLOWED_PLACEHOLDERS = {
    "source",
    "object",
    "image",
    "input",
    "start",
    "stop",
    "bytes",
    "binary",
}


def _run(command: Sequence[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    """Run one argv command without invoking a shell."""

    if not command:
        raise SmokeError("cannot execute an empty command")
    try:
        return subprocess.run(command, input=input_text, text=True, capture_output=True)
    except OSError as error:
        raise SmokeError(f"cannot execute {command[0]}: {error}") from error


def _ventris(command: Sequence[str], args: Sequence[str]) -> str:
    completed = _run([*command, *args])
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise SmokeError(f"ventris {' '.join(args[:1])} failed: {detail}")
    return _envelope(completed.stdout, args[0] if args else "ventris")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_disassembly_header(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    if _SYMBOL.fullmatch(line):
        return True
    if re.fullmatch(r".+:\s+file format\s+\S+", stripped, re.IGNORECASE):
        return True
    if re.fullmatch(r"Disassembly of section\s+.+:", stripped, re.IGNORECASE):
        return True
    if re.fullmatch(r"Contents of section\s+.+:", stripped, re.IGNORECASE):
        return True
    return False


def _parse_instruction_lines(disassembly: str, dialect: str) -> list[str]:
    """Parse instruction lines shared by the strict GNU and LLVM dialects."""

    if not isinstance(disassembly, str) or not disassembly.strip():
        raise SmokeError(f"{dialect} disassembly output is empty")
    mnemonics: list[str] = []
    for line_number, line in enumerate(disassembly.splitlines(), 1):
        if _is_disassembly_header(line):
            continue
        address_match = _ADDRESS.match(line)
        if address_match is None:
            raise SmokeError(
                f"{dialect} disassembly has unparsed output on line {line_number}: {line!r}"
            )
        fields = address_match.group(1).split()
        while fields and _RAW_WORD.fullmatch(fields[0]):
            fields.pop(0)
        if not fields or not _MNEMONIC.fullmatch(fields[0]):
            raise SmokeError(
                f"{dialect} disassembly has an unparsed instruction on line "
                f"{line_number}: {line!r}"
            )
        mnemonics.append(fields[0].lower())
    if not mnemonics:
        raise SmokeError(f"{dialect} disassembly contains no instructions")
    return mnemonics


def _parse_gnu_disassembly(disassembly: str) -> list[str]:
    """Parse GNU objdump output, rejecting every non-header non-instruction."""

    return _parse_instruction_lines(disassembly, "gnu")


def _parse_llvm_disassembly(disassembly: str) -> list[str]:
    """Parse LLVM objdump output, rejecting every non-header non-instruction."""

    return _parse_instruction_lines(disassembly, "llvm")


def parse_disassembly(disassembly: str, dialect: str) -> list[str]:
    """Return raw mnemonics from a known GNU or LLVM disassembly dialect."""

    normalized = dialect.lower() if isinstance(dialect, str) else dialect
    if normalized == "gnu":
        return _parse_gnu_disassembly(disassembly)
    if normalized == "llvm":
        return _parse_llvm_disassembly(disassembly)
    raise SmokeError(f"unknown disassembly dialect {dialect!r}")


def _alias_items(
    aliases: Mapping[str, str] | Iterable[MnemonicAlias] | Iterable[tuple[str, str]],
) -> dict[str, str]:
    if isinstance(aliases, Mapping):
        items = aliases.items()
    else:
        items = (
            (
                item.from_mnemonic if isinstance(item, MnemonicAlias) else item[0],
                item.to_mnemonic if isinstance(item, MnemonicAlias) else item[1],
            )
            for item in aliases
        )
    normalized: dict[str, str] = {}
    for source, destination in items:
        source = str(source).lower()
        destination = str(destination).lower()
        previous = normalized.get(source)
        if previous is not None and previous != destination:
            raise SmokeError(f"conflicting mnemonic aliases for {source!r}")
        normalized[source] = destination
    return normalized


def normalize_mnemonics(
    mnemonics: Iterable[str],
    aliases: Mapping[str, str] | Iterable[MnemonicAlias] | Iterable[tuple[str, str]] = (),
) -> list[str]:
    """Apply only manifest-provided target mnemonic aliases."""

    mapping = _alias_items(aliases)
    normalized: list[str] = []
    for mnemonic in mnemonics:
        current = mnemonic.lower()
        seen: set[str] = set()
        while current in mapping:
            if current in seen:
                raise SmokeError(f"cyclic mnemonic alias involving {current!r}")
            seen.add(current)
            current = mapping[current]
        normalized.append(current)
    return normalized


def _mnemonics(
    disassembly: str,
    dialect: str = "gnu",
    aliases: Mapping[str, str] | Iterable[MnemonicAlias] | Iterable[tuple[str, str]] = (),
) -> list[str]:
    """Compatibility wrapper for strict parsing followed by normalization."""

    # Older callers passed an alias mapping as the second positional argument.
    if not isinstance(dialect, str):
        aliases = dialect  # type: ignore[assignment]
        dialect = "gnu"
    return normalize_mnemonics(parse_disassembly(disassembly, dialect), aliases)


def _lcs_ratio(left: Sequence[str], right: Sequence[str]) -> float:
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    previous = [0] * (len(right) + 1)
    for left_item in left:
        current = [0]
        for index, right_item in enumerate(right, 1):
            current.append(
                previous[index - 1] + 1
                if left_item == right_item
                else max(previous[index], current[-1])
            )
        previous = current
    return (2.0 * previous[-1]) / (len(left) + len(right))


def _entry(entries: Sequence[ManifestEntry], entry_id: str) -> ManifestEntry:
    for entry in entries:
        if entry.id == entry_id:
            return entry
    raise SmokeError(f"unknown corpus id {entry_id!r}")


def _ratio_floor(function: ManifestFunction, requested: float | None) -> float:
    baseline = function.compiler_baseline or {}
    stored = baseline.get("minimum_mnemonic_lcs_ratio", 0.0)
    if isinstance(stored, bool) or not isinstance(stored, (int, float)):
        raise SmokeError(f"{function.name}: invalid compiler ratio baseline")
    floor = float(stored)
    if not 0.0 <= floor <= 1.0:
        raise SmokeError(f"{function.name}: compiler ratio baseline must be between 0 and 1")
    return max(floor, requested or 0.0)


def _placeholder_names(args: Sequence[str]) -> set[str]:
    return {name for arg in args for name in _PLACEHOLDER.findall(arg)}


def expand_command_args(
    args: Sequence[str], values: Mapping[str, object | None], *, field: str
) -> list[str]:
    """Expand a command template into argv, never invoking shell parsing."""

    expanded: list[str] = []
    for argument in args:
        if not isinstance(argument, str):
            raise SmokeError(f"{field}.args must contain strings")
        names = _PLACEHOLDER.findall(argument)
        for name in names:
            if name not in _ALLOWED_PLACEHOLDERS:
                raise SmokeError(f"{field}: unknown placeholder {{{name}}}")
            value = values.get(name)
            if value is None:
                raise SmokeError(f"{field}: missing placeholder {{{name}}}")
            argument = argument.replace("{" + name + "}", os.fspath(value))
        expanded.append(argument)
    return expanded


def _require_placeholders(args: Sequence[str], required: set[str], field: str) -> None:
    present = _placeholder_names(args)
    missing = sorted(required - present)
    if missing:
        joined = ", ".join("{" + name + "}" for name in missing)
        raise SmokeError(f"{field}: missing required placeholder(s): {joined}")


def _address_value(address: str) -> int:
    try:
        return int(address.rsplit("::", 1)[-1], 0)
    except ValueError as error:
        raise SmokeError(f"invalid function address {address!r}") from error


def _disassembler_args(
    toolchain: ManifestToolchain,
    *,
    input_path: Path,
    image_path: Path,
    start: int,
    stop: int,
    role: str,
    bytes_path: Path | None = None,
    program_override: str | None = None,
) -> list[str]:
    template = toolchain.disassembler.args
    names = _placeholder_names(template)
    if "input" not in names:
        # ``{bytes}`` was accepted by the first lifted-raw profile draft.  It
        # remains a narrow compatibility alias and cannot replace {input} for
        # image or candidate invocations.
        if not (role == "retail" and toolchain.retail_input == "lifted-raw" and "bytes" in names):
            raise SmokeError("disassembler: missing required placeholder {input}")
    if "bytes" in names and (role != "retail" or toolchain.retail_input != "lifted-raw"):
        raise SmokeError("disassembler: {bytes} is only valid for lifted-raw retail input")
    values: dict[str, object | None] = {
        "input": input_path,
        "image": image_path,
        "object": input_path,
        "start": str(start),
        "stop": str(stop),
        "bytes": bytes_path,
    }
    command = expand_command_args(template, values, field="disassembler")
    return [program_override or toolchain.disassembler.program, *command]


def _extract_lifted_bytes(
    ventris: Sequence[str],
    image: Path,
    address: str,
    function: ManifestFunction,
    target: str,
) -> bytes:
    result = _ventris(
        ventris,
        [
            "lift",
            os.fspath(image),
            address,
            "--target",
            target,
            "--limit",
            str(function.size),
            "--json",
        ],
    )
    declared_match = re.search(r"(?m)^bytes:\s*(\d+)\s*$", result)
    declared = int(declared_match.group(1)) if declared_match else None
    chunks: list[bytes] = []
    for line in result.splitlines():
        match = _LIFT_INSTRUCTION.match(line)
        if match is None:
            continue
        encoded = match.group(1)
        if len(encoded) % 2:
            raise SmokeError("lifted-raw extraction returned an odd-length byte string")
        try:
            chunks.append(bytes.fromhex(encoded))
        except ValueError as error:
            raise SmokeError("lifted-raw extraction returned invalid instruction bytes") from error
    data = b"".join(chunks)
    if not data:
        raise SmokeError("lifted-raw extraction returned no instruction bytes")
    if declared is None:
        raise SmokeError("lifted-raw extraction omitted the bytes summary")
    if len(data) != declared:
        raise SmokeError(
            f"lifted-raw extraction byte count mismatch (declared {declared}, got {len(data)})"
        )
    return data


def run_gate(
    *,
    image_dir: Path,
    entry_id: str,
    ventris: Sequence[str],
    compiler: str | None = None,
    objdump: str | None = None,
    functions: Sequence[str] = (),
    minimum_ratio: float | None = None,
    require_exact: bool = False,
) -> dict[str, object]:
    ventris = [*ventris]
    if not ventris or ventris[-1] != "__internal":
        ventris.append("__internal")
    corpus = _run([*ventris, "corpus", "--json"])
    if corpus.returncode != 0:
        detail = corpus.stderr.strip() or corpus.stdout.strip()
        raise SmokeError(f"ventris corpus failed: {detail}")
    manifest = parse_manifest(corpus.stdout)
    entry = _entry(manifest, entry_id)
    toolchain = entry.toolchain
    if toolchain is None:
        raise SmokeError(f"{entry.id}: compiler gate requires an entry-level toolchain")
    for function in entry.functions:
        baseline = function.compiler_baseline or {}
        baseline_target = baseline.get("target")
        if baseline_target is not None and baseline_target != entry.target:
            raise SmokeError(
                f"{entry.id}/{function.name}: compiler baseline target {baseline_target!r} "
                f"does not match entry target {entry.target!r}"
            )

    image = (image_dir / entry.binary_name).resolve()
    if not image.is_file():
        raise SmokeError(f"missing corpus image: {image}")
    actual_hash = _sha256(image)
    if entry.binary_sha256 is not None and actual_hash.lower() != entry.binary_sha256.lower():
        raise SmokeError(f"{entry.id}: SHA-256 mismatch")

    selected = [
        function
        for function in entry.functions
        if function.name in functions
        if functions
    ] if functions else [
        function for function in entry.functions if function.compiler_baseline is not None
    ]
    if not selected:
        raise SmokeError("no compiler-gate functions selected")
    known_names = {function.name for function in entry.functions}
    unknown = sorted(set(functions) - known_names)
    if unknown:
        raise SmokeError("unknown or unselected functions: " + ", ".join(unknown))

    _require_placeholders(toolchain.compiler.args, {"source", "object"}, "compiler")
    results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="ventris-compiler-gate-") as directory:
        work = Path(directory)
        metadata_args: list[str] = []
        if entry.metadata is not None:
            metadata_path = work / "metadata.json"
            metadata_path.write_text(json.dumps(entry.metadata, sort_keys=True), encoding="utf-8")
            metadata_args = ["--metadata", os.fspath(metadata_path)]

        for index, function in enumerate(selected):
            address = function_address(entry, function)
            try:
                source = _ventris(
                    ventris,
                    [
                        "reconstruct-source",
                        os.fspath(image),
                        address,
                        "--target",
                        entry.target,
                        "--limit",
                        str(function.size),
                        *metadata_args,
                        "--json",
                    ],
                )
                if not source.strip():
                    raise SmokeError("reconstruct-source returned empty C output")
            except SmokeError as error:
                results.append(
                    {
                        "function": function.name,
                        "address": function.address,
                        "size": function.size,
                        "compile_status": "source-failed",
                        "compiler_diagnostics": [str(error)],
                        "status": "compile-failed",
                        "pass": False,
                    }
                )
                continue

            source_path = work / f"candidate-{index}.c"
            object_path = work / f"candidate-{index}.o"
            source_path.write_text(source, encoding="utf-8")
            compile_args = expand_command_args(
                toolchain.compiler.args,
                {"source": source_path, "object": object_path},
                field="compiler",
            )
            compile_command = [compiler or toolchain.compiler.program, *compile_args]
            compiled = _run(compile_command)
            item: dict[str, object] = {
                "function": function.name,
                "address": function.address,
                "size": function.size,
                "compiler": compile_command[0],
                "toolchain": toolchain.id,
                "compile_command": compile_command,
                "compile_status": "success" if compiled.returncode == 0 else "failed",
                "compiler_diagnostics": [
                    line for line in compiled.stderr.splitlines() if line.strip()
                ],
            }
            if compiled.returncode != 0:
                item.update({"status": "compile-failed", "pass": False})
                results.append(item)
                continue

            try:
                candidate_start = 0
                candidate_stop = object_path.stat().st_size
                candidate_command = _disassembler_args(
                    toolchain,
                    input_path=object_path,
                    image_path=image,
                    start=candidate_start,
                    stop=candidate_stop,
                    role="candidate",
                    program_override=objdump,
                )
                candidate_dump = _run(candidate_command)
                if candidate_dump.returncode != 0:
                    raise SmokeError(
                        candidate_dump.stderr.strip()
                        or candidate_dump.stdout.strip()
                        or "candidate disassembly failed"
                    )
                candidate = normalize_mnemonics(
                    parse_disassembly(candidate_dump.stdout, toolchain.disassembly_format),
                    toolchain.mnemonic_aliases,
                )

                bytes_path: Path | None = None
                if toolchain.retail_input == "lifted-raw":
                    bytes_path = work / f"retail-{index}.bin"
                    bytes_path.write_bytes(
                        _extract_lifted_bytes(ventris, image, address, function, entry.target)
                    )
                    retail_input = bytes_path
                    retail_stop = bytes_path.stat().st_size
                elif toolchain.retail_input == "image":
                    retail_input = image
                    retail_stop = _address_value(function.address) + function.size
                else:  # parse_manifest currently rejects this; retain fail-closed behavior.
                    raise SmokeError(f"unknown retail input {toolchain.retail_input!r}")
                retail_start = _address_value(function.address)
                retail_command = _disassembler_args(
                    toolchain,
                    input_path=retail_input,
                    image_path=image,
                    start=retail_start,
                    stop=retail_stop,
                    role="retail",
                    bytes_path=bytes_path,
                    program_override=objdump,
                )
                retail_dump = _run(retail_command)
                if retail_dump.returncode != 0:
                    raise SmokeError(
                        retail_dump.stderr.strip()
                        or retail_dump.stdout.strip()
                        or "retail disassembly failed"
                    )
                retail = normalize_mnemonics(
                    parse_disassembly(retail_dump.stdout, toolchain.disassembly_format),
                    toolchain.mnemonic_aliases,
                )
            except (OSError, SmokeError) as error:
                item.update({"status": "disassembly-failed", "pass": False, "detail": str(error)})
                results.append(item)
                continue

            ratio_floor = _ratio_floor(function, minimum_ratio)
            ratio = _lcs_ratio(candidate, retail)
            exact = candidate == retail
            calls = normalize_mnemonics(toolchain.call_mnemonics, toolchain.mnemonic_aliases)
            call_set = set(calls)
            call_counts = {
                "candidate": sum(mnemonic in call_set for mnemonic in candidate),
                "retail": sum(mnemonic in call_set for mnemonic in retail),
            }
            passed = exact if require_exact else ratio >= ratio_floor
            item.update(
                {
                    "status": "exact" if exact else "normalized-similar" if passed else "normalized-diverged",
                    "pass": passed,
                    "exact": exact,
                    "mnemonic_lcs_ratio": round(ratio, 6),
                    "minimum_ratio": ratio_floor,
                    "instruction_counts": {"candidate": len(candidate), "retail": len(retail)},
                    "call_counts": call_counts,
                    "candidate_mnemonics": candidate,
                    "retail_mnemonics": retail,
                    "disassembler_commands": [candidate_command, retail_command],
                }
            )
            results.append(item)

    return {
        "ok": all(bool(item.get("pass")) for item in results),
        "id": entry.id,
        "target": entry.target,
        "toolchain": toolchain.id,
        "image": os.fspath(image),
        "sha256": actual_hash,
        "require_exact": require_exact,
        "requested_minimum_ratio": minimum_ratio,
        "functions": results,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-dir", type=Path)
    parser.add_argument("--id")
    parser.add_argument("--ventris")
    parser.add_argument("--fixture-dir", type=Path)
    parser.add_argument("--compiler", help="override only the configured compiler program")
    parser.add_argument("--objdump", help="override only the manifest disassembler program")
    parser.add_argument("--objcopy", help="override only the configured fixture objcopy program")
    parser.add_argument("--function", action="append", dest="functions", default=[])
    parser.add_argument("--minimum-ratio", type=float)
    parser.add_argument("--require-exact", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser
class FixtureGateError(SmokeError):
    """A fixture sidecar or exact-byte comparison failed (exit status 1)."""


class FixtureUnavailableError(SmokeError):
    """The configured fixture compiler or objcopy cannot be executed (status 3)."""


def _fixture_hash(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdefABCDEF" for character in value)
    ):
        raise FixtureGateError(f"{field} must be a SHA-256 digest")
    return value.lower()


def _fixture_command(value: object, field: str) -> ManifestCommand:
    if not isinstance(value, dict):
        raise FixtureGateError(f"{field} must be an object")
    program = value.get("program")
    args = value.get("args")
    if not isinstance(program, str) or not program:
        raise FixtureGateError(f"{field}.program must be a non-empty string")
    if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        raise FixtureGateError(f"{field}.args must be an array of strings")
    return ManifestCommand(program=program, args=tuple(args))


def _fixture_bytes(path: Path) -> bytes:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise FixtureGateError(f"cannot read expected bytes {path}: {error}") from error
    if not text.strip():
        raise FixtureGateError(f"{path.name}: expected byte fixture is empty")
    try:
        data = bytes.fromhex(text)
    except ValueError as error:
        raise FixtureGateError(f"{path.name}: expected byte fixture is not hexadecimal") from error
    if not data:
        raise FixtureGateError(f"{path.name}: expected byte fixture is empty")
    return data

def _fixture_sidecar(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise FixtureGateError(f"{path.name}: invalid sidecar JSON: {error}") from error
    if not isinstance(value, dict):
        raise FixtureGateError(f"{path.name}: sidecar must be an object")
    fixture = value.get("fixture")
    profiles = value.get("target_profiles")
    compiler_version = value.get("compiler_version", value.get("compiler_identity"))
    if not isinstance(fixture, str) or not fixture or Path(fixture).name != fixture:
        raise FixtureGateError(f"{path.name}: fixture must be a simple non-empty name")
    if (
        not isinstance(profiles, list)
        or not profiles
        or not all(isinstance(profile, str) and profile for profile in profiles)
    ):
        raise FixtureGateError(f"{path.name}: target_profiles must be non-empty strings")
    if not isinstance(compiler_version, str) or not compiler_version:
        raise FixtureGateError(f"{path.name}: compiler_version must be a non-empty string")
    normalized = dict(value)
    normalized["compiler_version"] = compiler_version
    if "expected_bytes_sha256" not in normalized and "bytes_sha256" in normalized:
        normalized["expected_bytes_sha256"] = normalized["bytes_sha256"]
    return normalized

def _fixture_expand(
    spec: ManifestCommand,
    required: set[str],
    values: Mapping[str, object | None],
    field: str,
) -> list[str]:
    try:
        _require_placeholders(spec.args, required, field)
        return expand_command_args(spec.args, values, field=field)
    except SmokeError as error:
        raise FixtureGateError(str(error)) from error



def run_fixture_gate(
    fixture_dir: Path,
    *,
    compiler: str | None = None,
    objcopy: str | None = None,
) -> dict[str, object]:
    """Compile authored ABI fixtures and compare their exact extracted bytes."""

    fixture_dir = fixture_dir.resolve()
    if not fixture_dir.is_dir():
        raise FixtureGateError(f"fixture directory does not exist: {fixture_dir}")
    sidecars = sorted(fixture_dir.glob("*.json"))
    if not sidecars:
        raise FixtureGateError(f"fixture directory has no JSON sidecars: {fixture_dir}")

    fixtures: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="ventris-abi-fixtures-") as directory:
        work = Path(directory)
        for sidecar_path in sidecars:
            metadata = _fixture_sidecar(sidecar_path)
            fixture = str(metadata["fixture"])
            source_path = fixture_dir / f"{fixture}.c"
            expected_path = fixture_dir / f"{fixture}.hex"
            if not source_path.is_file():
                raise FixtureGateError(f"{fixture}: missing source fixture {source_path.name}")
            if not expected_path.is_file():
                raise FixtureGateError(f"{fixture}: missing byte fixture {expected_path.name}")
            source_hash = _sha256(source_path)
            expected_source_hash = _fixture_hash(metadata.get("source_sha256"), f"{fixture}.source_sha256")
            if source_hash.lower() != expected_source_hash:
                raise FixtureGateError(
                    f"{fixture}: source SHA-256 mismatch (expected {expected_source_hash}, got {source_hash})"
                )
            expected_bytes = _fixture_bytes(expected_path)
            expected_hash = _fixture_hash(
                metadata.get("expected_bytes_sha256"), f"{fixture}.expected_bytes_sha256"
            )
            parsed_hash = hashlib.sha256(expected_bytes).hexdigest()
            if parsed_hash != expected_hash:
                raise FixtureGateError(
                    f"{fixture}: expected byte SHA-256 mismatch (sidecar {expected_hash}, parsed {parsed_hash})"
                )

            compiler_spec = _fixture_command(metadata.get("compiler"), f"{fixture}.compiler")
            objcopy_spec = _fixture_command(metadata.get("objcopy"), f"{fixture}.objcopy")
            object_path = work / f"{fixture}.o"
            binary_path = work / f"{fixture}.bin"
            compiler_command = [
                compiler or compiler_spec.program,
                *_fixture_expand(
                    compiler_spec,
                    {"source", "object"},
                    {"source": source_path, "object": object_path},
                    f"{fixture}.compiler",
                ),
            ]
            objcopy_command = [
                objcopy or objcopy_spec.program,
                *_fixture_expand(
                    objcopy_spec,
                    {"object", "binary"},
                    {"object": object_path, "binary": binary_path},
                    f"{fixture}.objcopy",
                ),
            ]
            try:
                compiled = _run(compiler_command)
            except SmokeError as error:
                if str(error).startswith("cannot execute "):
                    raise FixtureUnavailableError(str(error)) from error
                raise FixtureGateError(f"{fixture}: compiler failed: {error}") from error
            if compiled.returncode != 0:
                detail = compiled.stderr.strip() or compiled.stdout.strip() or "compiler failed"
                raise FixtureGateError(f"{fixture}: compiler failed: {detail}")
            try:
                extracted = _run(objcopy_command)
            except SmokeError as error:
                if str(error).startswith("cannot execute "):
                    raise FixtureUnavailableError(str(error)) from error
                raise FixtureGateError(f"{fixture}: objcopy failed: {error}") from error
            if extracted.returncode != 0:
                detail = extracted.stderr.strip() or extracted.stdout.strip() or "objcopy failed"
                raise FixtureGateError(f"{fixture}: objcopy failed: {detail}")
            if not binary_path.is_file():
                raise FixtureGateError(f"{fixture}: objcopy did not create {binary_path.name}")
            actual_bytes = binary_path.read_bytes()
            actual_hash = hashlib.sha256(actual_bytes).hexdigest()
            exact = actual_bytes == expected_bytes and actual_hash == expected_hash
            item: dict[str, object] = {
                "fixture": fixture,
                "target_profiles": list(metadata["target_profiles"]),
                "compiler_version": metadata["compiler_version"],
                "source_sha256": source_hash,
                "expected_bytes_sha256": expected_hash,
                "actual_bytes_sha256": actual_hash,
                "exact": exact,
                "compiler_command": compiler_command,
                "objcopy_command": objcopy_command,
                "status": "exact" if exact else "mismatch",
            }
            if not exact:
                item["error"] = f"{fixture}: extracted .text bytes differ from expected fixture"
            fixtures.append(item)

    return {
        "ok": all(bool(item["exact"]) for item in fixtures),
        "fixture_dir": os.fspath(fixture_dir),
        "fixtures": fixtures,
    }

def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.fixture_dir is not None:
        if any(
            value
            for value in (
                args.image_dir,
                args.id,
                args.ventris,
                args.objdump,
                args.functions,
                args.minimum_ratio,
                args.require_exact,
            )
        ):
            _parser().error("--fixture-dir cannot be combined with corpus gate options")
        try:
            report = run_fixture_gate(
                args.fixture_dir,
                compiler=args.compiler,
                objcopy=args.objcopy,
            )
        except FixtureUnavailableError as error:
            if args.json:
                print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
            else:
                print(f"compiler-gate: FAIL: {error}", file=sys.stderr)
            return 3
        except FixtureGateError as error:
            if args.json:
                print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
            else:
                print(f"compiler-gate: FAIL: {error}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            state = "PASS" if report["ok"] else "FAIL"
            print(f"compiler-gate: {state} ({len(report['fixtures'])} fixtures)")
            for item in report["fixtures"]:
                print(f"  {item['status']} {item['fixture']}")
        return 0 if report["ok"] else 1

    if args.image_dir is None or args.id is None or args.ventris is None:
        _parser().error("--image-dir, --id, and --ventris are required without --fixture-dir")
    try:
        report = run_gate(
            image_dir=args.image_dir,
            entry_id=args.id,
            ventris=(args.ventris,),
            compiler=args.compiler,
            objdump=args.objdump,
            functions=args.functions,
            minimum_ratio=args.minimum_ratio,
            require_exact=args.require_exact,
        )
    except SmokeError as error:
        print(f"compiler-gate: FAIL: {error}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        state = "PASS" if report["ok"] else "FAIL"
        print(f"compiler-gate: {state} ({len(report['functions'])} functions)")
        for item in report["functions"]:
            ratio = item.get("mnemonic_lcs_ratio", "n/a")
            print(f"  {item['status']} {item['function']} ratio={ratio}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
