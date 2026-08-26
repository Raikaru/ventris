"""Run the source-backed real-image corpus smoke contract.

The runner deliberately keeps game images outside the repository. It loads the
checked-in corpus manifest through Ventris's internal developer namespace,
verifies each local image's SHA-256, resolves every manifest function address,
and runs bounded native decompilation for each selected target.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import sys
from typing import Callable, Iterable, Sequence


DEFAULT_IDS = (
    "n64-perfect-dark-ntsc-final",
    "gamecube-animal-crossing-gafe01",
    "ps2-dungeon-game",
)


class SmokeError(RuntimeError):
    """Raised when the corpus manifest or a smoke command is invalid."""


@dataclass(frozen=True)
class ManifestCommand:
    """One argv-based tool command from an entry-level toolchain profile."""

    program: str
    args: tuple[str, ...]


@dataclass(frozen=True)
class MnemonicAlias:
    """A target-provided disassembler mnemonic alias."""

    from_mnemonic: str
    to_mnemonic: str


@dataclass(frozen=True)
class ManifestToolchain:
    """Typed compiler/disassembler facts supplied by the corpus manifest."""

    id: str
    compiler: ManifestCommand
    disassembler: ManifestCommand
    disassembly_format: str
    mnemonic_aliases: tuple[MnemonicAlias, ...]
    call_mnemonics: tuple[str, ...]
    retail_input: str
    # These optional fields are accepted for forward-compatible manifests and
    # are checked against the containing entry when present.
    target: str | None = None
    profile: str | None = None

@dataclass(frozen=True)
class ManifestFunction:
    name: str
    address: str
    size: int
    semantic: dict[str, object] | None
    source_path: str
    compiler_baseline: dict[str, object] | None = None


@dataclass(frozen=True)
class ManifestEntry:
    id: str
    title: str
    target: str
    source_url: str
    source_commit: str
    source_license: str
    binary_name: str
    binary_sha256: str | None
    binary_sha1: str | None
    base: int | None
    address_space: str | None
    functions: tuple[ManifestFunction, ...]
    metadata: dict[str, object] | None = None
    toolchain: ManifestToolchain | None = None


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


def _parse_string_list(value: object, field: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SmokeError(f"{field} must be an array of strings")
    if not allow_empty and not value:
        raise SmokeError(f"{field} must not be empty")
    if any(not item for item in value):
        raise SmokeError(f"{field} must not contain empty strings")
    return tuple(value)


def _parse_tool_command(value: object, field: str) -> ManifestCommand:
    if not isinstance(value, dict):
        raise SmokeError(f"{field} must be an object")
    program = value.get("program")
    if not isinstance(program, str) or not program:
        raise SmokeError(f"{field}.program must be a non-empty string")
    args = _parse_string_list(value.get("args"), f"{field}.args")
    return ManifestCommand(program=program, args=args)


def _parse_toolchain(value: object, entry_id: str, target: str) -> ManifestToolchain:
    if not isinstance(value, dict):
        raise SmokeError(f"{entry_id}: toolchain must be an object or null")
    toolchain_id = value.get("id")
    if not isinstance(toolchain_id, str) or not toolchain_id:
        raise SmokeError(f"{entry_id}: toolchain.id must be a non-empty string")
    disassembly_format = value.get("disassembly_format")
    if not isinstance(disassembly_format, str):
        raise SmokeError(f"{entry_id}: toolchain.disassembly_format must be a string")
    disassembly_format = disassembly_format.lower()
    if disassembly_format not in {"gnu", "llvm"}:
        raise SmokeError(
            f"{entry_id}: unknown disassembly dialect {disassembly_format!r}"
        )
    retail_input = value.get("retail_input")
    if not isinstance(retail_input, str):
        raise SmokeError(f"{entry_id}: toolchain.retail_input must be a string")
    retail_input = retail_input.lower()
    if retail_input not in {"image", "lifted-raw"}:
        raise SmokeError(f"{entry_id}: unknown retail input {retail_input!r}")

    raw_aliases = value.get("mnemonic_aliases")
    if not isinstance(raw_aliases, list):
        raise SmokeError(f"{entry_id}: toolchain.mnemonic_aliases must be an array")
    aliases: list[MnemonicAlias] = []
    seen_aliases: dict[str, str] = {}
    for index, raw_alias in enumerate(raw_aliases):
        if not isinstance(raw_alias, dict):
            raise SmokeError(
                f"{entry_id}: toolchain.mnemonic_aliases[{index}] must be an object"
            )
        from_mnemonic = raw_alias.get("from")
        to_mnemonic = raw_alias.get("to")
        if (
            not isinstance(from_mnemonic, str)
            or not from_mnemonic
            or not isinstance(to_mnemonic, str)
            or not to_mnemonic
        ):
            raise SmokeError(
                f"{entry_id}: toolchain.mnemonic_aliases[{index}] needs non-empty from/to"
            )
        source = from_mnemonic.lower()
        destination = to_mnemonic.lower()
        previous = seen_aliases.get(source)
        if previous is not None and previous != destination:
            raise SmokeError(
                f"{entry_id}: conflicting mnemonic aliases for {from_mnemonic!r}"
            )
        if previous is None:
            aliases.append(MnemonicAlias(source, destination))
            seen_aliases[source] = destination
    call_mnemonics = tuple(
        item.lower()
        for item in _parse_string_list(
            value.get("call_mnemonics"),
            f"{entry_id}.toolchain.call_mnemonics",
        )
    )
    target_hint = value.get("target")
    profile_hint = value.get("profile")
    for field, hint in (("target", target_hint), ("profile", profile_hint)):
        if hint is not None and (
            not isinstance(hint, str) or not hint or hint != target
        ):
            raise SmokeError(
                f"{entry_id}: toolchain {field} does not match target {target!r}"
            )
    return ManifestToolchain(
        id=toolchain_id,
        compiler=_parse_tool_command(value.get("compiler"), f"{entry_id}.toolchain.compiler"),
        disassembler=_parse_tool_command(
            value.get("disassembler"), f"{entry_id}.toolchain.disassembler"
        ),
        disassembly_format=disassembly_format,
        mnemonic_aliases=tuple(aliases),
        call_mnemonics=call_mnemonics,
        retail_input=retail_input,
        target=target_hint,
        profile=profile_hint,
    )


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
        expected_sha1 = raw.get("binary_sha1")
        raw_base = raw.get("base")
        source_url = raw.get("source_url")
        source_commit = raw.get("source_commit")
        source_license = raw.get("source_license")
        metadata = raw.get("metadata")
        toolchain_raw = raw.get("toolchain")
        functions_raw = raw.get("functions")
        if not all(
            isinstance(value, str)
            for value in (
                entry_id,
                title,
                target,
                binary_name,
                source_url,
                source_commit,
                source_license,
            )
        ):
            raise SmokeError("corpus entry is missing string identity/provenance fields")
        if expected_hash is not None and not isinstance(expected_hash, str):
            raise SmokeError(f"{entry_id}: binary_sha256 must be a string or null")
        if expected_sha1 is not None and not isinstance(expected_sha1, str):
            raise SmokeError(f"{entry_id}: binary_sha1 must be a string or null")
        if raw_base is not None:
            raw_base = _parse_int(raw_base, f"{entry_id}.base")
        address_space = raw.get("address_space")
        if address_space is not None and (
            not isinstance(address_space, str) or not address_space
        ):
            raise SmokeError(f"{entry_id}: address_space must be a non-empty string or null")
        if metadata is not None and not isinstance(metadata, dict):
            raise SmokeError(f"{entry_id}: metadata must be an object or null")
        toolchain = (
            None
            if toolchain_raw is None
            else _parse_toolchain(toolchain_raw, entry_id, target)
        )
        if not isinstance(functions_raw, list) or not functions_raw:
            raise SmokeError(f"{entry_id}: corpus entry has no representative function")
        functions: list[ManifestFunction] = []
        for raw_function in functions_raw:
            if not isinstance(raw_function, dict):
                raise SmokeError(f"{entry_id}: function must be an object")
            name = raw_function.get("name")
            address = raw_function.get("address")
            size = raw_function.get("size")
            semantic = raw_function.get("semantic")
            compiler_baseline = raw_function.get("compiler_baseline")
            source_path = raw_function.get("source_path")
            if (
                not isinstance(name, str)
                or not isinstance(address, str)
                or not isinstance(source_path, str)
            ):
                raise SmokeError(f"{entry_id}: function is missing name/address/source_path")
            if semantic is not None and not isinstance(semantic, dict):
                raise SmokeError(
                    f"{entry_id}/{name}: semantic baseline must be an object or null"
                )
            if compiler_baseline is not None and not isinstance(compiler_baseline, dict):
                raise SmokeError(
                    f"{entry_id}/{name}: compiler baseline must be an object or null"
                )
            if (
                compiler_baseline is not None
                and compiler_baseline.get("target") is not None
                and compiler_baseline.get("target") != target
            ):
                raise SmokeError(
                    f"{entry_id}/{name}: compiler baseline target does not match "
                    f"entry target {target!r}"
                )
            functions.append(
                ManifestFunction(
                    name=name,
                    address=address,
                    size=_parse_int(size, f"{entry_id}.function.size"),
                    semantic=semantic,
                    compiler_baseline=compiler_baseline,
                    source_path=source_path,
                )
            )

        entries.append(
            ManifestEntry(
                id=entry_id,
                title=title,
                target=target,
                source_url=source_url,
                source_commit=source_commit,
                source_license=source_license,
                binary_name=binary_name,
                binary_sha256=expected_hash,
                binary_sha1=expected_sha1,
                base=raw_base,
                functions=tuple(functions),
                metadata=metadata,
                address_space=address_space,
                toolchain=toolchain,
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




def sha1_file(path: Path) -> str:
    digest = hashlib.sha1()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def function_address(entry: ManifestEntry, function: ManifestFunction) -> str:
    """Qualify a manifest offset when the corpus pins an image space."""

    if "::" in function.address or entry.address_space is None:
        return function.address
    return f"{entry.address_space}::{function.address}"


def _hash_status(
    entry: ManifestEntry,
    actual_sha256: str,
    actual_sha1: str,
    require_hashes: bool,
) -> str:
    expected_sha256 = entry.binary_sha256
    expected_sha1 = entry.binary_sha1
    if expected_sha256 is None and expected_sha1 is None:
        if require_hashes:
            raise SmokeError(f"{entry.id}: manifest has no pinned image hash")
        return "unverified"
    if expected_sha256 is not None:
        if len(expected_sha256) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in expected_sha256):
            raise SmokeError(f"{entry.id}: manifest binary_sha256 is not a SHA-256 digest")
        if actual_sha256.lower() != expected_sha256.lower():
            raise SmokeError(
                f"{entry.id}: SHA-256 mismatch (expected {expected_sha256}, got {actual_sha256})"
            )
    if expected_sha1 is not None:
        if len(expected_sha1) != 40 or any(ch not in "0123456789abcdefABCDEF" for ch in expected_sha1):
            raise SmokeError(f"{entry.id}: manifest binary_sha1 is not a SHA-1 digest")
        if actual_sha1.lower() != expected_sha1.lower():
            raise SmokeError(
                f"{entry.id}: SHA-1 mismatch (expected {expected_sha1}, got {actual_sha1})"
            )
    return "verified"

SEMANTIC_DIMENSIONS = (
    "boundary",
    "control_flow",
    "calls",
    "globals",
    "recovered_accesses_types",
    "casts",
    "aggregate_copies",
    "declaration_order",
    "nominal_fields",
    "reconstructed_source_structure",
)


def _strings(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SmokeError(f"{field} must be an array of strings")
    return list(value)


def _source_signature(source: str, function_name: str) -> re.Match[str] | None:
    signatures = [
        candidate
        for candidate in re.finditer(
            r"\b([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*\{", source
        )
        if candidate.group(1) not in {"if", "for", "while", "switch"}
    ]
    return next(
        (candidate for candidate in signatures if candidate.group(1) == function_name),
        signatures[0] if signatures else None,
    )


def _source_body(source: str, function_name: str) -> str | None:
    signature = _source_signature(source, function_name)
    if signature is None:
        return None
    start = source.find("{", signature.start())
    depth = 0
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start + 1 : index]
    return None


def _source_structure(source: str, function_name: str) -> tuple[list[str], list[str]]:
    body = _source_body(source, function_name) or ""
    controls: list[tuple[int, str]] = []
    structure: list[tuple[int, str]] = []
    keywords = {"if", "for", "while", "switch", "goto", "return", "sizeof"}
    for match in re.finditer(r"\b(if|for|while|switch|goto|return)\b", body):
        token = match.group(1)
        if token == "return" and body[match.end() :].strip() == ";":
            before = body[: match.start()].rstrip()
            if not re.search(r"\bloc_[0-9a-fA-F]+:\s*$", before):
                continue
        controls.append((match.start(), token))
        structure.append((match.start(), token))
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", body):
        if match.group(1) not in keywords:
            structure.append((match.start(), "call"))
    controls.sort()
    structure.sort()
    return [token for _, token in controls], [token for _, token in structure]


def _source_declarations(source: str, function_name: str) -> list[str]:
    body = _source_body(source, function_name) or ""
    declarations: list[str] = []
    pattern = re.compile(
        r"^\s*(?:const\s+)?(?:u?int(?:8|16|32|64)_t|uintptr_t|float|double|bool|"
        r"struct\s+\w+|\w+)\s+\**\s*([A-Za-z_]\w*)\s*(?:=[^;]*)?;\s*$"
    )
    for line in body.splitlines():
        if re.match(r"\s*(?:return|if|for|while|switch)\b", line):
            continue
        match = pattern.match(line)
        if match and match.group(1) not in {"return", "if", "for", "while", "switch"}:
            declarations.append(match.group(1))
    return declarations


def _memory_snapshots(body: str) -> set[str]:
    """Locals holding a memory value across a write to the same location.

    This is the construct the filter below describes, recognised by what it does
    rather than by what it is called. The address-ordered renderer names these
    `mem_<address>_<n>`, which the name pattern catches; the graph emitter names
    them like any other temporary, and so does Ghidra, which calls the one in
    `allocEnemyEntity` `uVar1`. Naming is therefore not the distinguishing
    feature, and matching on it exempted one emitter's artifacts and not the
    other's.
    """
    member = r"[A-Za-z_]\w*(?:->|\.)[A-Za-z_]\w+"
    snapshot_of: dict[str, str] = {}
    for line in body.splitlines():
        match = re.match(
            rf"\s*(?:[\w ]+\s)?([A-Za-z_]\w*)\s*=\s*\(?({member})\)?\s*;\s*$", line
        )
        if match:
            snapshot_of.setdefault(match.group(1), match.group(2))
    written = {
        match.group(1)
        for match in (
            re.match(rf"\s*\(?({member})\)?\s*=[^=]", line)
            for line in body.splitlines()
        )
        if match
    }
    return {name for name, read in snapshot_of.items() if read in written}


def _source_declaration_order(source: str, function_name: str) -> list[str]:
    # Materialized call results and memory snapshots preserve evaluation order
    # but are renderer implementation details, not recovered source declaration
    # evidence. A snapshot exists because a store would otherwise change what a
    # later read observes; the original source names no such variable.
    snapshots = _memory_snapshots(_source_body(source, function_name) or "")
    return [
        name
        for name in _source_declarations(source, function_name)
        if re.fullmatch(r"(?:call|mem)_[0-9a-f]+(?:_\d+)?", name) is None
        and name not in snapshots
    ]


def _source_cast_count(source: str, function_name: str) -> int:
    body = _source_body(source, function_name) or ""
    return len(
        re.findall(
            r"\(\s*(?:const\s+)?(?:u?int(?:8|16|32|64)_t|uintptr_t|float|double|bool|"
            r"struct\s+\w+|\w+\s*\*)\s*\)",
            body,
        )
    )


def _source_nominal_fields(source: str, function_name: str) -> list[str]:
    body = _source_body(source, function_name) or ""
    parameter_types = {
        name: c_type
        for c_type, name in re.findall(r"\b([A-Z]\w*)\s*\*\s*([A-Za-z_]\w*)", source)
    }
    fields = {
        parameter_types.get(match.group(1), match.group(1))
        + re.sub(r"->", ".", match.group(2))
        for match in re.finditer(
            r"\b([A-Za-z_]\w*)((?:(?:->|\.)[A-Za-z_]\w+)+)", body
        )
    }
    return sorted(fields)


def _source_globals(source: str, function_name: str) -> list[str]:
    body = _source_body(source, function_name) or ""
    locals_ = set(_source_declarations(source, function_name))
    signature = _source_signature(source, function_name)
    if signature:
        locals_.update(
            re.findall(r"\b([A-Za-z_]\w*)\s*(?=,|$)", signature.group(2))
        )
    calls = {
        match.group(1)
        for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", body)
    }
    member_names = {
        match.group(1)
        for match in re.finditer(r"(?:->|\.)\s*([A-Za-z_]\w*)", body)
    }
    ignored = {
        "if", "else", "for", "while", "switch", "case", "break", "continue",
        "goto", "return", "sizeof", "true", "false", "void", "const", "volatile",
        "int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t", "uint32_t",
        "int64_t", "uint64_t", "uintptr_t", "float", "double", "bool",
        "s8", "u8", "s16", "u16", "s32", "u32", "s64", "u64", "f32", "f64",
    }
    identifiers = set(re.findall(r"\b[A-Za-z_]\w*\b", body))
    globals_ = identifiers - locals_ - calls - member_names - ignored - {function_name}
    globals_ = {
        name
        for name in globals_
        if not re.fullmatch(
            r"(?:zero|at|[avstfk]\d+|r\d+|sp|fp|ra|gp|pc|lr|"
            r"loc_[0-9a-fA-F]+|sub_[0-9a-fA-F]+)",
            name,
        )
    }
    return sorted(globals_)


def _normalize_type(token: str) -> str:
    token = token.strip().rstrip(",;")
    aliases = {
        "int8_t": "s8", "int8": "s8", "uint8_t": "u8", "uint8": "u8",
        "int16_t": "s16", "int16": "s16", "uint16_t": "u16", "uint16": "u16",
        "int32_t": "s32", "int32": "s32", "uint32_t": "u32", "uint32": "u32",
        "int64_t": "s64", "int64": "s64", "uint64_t": "u64", "uint64": "u64",
        "float": "f32", "double": "f64",
    }
    return aliases.get(token, token)


def _recovered_access_types(recovery: str, source: str) -> list[str]:
    tokens = {
        _normalize_type(token)
        for token in re.findall(r"\btype(?:=|:\s*)([^\s]+)", recovery)
    }
    tokens.update(
        _normalize_type(token)
        for token in re.findall(
            r"\b(?:int8_t|uint8_t|int16_t|uint16_t|int32_t|uint32_t|"
            r"int64_t|uint64_t|s8|u8|s16|u16|s32|u32|s64|u64|f32|f64|"
            r"float|double)\b",
            source,
        )
    )
    tokens.update(
        match.group(1)
        for match in re.finditer(
            r"(?:typedef\s+struct(?:\s+\w+)?|struct)\b[^;]*\b([A-Z]\w*)\s*;",
            source,
        )
    )
    return sorted(token for token in tokens if token)


def _lift_summary(text: str) -> tuple[int | None, list[str] | None]:
    byte_match = re.search(r"(?m)^bytes:\s*(\d+)\s*$", text)
    call_match = re.search(r"(?m)^calls:\s*\{([^}]*)\}\s*$", text)
    valid_lift = all(
        re.search(pattern, text, re.MULTILINE)
        for pattern in (
            r"^architecture:\s+\S+",
            r"^entry:\s+0x[0-9a-fA-F]+",
            r"^instructions:\s+\d+",
            r"^bytes:\s+\d+",
        )
    )
    calls = (
        sorted(
            f"0x{int(value):x}"
            for value in re.findall(r"\b\d+\b", call_match.group(1))
        )
        if call_match
        else []
        if valid_lift
        else None
    )
    return (int(byte_match.group(1)) if byte_match else None), calls


def _resolved_offset(text: str) -> str | None:
    match = re.search(r"(?m)^offset:\s*(0x[0-9a-fA-F]+|\d+)\s*$", text)
    return f"0x{int(match.group(1), 0):x}" if match else None


def _semantic_expected(function: ManifestFunction) -> dict[str, object]:
    baseline = function.semantic
    if baseline is None:
        return {}
    expected_calls = _strings(baseline.get("calls"), "semantic.calls")
    canonical_calls: list[str] = []
    for token in expected_calls:
        address = token.rsplit("@", 1)[-1]
        try:
            canonical_calls.append(f"0x{int(address, 0):x}")
        except ValueError as error:
            raise SmokeError(
                f"semantic.calls item {token!r} must end in a numeric address"
            ) from error
    return {
        "boundary": {
            "address": f"0x{int(function.address.split('::')[-1], 0):x}",
            "size": function.size,
        },
        "control_flow": _strings(
            baseline.get("control_flow"), "semantic.control_flow"
        ),
        "calls": sorted(canonical_calls),
        "globals": _strings(baseline.get("globals"), "semantic.globals"),
        "recovered_accesses_types": _strings(
            baseline.get("access_types"), "semantic.access_types"
        ),
        "casts": _parse_int(baseline.get("casts"), "semantic.casts"),
        "aggregate_copies": _parse_int(
            baseline.get("aggregate_copies"), "semantic.aggregate_copies"
        ),
        "declaration_order": _strings(
            baseline.get("declaration_order"), "semantic.declaration_order"
        ),
        "nominal_fields": _strings(
            baseline.get("nominal_fields"), "semantic.nominal_fields"
        ),
        "reconstructed_source_structure": _strings(
            baseline.get("source_structure"), "semantic.source_structure"
        ),
    }


def _semantic_provenance(
    entry: ManifestEntry, function: ManifestFunction
) -> dict[str, str]:
    return {
        "url": entry.source_url,
        "commit": entry.source_commit,
        "license": entry.source_license,
        "path": function.source_path,
        "function": function.name,
    }


def _semantic_report(
    entry: ManifestEntry,
    function: ManifestFunction,
    *,
    resolved: str | None,
    lift: str | None,
    recovery: str | None,
    source: str | None,
    errors: dict[str, str] | None = None,
    image_sha256: str | None = None,
    image_sha1: str | None = None,
) -> dict[str, object] | None:
    expected = _semantic_expected(function)
    if not expected:
        return None
    errors = errors or {}
    body = _source_body(source or "", function.name) if source is not None else None
    resolved_offset = _resolved_offset(resolved or "")
    lifted_size, lifted_calls = _lift_summary(lift or "")
    observed: dict[str, object] = {
        "boundary": {
            "address": resolved_offset,
            "size": lifted_size,
        },
        "control_flow": _source_structure(source or "", function.name)[0],
        "calls": lifted_calls,
        "globals": _source_globals(source or "", function.name),
        "recovered_accesses_types": _recovered_access_types(recovery or "", ""),
        "casts": _source_cast_count(source or "", function.name),
        "aggregate_copies": (source or "").count("__builtin_memcpy("),
        "declaration_order": _source_declaration_order(source or "", function.name),
        "nominal_fields": _source_nominal_fields(source or "", function.name),
        "reconstructed_source_structure": _source_structure(
            source or "", function.name
        )[1],
    }
    producers = {
        "boundary": ("resolve", "lift"),
        "control_flow": ("reconstruct-source",),
        "calls": ("lift",),
        "globals": ("reconstruct-source",),
        "recovered_accesses_types": ("recover-types",),
        "casts": ("reconstruct-source",),
        "aggregate_copies": ("reconstruct-source",),
        "declaration_order": ("reconstruct-source",),
        "nominal_fields": ("reconstruct-source",),
        "reconstructed_source_structure": ("reconstruct-source",),
    }
    available = {
        "resolve": resolved is not None,
        "lift": lift is not None,
        "recover-types": recovery is not None,
        "reconstruct-source": source is not None and body is not None,
    }
    parsed = {
        "boundary": resolved_offset is not None and lifted_size is not None,
        "calls": lifted_calls is not None,
    }
    provenance = _semantic_provenance(entry, function)
    dimensions: list[dict[str, object]] = []
    for dimension in SEMANTIC_DIMENSIONS:
        required = producers[dimension]
        missing = [producer for producer in required if not available[producer]]
        detail = None
        if not missing and dimension in parsed and not parsed[dimension]:
            missing = list(required)
            detail = f"{dimension} facts were absent from successful analysis output"
        if missing:
            details = [errors.get(producer) for producer in missing if errors.get(producer)]
            detail = detail or "; ".join(details) or (
                "analysis unavailable from " + ", ".join(missing)
            )
            status = (
                "unsupported"
                if any("unsupported" in item.lower() for item in details)
                else "unavailable"
            )
            observed_value = None
        else:
            observed_value = observed[dimension]
            if (
                dimension == "nominal_fields"
                and expected[dimension]
                and not observed_value
                and "name=<unknown>" in (recovery or "")
            ):
                status = "unavailable"
                detail = "nominal field metadata is unavailable"
                observed_value = None
            elif (
                dimension in {"globals", "nominal_fields"}
                and expected[dimension]
                and observed_value
                and all(
                    any(
                        part.startswith(("DAT_", "field_", "unknown", "RecoveredStruct"))
                        for part in token.split(".")
                    )
                    for token in observed_value
                )
            ):
                status = "unavailable"
                detail = "nominal symbol/type metadata is unavailable"
                observed_value = None
            elif (
                dimension == "recovered_accesses_types"
                and expected[dimension]
                and observed_value
                and all(str(token).startswith("unknown") for token in observed_value)
            ):
                status = "unavailable"
                detail = "recovered access types are unavailable"
                observed_value = None
            else:
                if expected[dimension] == observed_value:
                    status = (
                        "applied"
                        if entry.metadata is not None
                        and (
                            dimension in {"recovered_accesses_types", "nominal_fields"}
                            or (dimension == "casts" and bool(expected[dimension]))
                        )
                        else "exact"
                    )
                else:
                    status = "diverged"
        observed_evidence = None
        if observed_value is not None:
            observed_evidence = {
                "commands": list(required),
                "image_sha256": image_sha256,
                "image_sha1": image_sha1,
                "address": function.address,
            }
            if status == "applied":
                observed_evidence["metadata"] = entry.metadata.get("provenance")
        result = {
            "function": function.name,
            "dimension": dimension,
            "status": status,
            "expected": expected[dimension],
            "observed": observed_value,
            "expected_evidence": provenance,
            "observed_evidence": observed_evidence,
        }
        if detail is not None:
            result["detail"] = detail
        dimensions.append(result)
    statuses = {item["status"] for item in dimensions}
    report_status = (
        "exact"
        if statuses <= {"exact", "applied"}
        else "diverged"
        if "diverged" in statuses
        else "unsupported"
        if "unsupported" in statuses
        else "unavailable"
    )
    return {
        "function": function.name,
        "status": report_status,
        "dimensions": dimensions,
        "source": provenance,
    }


def smoke_entry(
    entry: ManifestEntry,
    image_dir: Path,
    command: Sequence[str],
    *,
    limit: int,
    require_hashes: bool,
    command_runner: CommandRunner = run_command,
    metadata_dir: Path | None = None,
) -> dict[str, object]:
    image = image_dir / entry.binary_name
    if not image.is_file():
        raise SmokeError(f"{entry.id}: image does not exist: {image}")
    actual_hash = sha256_file(image)
    actual_sha1 = sha1_file(image)
    hash_status = _hash_status(entry, actual_hash, actual_sha1, require_hashes)
    metadata_args: list[str] = []
    if entry.metadata is not None:
        if metadata_dir is None:
            raise SmokeError(f"{entry.id}: metadata_dir is required for embedded metadata")
        metadata_path = metadata_dir / f"{entry.id}.metadata.json"
        metadata_path.write_text(
            json.dumps(entry.metadata, sort_keys=True), encoding="utf-8"
        )
        metadata_args = ["--metadata", os.fspath(metadata_path)]
    target_args = ["--target", entry.target]
    if entry.base is not None:
        target_args.extend(["--base", f"0x{entry.base:x}"])
    target_args.append("--json")
    function_results: list[dict[str, object]] = []
    warnings: list[str] = []

    for function in entry.functions:
        address = function_address(entry, function)
        command_errors: dict[str, str] = {}
        command_warnings: list[str] = []
        try:
            resolve_stdout, resolve_stderr = command_runner(
                command,
                ["resolve", os.fspath(image), address, *target_args],
            )
            resolve_result = _envelope(resolve_stdout, "resolve")
            command_warnings.extend(resolve_stderr.splitlines())
            expected_offset = f"offset: {function.address}"
            if expected_offset.lower() not in resolve_result.lower():
                raise SmokeError(
                    f"resolve returned the wrong manifest offset; expected {function.address}"
                )
        except SmokeError as error:
            detail = str(error)
            command_errors["resolve"] = detail
            semantic_report = _semantic_report(
                entry,
                function,
                resolved=None,
                lift=None,
                recovery=None,
                source=None,
                errors=command_errors,
                image_sha256=actual_hash,
                image_sha1=actual_sha1,
            )
            function_result = {
                "name": function.name,
                "address": function.address,
                "size": function.size,
                "warnings": [],
                "status": "fail",
                "error": f"{entry.id}/{function.name}: {detail}",
            }
            if semantic_report is not None:
                function_result["semantic"] = semantic_report
            function_results.append(function_result)
            continue

        analysis_args = [
            os.fspath(image),
            address,
            *target_args[:-1],
            "--limit",
            str(limit),
            "--json",
        ]
        decompile_result = None
        try:
            stdout, stderr = command_runner(
                command, ["decompile-native", *analysis_args]
            )
            decompile_result = _envelope(stdout, "decompile-native")
            command_warnings.extend(stderr.splitlines())
            if not decompile_result.strip():
                raise SmokeError("decompile-native returned empty C output")
        except SmokeError as error:
            command_errors["decompile-native"] = str(error)

        semantic_report = None
        if function.semantic is not None:
            outputs: dict[str, str | None] = {
                "lift": None,
                "recover-types": None,
                "reconstruct-source": None,
            }
            for producer in outputs:
                try:
                    producer_args = (
                        [*analysis_args, *metadata_args]
                        if producer in {"recover-types", "reconstruct-source"}
                        else analysis_args
                    )
                    stdout, stderr = command_runner(command, [producer, *producer_args])
                    outputs[producer] = _envelope(stdout, producer)
                    command_warnings.extend(stderr.splitlines())
                except SmokeError as error:
                    command_errors[producer] = str(error)
            semantic_report = _semantic_report(
                entry,
                function,
                resolved=resolve_result,
                lift=outputs["lift"],
                recovery=outputs["recover-types"],
                source=outputs["reconstruct-source"],
                errors=command_errors,
                image_sha256=actual_hash,
                image_sha1=actual_sha1,
            )

        function_warnings = [line for line in command_warnings if line.strip()]
        warnings.extend(function_warnings)
        problems: list[str] = []
        if decompile_result is None:
            problems.append(command_errors["decompile-native"])
        if semantic_report is not None and semantic_report["status"] != "exact":
            incomplete = [
                f"{item['dimension']}={item['status']}"
                for item in semantic_report["dimensions"]
                if item["status"] != "exact"
            ]
            problems.append("semantic comparison: " + ", ".join(incomplete))
        function_result: dict[str, object] = {
            "name": function.name,
            "address": function.address,
            "size": function.size,
            "warnings": function_warnings,
            "status": "fail" if problems else "pass",
        }
        if semantic_report is not None:
            function_result["semantic"] = semantic_report
        if problems:
            function_result["error"] = (
                f"{entry.id}/{function.name}: " + "; ".join(problems)
            )
        function_results.append(function_result)

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
        "sha1": actual_sha1,
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
    command = [*list(command or find_ventris()), "__internal"]
    manifest_stdout, _ = command_runner(command, ["corpus", "--json"])
    entries = {entry.id: entry for entry in parse_manifest(manifest_stdout)}
    selected_ids = tuple(ids)
    metadata_temp = tempfile.TemporaryDirectory(prefix="ventris-corpus-metadata-")
    metadata_dir = Path(metadata_temp.name)
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
                    metadata_dir=metadata_dir,
                )
            )
        except SmokeError as error:
            results.append({"id": entry.id, "title": entry.title, "target": entry.target, "status": "fail", "error": str(error)})

    metadata_temp.cleanup()
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
