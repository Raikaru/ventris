#!/usr/bin/env python3
"""Differentially compare Ventris instruction p-code with Ghidra.

The harness deliberately compares the instruction-level contract, not rendered
C. Ghidra supplies the reference p-code through ``dump_capsule.java``; Ventris
supplies its p-code through the native ``lift`` command. Unique-space offsets
are canonicalized per instruction because they are allocator-local names, but
opcodes, operand order, address-space kind, offsets, and widths remain strict.
"""

from __future__ import annotations

import argparse
import hashlib
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Iterable, Sequence

GHIDRA_VERSION = "12.1.3"
GHIDRA_RELEASE_TAG = "Ghidra_12.1.3_build"
GHIDRA_SOURCE_COMMIT = "8b4c91d4d5bd1549622bfbade0df199585b98365"
GHIDRA_RELEASE_SHA256 = "93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54"


@dataclass(frozen=True)
class Varnode:
    space: int
    offset: int
    size: int


@dataclass(frozen=True)
class Operation:
    opcode: int
    output: Varnode | None
    inputs: tuple[Varnode, ...]


@dataclass
class Instruction:
    address: int
    length: int
    operations: list[Operation]
    bytes_hex: str = ""
    flow: str = ""


@dataclass
class Capsule:
    function: str
    language: str
    entry: int
    length: int
    image: bytes
    instructions: list[Instruction]


@dataclass
class Diff:
    address: int
    kind: str
    detail: str


SPACE_NAMES = {
    "const": 0,
    "constant": 0,
    "other": 1,
    "unique": 2,
    "ram": 3,
    "register": 4,
}

SPACE_IDS = {value: key for key, value in SPACE_NAMES.items() if key in {"const", "other", "unique", "ram", "register"}}
VAR_NODE = re.compile(r"Varnode \{ space: (\d+), offset: (\d+), size: (\d+) \}")
NATIVE_INST = re.compile(
    r"^\s+(0x[0-9a-fA-F]+):\s+(\d+)\s+([0-9a-fA-F]*)\s+flow=(.*)$"
)
NATIVE_OP = re.compile(r"^\s+op (-?\d+) output=(.*?) inputs=\[(.*)\]\s*$")
GHIDRA_INST = re.compile(r"^inst (\d+) (\d+) (\d+)(?:\s+#.*)?$")
GHIDRA_OP = re.compile(r"^  op (-?\d+)(?: (.*))?$")


def parse_int(value: str) -> int:
    return int(value, 0)


def parse_ghidra_varnode(token: str) -> Varnode:
    parts = token.split(":")
    if len(parts) != 3:
        raise ValueError(f"bad Ghidra varnode {token!r}")
    space = SPACE_NAMES.get(parts[0].lower())
    if space is None:
        raise ValueError(f"unknown Ghidra address space {parts[0]!r}")
    return Varnode(space, parse_int(parts[1]), parse_int(parts[2]))


def parse_capsule_text(text: str) -> Capsule:
    function = ""
    language = ""
    entry = None
    length = None
    image = b""
    instructions: list[Instruction] = []
    lines = iter(text.splitlines())
    for line in lines:
        if line.startswith("function "):
            function = line[9:].strip()
        elif line.startswith("language "):
            language = line[9:].strip()
        elif line.startswith("entry "):
            entry = parse_int(line[6:].strip())
        elif line.startswith("length "):
            length = parse_int(line[7:].strip())
        elif line.startswith("bytes "):
            image = bytes.fromhex(line[6:].strip())
        else:
            match = GHIDRA_INST.match(line)
            if not match:
                continue
            address, inst_len, op_count = map(int, match.groups())
            operations: list[Operation] = []
            for _ in range(op_count):
                op_line = next(lines, None)
                if op_line is None:
                    raise ValueError(f"truncated operations at {address:#x}")
                op_match = GHIDRA_OP.match(op_line)
                if not op_match:
                    raise ValueError(f"bad Ghidra operation {op_line!r}")
                opcode = int(op_match.group(1))
                payload = (op_match.group(2) or "").split()
                output = None if not payload or payload[0] == "void" else parse_ghidra_varnode(payload[0])
                input_tokens = (
                    payload[1:]
                    if payload and payload[0] == "void"
                    else (payload if output is None else payload[1:])
                )
                operations.append(
                    Operation(opcode, output, tuple(parse_ghidra_varnode(token) for token in input_tokens))
                )
            instructions.append(Instruction(address, inst_len, operations))
    if entry is None or length is None:
        raise ValueError("capsule is missing entry/length")
    if not function:
        function = "<unnamed>"
    return Capsule(function, language, entry, length, image, instructions)


def parse_capsule(path: Path) -> Capsule:
    return parse_capsule_text(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def write_ghidra_fixture(
    args: argparse.Namespace,
    capsule_path: Path,
    capsule: Capsule,
    destination: Path,
) -> None:
    """Persist only Ghidra-authored p-code plus immutable oracle provenance."""
    metadata = [
        "# ventris-ghidra-fixture 1",
        "# oracle=Ghidra",
        f"# ghidra_version={GHIDRA_VERSION}",
        f"# ghidra_release_tag={GHIDRA_RELEASE_TAG}",
        f"# ghidra_source_commit={GHIDRA_SOURCE_COMMIT}",
        f"# ghidra_release_sha256={GHIDRA_RELEASE_SHA256}",
        f"# language={capsule.language}",
        f"# architecture={args.arch}",
        f"# source_image={args.image.name}",
        f"# source_image_sha256={sha256_file(args.image)}",
        f"# function={capsule.function}",
        f"# entry={capsule.entry:#x}",
        f"# length={capsule.length:#x}",
        f"# function_bytes_sha256={hashlib.sha256(capsule.image).hexdigest()}",
        "# generated_by=tools/diff_ghidra.py",
        "",
    ]
    capsule_lines = [
        line
        for line in capsule_path.read_text(encoding="utf-8").splitlines()
        if not line.startswith(("reg ", "userop "))
    ]
    body = "\n".join(capsule_lines) + "\n"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(metadata) + body, encoding="utf-8", newline="\n")


def parse_native_varnodes(text: str) -> list[Varnode]:
    return [Varnode(int(space), int(offset), int(size)) for space, offset, size in VAR_NODE.findall(text)]


def parse_lift(text: str) -> list[Instruction]:
    instructions: list[Instruction] = []
    current: Instruction | None = None
    for line in text.splitlines():
        match = NATIVE_INST.match(line)
        if match:
            address = int(match.group(1), 16)
            current = Instruction(address, int(match.group(2)), [], match.group(3), match.group(4))
            instructions.append(current)
            continue
        match = NATIVE_OP.match(line)
        if not match or current is None:
            continue
        opcode = int(match.group(1))
        output_text = match.group(2)
        nodes = parse_native_varnodes(output_text + " " + match.group(3))
        if output_text.startswith("Some("):
            if not nodes:
                raise ValueError(f"missing native output varnode in {line!r}")
            output = nodes[0]
            inputs = tuple(nodes[1:])
        else:
            output = None
            inputs = tuple(nodes)
        current.operations.append(Operation(opcode, output, inputs))
    if not instructions:
        raise ValueError("native lifter produced no instructions")
    return instructions


def canonical_operations(operations: Iterable[Operation]) -> tuple[Operation, ...]:
    """Normalize unique temporaries while retaining every other operand fact."""
    unique: dict[int, int] = {}

    def canonical(node: Varnode | None) -> Varnode | None:
        if node is None or node.space != SPACE_NAMES["unique"]:
            return node
        canonical_offset = unique.setdefault(node.offset, len(unique))
        return Varnode(node.space, canonical_offset, node.size)

    return tuple(
        Operation(operation.opcode, canonical(operation.output), tuple(canonical(node) for node in operation.inputs))
        for operation in operations
    )


def compare(capsule: Capsule, native: Sequence[Instruction]) -> list[Diff]:
    reference = {instruction.address: instruction for instruction in capsule.instructions}
    candidate = {instruction.address: instruction for instruction in native}
    diffs: list[Diff] = []
    for address in sorted(reference.keys() - candidate.keys()):
        diffs.append(Diff(address, "missing", "Ventris did not lift the Ghidra instruction"))
    for address in sorted(candidate.keys() - reference.keys()):
        diffs.append(Diff(address, "extra", "Ventris lifted outside the Ghidra function body"))
    for address in sorted(reference.keys() & candidate.keys()):
        expected = reference[address]
        actual = candidate[address]
        if expected.length != actual.length:
            diffs.append(Diff(address, "length", f"Ghidra={expected.length} Ventris={actual.length}"))
        expected_ops = canonical_operations(expected.operations)
        actual_ops = canonical_operations(actual.operations)
        if expected_ops != actual_ops:
            diffs.append(
                Diff(
                    address,
                    "pcode",
                    f"Ghidra={expected_ops!r} Ventris={actual_ops!r}",
                )
            )
    return diffs


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def ghidra_version(root: Path) -> str:
    properties = root / "Ghidra" / "application.properties"
    if not properties.is_file():
        raise RuntimeError(f"Ghidra install has no application metadata: {properties}")
    for line in properties.read_text(encoding="utf-8").splitlines():
        if line.startswith("application.version="):
            return line.partition("=")[2].strip()
    raise RuntimeError(f"Ghidra install does not declare application.version: {properties}")


def validate_ghidra(root: Path) -> Path:
    if not (root / "support" / "analyzeHeadless.bat").is_file() and not (
        root / "support" / "analyzeHeadless"
    ).is_file():
        raise RuntimeError(f"Ghidra install has no headless launcher: {root}")
    version = ghidra_version(root)
    if version != GHIDRA_VERSION:
        raise RuntimeError(
            f"Ghidra {GHIDRA_VERSION} is required; {root} contains {version}"
        )
    return root


def find_ghidra(explicit: str | None) -> Path:
    if explicit:
        return validate_ghidra(Path(explicit))
    env_root = os.environ.get("GHIDRA_INSTALL_DIR")
    if env_root:
        return find_ghidra(env_root)
    candidates = (
        sorted(Path("C:/Tools").glob("ghidra*"), reverse=True)
        if Path("C:/Tools").is_dir()
        else []
    )
    mismatches = []
    for candidate in candidates:
        try:
            return validate_ghidra(candidate)
        except RuntimeError as error:
            mismatches.append(str(error))
    detail = f": {'; '.join(mismatches)}" if mismatches else ""
    raise RuntimeError(
        f"Ghidra {GHIDRA_VERSION} not found; pass --ghidra or set "
        f"GHIDRA_INSTALL_DIR{detail}"
    )


def find_ventris(explicit: str | None) -> list[str]:
    if explicit:
        return [explicit]
    root = repo_root()
    for candidate in (root / "target" / "debug" / "ventris.exe", root / "target" / "release" / "ventris.exe"):
        if candidate.is_file():
            return [str(candidate)]
    cargo = shutil.which("cargo")
    if cargo:
        return [cargo, "run", "--quiet", "-p", "ventris-cli", "--"]
    raise RuntimeError("Ventris executable not found; build it or pass --ventris")


def run_ghidra(args: argparse.Namespace, capsule_path: Path) -> tuple[str, str]:
    root = find_ghidra(args.ghidra)
    launcher = root / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    script = repo_root() / "tools" / "DumpCapsule.java"
    if not script.is_file():
        raise RuntimeError(f"missing Ghidra exporter: {script}")
    with tempfile.TemporaryDirectory(prefix="ventris-ghidra-") as project:
        command = [str(launcher), project, "ventris-diff", "-noanalysis", "-import", str(args.image)]
        if args.raw:
            if not args.processor:
                raise RuntimeError("--raw requires --processor")
            command.extend(
                [
                    "-loader",
                    "BinaryLoader",
                    "-processor",
                    args.processor,
                    "-loader-baseAddr",
                    hex(args.entry),
                ]
            )
        if args.arch == "gamecube" and not args.raw:
            # GameCubeLoader otherwise opens a Swing symbol-map prompt when no
            # adjacent map exists, which deadlocks analyzeHeadless.
            command.extend(["-loader-autoloadMaps", "false"])
        command.extend(
            [
                "-scriptPath",
                str(script.parent),
                "-postScript",
                script.name,
                args.function,
                str(capsule_path),
            ]
        )
        if args.length is not None:
            command.append(str(args.length))
        command.append("-deleteProject")
        completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.returncode:
        raise RuntimeError(
            "Ghidra headless failed (exit %d):\n%s" % (completed.returncode, completed.stdout + completed.stderr)
        )
    if not capsule_path.is_file():
        raise RuntimeError("Ghidra exporter did not create a capsule:\n" + completed.stdout + completed.stderr)
    return completed.stdout, completed.stderr


def run_native(args: argparse.Namespace, entry: int, limit: int) -> str:
    command = find_ventris(args.ventris) + [
        "lift",
        str(args.image),
        hex(entry),
        "--arch",
        args.arch,
        "--limit",
        str(max(limit, args.limit)),
    ]
    if args.raw:
        command.append("--raw")
    elif args.arch == "gamecube":
        # DOL has no container magic; the architecture alone cannot make
        # Ventris's loader auto-detect it.
        command.extend(["--loader", "dol"])
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.returncode:
        raise RuntimeError(
            "Ventris lift failed (exit %d):\n%s" % (completed.returncode, completed.stdout + completed.stderr)
        )
    return completed.stdout


def report_dict(capsule: Capsule, native: Sequence[Instruction], diffs: Sequence[Diff]) -> dict[str, object]:
    return {
        "function": capsule.function,
        "language": capsule.language,
        "entry": hex(capsule.entry),
        "ghidra_instructions": len(capsule.instructions),
        "ventris_instructions": len(native),
        "differences": [
            {"address": hex(diff.address), "kind": diff.kind, "detail": diff.detail} for diff in diffs
        ],
        "matched": not diffs,
        "ghidra_version": GHIDRA_VERSION,
        "ghidra_release_tag": GHIDRA_RELEASE_TAG,
    }


def self_test() -> None:
    capsule = parse_capsule_text(
        "\n".join(
            [
                "function f",
                "language x86:LE:64:default",
                "entry 4096",
                "length 2",
                "bytes 31c0",
                "inst 4096 2 1  # XOR",
                "  op 26 register:0:4 register:0:4 register:0:4",
            ]
        )
    )
    native = parse_lift(
        "\n".join(
            [
                "  0x1000: 2 31c0 flow=FallThrough(4098)",
                "    op 26 output=Some(Varnode { space: 4, offset: 0, size: 4 }) inputs=[Varnode { space: 4, offset: 0, size: 4 }, Varnode { space: 4, offset: 0, size: 4 }]",
            ]
        )
    )
    assert not compare(capsule, native)
    with tempfile.TemporaryDirectory(prefix="ventris-ghidra-version-") as work:
        root = Path(work)
        (root / "Ghidra").mkdir()
        (root / "support").mkdir()
        (root / "support" / "analyzeHeadless.bat").touch()
        properties = root / "Ghidra" / "application.properties"
        properties.write_text(
            f"application.version={GHIDRA_VERSION}\n", encoding="utf-8"
        )
        assert validate_ghidra(root) == root
        properties.write_text("application.version=12.1\n", encoding="utf-8")
        try:
            validate_ghidra(root)
        except RuntimeError as error:
            assert f"Ghidra {GHIDRA_VERSION} is required" in str(error)
        else:
            raise AssertionError("version mismatch was accepted")
    print("diff_ghidra self-test: ok")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", nargs="?", type=Path, help="binary to import into Ghidra")
    parser.add_argument("--function", default="0x140001460", help="function name or entry address")
    parser.add_argument("--entry", type=parse_int, help="numeric entry for raw imports")
    parser.add_argument(
        "--arch",
        default="x86_64",
        choices=["x86_64", "x86_32", "aarch64", "arm32", "thumb", "mips32", "mips32be", "ps1", "ps2", "n64", "rv64", "rv32", "ppc32", "ppc64", "gamecube", "m68k", "sh2", "sh4", "m6502", "z80", "spu"],
    )
    parser.add_argument("--processor", help="Ghidra processor language for --raw imports")
    parser.add_argument("--raw", action="store_true", help="import image as raw bytes")
    parser.add_argument(
        "--ghidra",
        help=f"Ghidra {GHIDRA_VERSION} installation directory",
    )
    parser.add_argument("--ventris", help="Ventris executable")
    parser.add_argument("--limit", type=int, default=4096)
    parser.add_argument(
        "--length",
        type=parse_int,
        help="explicit raw function byte length; disassembles only that bounded range",
    )
    parser.add_argument("--strict", action="store_true", help="return non-zero when p-code differs")
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    parser.add_argument(
        "--summary-json",
        action="store_true",
        help="emit compact JSON with difference counts instead of full details",
    )
    parser.add_argument(
        "--write-ghidra-fixture",
        type=Path,
        help="write the Ghidra capsule and pinned provenance before comparing Ventris",
    )
    parser.add_argument("--self-test", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    if args.image is None:
        parser.error("image is required unless --self-test is used")
    args.image = args.image.resolve()
    if not args.image.is_file():
        parser.error(f"image does not exist: {args.image}")
    if args.entry is None:
        try:
            args.entry = parse_int(args.function)
        except ValueError:
            args.entry = 0
    if args.raw and args.entry == 0:
        parser.error("--raw requires --entry")
    if args.length is not None and args.length <= 0:
        parser.error("--length must be positive")
    with tempfile.TemporaryDirectory(prefix="ventris-diff-") as work:
        capsule_path = Path(work) / "capsule.txt"
        ghidra_stdout, ghidra_stderr = run_ghidra(args, capsule_path)
        capsule = parse_capsule(capsule_path)
        if args.write_ghidra_fixture is not None:
            write_ghidra_fixture(args, capsule_path, capsule, args.write_ghidra_fixture)
        native_text = run_native(args, capsule.entry, len(capsule.instructions))
        native = parse_lift(native_text)
        if args.length is not None:
            stop = capsule.entry + capsule.length
            native = [
                instruction
                for instruction in native
                if capsule.entry <= instruction.address < stop
            ]
    report = report_dict(capsule, native, compare(capsule, native))
    if args.summary_json:
        kinds: dict[str, int] = {}
        for difference in report["differences"]:
            kind = difference["kind"]
            kinds[kind] = kinds.get(kind, 0) + 1
        summary = {key: value for key, value in report.items() if key != "differences"}
        summary["difference_count"] = len(report["differences"])
        summary["difference_kinds"] = kinds
        print(json.dumps(summary, indent=2, sort_keys=True))
    elif args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            f"{report['function']} {report['entry']}: "
            f"Ghidra={report['ghidra_instructions']} Ventris={report['ventris_instructions']} "
            f"differences={len(report['differences'])}"
        )
        for difference in report["differences"]:
            print(f"  {difference['address']} {difference['kind']}: {difference['detail']}")
    if ghidra_stderr and os.environ.get("VENTRIS_DIFF_VERBOSE"):
        print(ghidra_stderr, file=sys.stderr, end="")
    return 1 if args.strict and report["differences"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
