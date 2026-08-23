"""Compile reconstructed PS2 C and compare normalized MIPS assembly.

The gate is intentionally compiler-agnostic: exact bytes are reported when
present, while ordinary runs require compilable C and a minimum mnemonic LCS
ratio against the pinned retail function window.
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
from typing import Sequence

from .corpus_smoke import ManifestEntry, SmokeError, _envelope, parse_manifest


_INSTRUCTION = re.compile(r"^\s*[0-9a-fA-F]+:\s+([A-Za-z_.][A-Za-z0-9_.]*)\b", re.MULTILINE)
_CALLS = {"jal", "jalr", "bal", "bgezal", "bltzal"}


def _run(command: Sequence[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, input=input_text, text=True, capture_output=True)
    except OSError as error:
        raise SmokeError(f"cannot execute {command[0]}: {error}") from error


def _ventris(command: Sequence[str], args: Sequence[str]) -> str:
    completed = _run([*command, *args])
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise SmokeError(f"ventris {' '.join(args[:1])} failed: {detail}")
    return _envelope(completed.stdout, args[0])


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _mnemonics(disassembly: str) -> list[str]:
    aliases = {"move": "addu", "b": "beq", "beqz": "beq", "bnez": "bne"}
    return [aliases.get(token.lower(), token.lower()) for token in _INSTRUCTION.findall(disassembly)]


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


def run_gate(
    *,
    image_dir: Path,
    entry_id: str,
    ventris: Sequence[str],
    compiler: str = "clang",
    objdump: str = "llvm-objdump",
    functions: Sequence[str] = (),
    minimum_ratio: float = 0.15,
    require_exact: bool = False,
) -> dict[str, object]:
    corpus = _run([*ventris, "corpus", "--json"])
    if corpus.returncode != 0:
        detail = corpus.stderr.strip() or corpus.stdout.strip()
        raise SmokeError(f"ventris corpus failed: {detail}")
    manifest = parse_manifest(corpus.stdout)
    entry = _entry(manifest, entry_id)
    if entry.target != "ps2":
        raise SmokeError("compiler gate currently supports the PS2 MIPS target")
    image = (image_dir / entry.binary_name).resolve()
    if not image.is_file():
        raise SmokeError(f"missing corpus image: {image}")
    actual_hash = _sha256(image)
    if entry.binary_sha256 is not None and actual_hash.lower() != entry.binary_sha256.lower():
        raise SmokeError(f"{entry.id}: SHA-256 mismatch")

    selected = [
        function
        for function in entry.functions
        if (function.name in functions if functions else function.semantic is not None)
    ]
    if not selected:
        raise SmokeError("no compiler-gate functions selected")
    unknown = sorted(set(functions) - {function.name for function in selected})
    if unknown:
        raise SmokeError("unknown or unselected functions: " + ", ".join(unknown))

    results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="ventris-compiler-gate-") as directory:
        work = Path(directory)
        metadata_args: list[str] = []
        if entry.metadata is not None:
            metadata_path = work / "metadata.json"
            metadata_path.write_text(json.dumps(entry.metadata, sort_keys=True), encoding="utf-8")
            metadata_args = ["--metadata", os.fspath(metadata_path)]

        for index, function in enumerate(selected):
            source = _ventris(
                ventris,
                [
                    "reconstruct-source",
                    os.fspath(image),
                    f"ram::{function.address}",
                    "--target",
                    entry.target,
                    "--limit",
                    str(function.size),
                    *metadata_args,
                    "--json",
                ],
            )
            source_path = work / f"candidate-{index}.c"
            object_path = work / f"candidate-{index}.o"
            source_path.write_text(source, encoding="utf-8")
            compile_command = [
                compiler,
                "--target=mipsel-none-elf",
                "-std=c11",
                "-O2",
                "-ffreestanding",
                "-fno-pic",
                "-mno-abicalls",
                "-Wno-error=int-conversion",
                "-c",
                os.fspath(source_path),
                "-o",
                os.fspath(object_path),
            ]
            compiled = _run(compile_command)
            item: dict[str, object] = {
                "function": function.name,
                "address": function.address,
                "size": function.size,
                "compiler": compiler,
                "compiler_target": "mipsel-none-elf",
                "compile_status": "success" if compiled.returncode == 0 else "failed",
                "compiler_diagnostics": [
                    line for line in compiled.stderr.splitlines() if line.strip()
                ],
            }
            if compiled.returncode != 0:
                item.update({"status": "compile-failed", "pass": False})
                results.append(item)
                continue

            candidate_dump = _run([objdump, "-d", "--no-show-raw-insn", os.fspath(object_path)])
            retail_dump = _run(
                [
                    objdump,
                    "-d",
                    "--no-show-raw-insn",
                    f"--start-address={int(function.address, 0)}",
                    f"--stop-address={int(function.address, 0) + function.size}",
                    os.fspath(image),
                ]
            )
            if candidate_dump.returncode != 0 or retail_dump.returncode != 0:
                detail = candidate_dump.stderr.strip() or retail_dump.stderr.strip()
                item.update({"status": "disassembly-failed", "pass": False, "detail": detail})
                results.append(item)
                continue

            candidate = _mnemonics(candidate_dump.stdout)
            retail = _mnemonics(retail_dump.stdout)
            ratio = _lcs_ratio(candidate, retail)
            exact = candidate == retail
            call_counts = {
                "candidate": sum(mnemonic in _CALLS for mnemonic in candidate),
                "retail": sum(mnemonic in _CALLS for mnemonic in retail),
            }
            passed = exact if require_exact else ratio >= minimum_ratio
            item.update(
                {
                    "status": "exact" if exact else "normalized-similar" if passed else "normalized-diverged",
                    "pass": passed,
                    "exact": exact,
                    "mnemonic_lcs_ratio": round(ratio, 6),
                    "minimum_ratio": minimum_ratio,
                    "instruction_counts": {"candidate": len(candidate), "retail": len(retail)},
                    "call_counts": call_counts,
                    "candidate_mnemonics": candidate,
                    "retail_mnemonics": retail,
                }
            )
            results.append(item)

    return {
        "ok": all(bool(item.get("pass")) for item in results),
        "id": entry.id,
        "image": os.fspath(image),
        "sha256": actual_hash,
        "require_exact": require_exact,
        "minimum_ratio": minimum_ratio,
        "functions": results,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-dir", required=True, type=Path)
    parser.add_argument("--id", required=True)
    parser.add_argument("--ventris", required=True)
    parser.add_argument("--compiler", default="clang")
    parser.add_argument("--objdump", default="llvm-objdump")
    parser.add_argument("--function", action="append", dest="functions", default=[])
    parser.add_argument("--minimum-ratio", type=float, default=0.15)
    parser.add_argument("--require-exact", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
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
