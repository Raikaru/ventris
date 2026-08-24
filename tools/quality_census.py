"""Measure Ventris rendered-C quality against the Ghidra decompiler oracle.

The corpus gate answers "did this function regress". It cannot answer "which
change would improve the most functions", because it only reports pass or fail
against per-function baselines. This census answers the second question: it
renders every hash-verified corpus function with Ventris, renders the same
function with Ghidra's decompiler, and classifies the differences into defect
families ranked by how many real functions each affects.

Ghidra is an oracle, not a specification. A difference is evidence to
investigate, not automatically a bug, so every finding names the function it
came from.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import corpus_smoke

# Import arguments per corpus target. Container-aware loaders pick the language
# themselves; forcing `-processor` alongside them makes Ghidra reject the
# import. Raw ROMs have no loader, so they need both a processor and a base.
GHIDRA_IMPORT = {
    "gamecube": ["-loader-autoloadMaps", "false"],
    "ps2": [],
    "n64": [
        "-processor",
        "MIPS:BE:64:64-32addr",
        "-loader",
        "BinaryLoader",
        "-loader-baseAddr",
        "0x80000000",
    ],
}


class CensusError(RuntimeError):
    """Raised when the census cannot be measured as requested."""


@dataclass(frozen=True)
class Target:
    entry_id: str
    target: str
    image: Path
    name: str
    address: str
    size: str
    address_space: str | None
    base: int | None
    has_baseline: bool

    @property
    def census_id(self) -> str:
        return f"{self.entry_id}__{self.name}"

    @property
    def qualified_address(self) -> str:
        if "::" in self.address or not self.address_space:
            return self.address
        return f"{self.address_space}::{self.address}"


@dataclass
class Finding:
    family: str
    detail: str


@dataclass
class Row:
    target: Target
    ventris: str | None = None
    ventris_error: str | None = None
    oracle: str | None = None
    oracle_error: str | None = None
    findings: list[Finding] = field(default_factory=list)


def selected_entries(manifest: Sequence[dict], image_dir: Path) -> list[dict]:
    """Keeps entries whose on-disk image matches the manifest's pinned hash.

    An unverified image cannot support evidence about decompilation quality: a
    difference could come from the decompiler or from the wrong bytes.
    """
    entries = []
    for entry in manifest:
        image = image_dir / entry["binary_name"]
        if not image.is_file():
            continue
        expected_sha256 = entry.get("binary_sha256")
        expected_sha1 = entry.get("binary_sha1")
        if expected_sha256 and corpus_smoke.sha256_file(image) != expected_sha256:
            continue
        if expected_sha1 and corpus_smoke.sha1_file(image) != expected_sha1:
            continue
        if not expected_sha256 and not expected_sha1:
            continue
        entries.append(entry)
    return entries


def targets_for(entries: Iterable[dict], image_dir: Path) -> list[Target]:
    targets = []
    for entry in entries:
        for function in entry["functions"]:
            targets.append(
                Target(
                    entry_id=entry["id"],
                    target=entry["target"],
                    image=image_dir / entry["binary_name"],
                    name=function["name"],
                    address=function["address"],
                    size=function["size"],
                    address_space=entry.get("address_space"),
                    base=entry.get("base"),
                    has_baseline=function.get("semantic") is not None,
                )
            )
    return targets


def read_manifest(ventris: str) -> list[dict]:
    completed = subprocess.run(
        [ventris, "__internal", "corpus", "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise CensusError(f"corpus manifest failed: {completed.stderr.strip()}")
    return json.loads(json.loads(completed.stdout)["result"])


def render_ventris(ventris: str, target: Target, limit: int) -> tuple[str | None, str | None]:
    # The public `decompile` command is what a user runs: load, lift, analyze,
    # and render. Measuring the internal raw-render stage instead would report
    # missing type recovery that the product already performs. No metadata is
    # supplied, so both sides rely on their own inference.
    args = [
        ventris,
        "decompile",
        os.fspath(target.image),
        target.qualified_address,
        "--target",
        target.target,
        "--limit",
        str(limit),
        "--json",
    ]
    if target.base is not None:
        args[4:4] = ["--base", f"0x{target.base:x}"]
    completed = subprocess.run(args, capture_output=True, text=True, check=False)
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None, completed.stderr.strip() or "no JSON envelope"
    if not payload.get("ok"):
        return None, str(payload.get("error", "unknown error"))
    return payload["result"], None


def run_oracle(
    ghidra: Path, project_dir: Path, out_dir: Path, entry: dict, targets: Sequence[Target]
) -> None:
    import_args = GHIDRA_IMPORT.get(entry["target"])
    if import_args is None:
        raise CensusError(f"no Ghidra import recipe for target {entry['target']}")
    spec_path = out_dir / f"{entry['id']}.spec"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text(
        "".join(
            f"{target.census_id}\t{target.address}\t{target.size}\n" for target in targets
        ),
        encoding="utf-8",
        newline="\n",
    )
    project_dir.mkdir(parents=True, exist_ok=True)
    command = [
        "cmd.exe",
        "/d",
        "/c",
        os.fspath(ghidra / "support" / "analyzeHeadless.bat"),
        os.fspath(project_dir),
        f"census-{entry['id']}",
        "-import",
        os.fspath(targets[0].image),
        *import_args,
        "-scriptPath",
        os.fspath(Path(__file__).resolve().parent),
        "-postScript",
        "CensusDecompile.java",
        os.fspath(spec_path),
        os.fspath(out_dir),
        "-deleteProject",
    ]
    if os.name != "nt":
        command = command[3:]
        command[0] = os.fspath(ghidra / "support" / "analyzeHeadless")
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if "VENTRIS census done" not in completed.stdout:
        tail = completed.stdout[-2000:] + completed.stderr[-2000:]
        raise CensusError(f"{entry['id']}: Ghidra census did not complete:\n{tail}")


def oracle_c(text: str) -> str:
    body = text.split("c_begin\n", 1)
    if len(body) != 2:
        raise CensusError("oracle output has no c_begin marker")
    return body[1].split("c_end\n", 1)[0]


CONTROL_TOKENS = ("if", "else", "for", "while", "do", "switch", "goto", "return", "break")


def control_profile(source: str) -> Counter:
    counts: Counter = Counter()
    for token in CONTROL_TOKENS:
        counts[token] = len(re.findall(rf"\b{token}\b", source))
    return counts


def function_body(source: str) -> str:
    """Drops the signature so a definition is never counted as a call site.

    Ventris names an unsymbolized function `sub_<address>` and Ghidra names it
    `FUN_<address>`, both of which match a call pattern. Counting the signature
    reported a phantom call in every function whose oracle had a real symbol.
    """
    lines = source.splitlines()
    for index, line in enumerate(lines):
        if line.strip().startswith("{"):
            return "\n".join(lines[index + 1 :])
    return source


def call_names(source: str) -> Counter:
    return Counter(
        re.findall(
            r"\b((?:FUN_|func_0x|sub_)[0-9A-Fa-f]+|[A-Za-z_][A-Za-z0-9_]*)\s*\(",
            function_body(source),
        )
    )


def function_signature(source: str) -> str | None:
    """Finds the rendered function signature, ignoring types and comments.

    Both renderers emit type declarations and comments before the function, and
    Ghidra writes calling conventions and qualified names into the signature. A
    depth-aware scan for the last top-level declaration line is the only form
    that reads both.
    """
    depth = 0
    candidate = None
    for line in source.splitlines():
        stripped = line.strip()
        if (
            depth == 0
            and "(" in stripped
            and not stripped.startswith(("/*", "*", "//", "#"))
            and not stripped.endswith(";")
        ):
            candidate = stripped
        depth += line.count("{") - line.count("}")
    return candidate


def returns_void(source: str) -> bool:
    signature = function_signature(source)
    return signature is not None and re.match(r"void\b", signature) is not None


def cast_count(source: str) -> int:
    return len(
        re.findall(
            r"\(\s*(?:const\s+)?(?:u?int(?:8|16|32|64)_t|uint|int|short|long|char|bool|float|double|byte|undefined[1248]?)\s*\*?\s*\)",
            source,
        )
    )


# The PowerPC/MIPS condition-register idiom Ventris currently spells out:
# a comparison encoded as `(x < 0) << 3 | (0 < x) << 2 | (x == 0) << 1 | ...`.
FLAG_EXPRESSION = re.compile(r"<<\s*3\s*\|[^;]{0,400}?<<\s*1\s*\|")


def widest_expression(source: str) -> int:
    return max((len(line.strip()) for line in source.splitlines()), default=0)


def classify(row: Row) -> None:
    """Assigns defect families to one function's Ventris/oracle pair."""
    if row.ventris_error is not None:
        row.findings.append(Finding("ventris-unsupported", row.ventris_error))
        return
    if row.oracle_error is not None:
        row.findings.append(Finding("oracle-unavailable", row.oracle_error))
        return
    assert row.ventris is not None and row.oracle is not None
    ours, theirs = row.ventris, row.oracle

    ours_control, theirs_control = control_profile(ours), control_profile(theirs)
    # A condition register materialized as arithmetic is the single most
    # destructive defect: it hides the comparison, so structuring cannot find
    # the loop or branch, and every use drags the whole chain along.
    flag_chains = len(FLAG_EXPRESSION.findall(ours))
    if flag_chains:
        row.findings.append(
            Finding("unreduced-flag-expression", f"{flag_chains} condition-register chains")
        )
    widest_ours = widest_expression(ours)
    widest_theirs = widest_expression(theirs)
    if widest_ours > max(120, widest_theirs * 3):
        row.findings.append(
            Finding("oversized-expression", f"{widest_ours} vs {widest_theirs} characters")
        )

    if ours_control["goto"] > theirs_control["goto"]:
        row.findings.append(
            Finding(
                "unstructured-control-flow",
                f"goto {ours_control['goto']} vs {theirs_control['goto']}",
            )
        )
    for token in ("for", "while", "do", "switch"):
        if theirs_control[token] > ours_control[token]:
            row.findings.append(
                Finding(
                    "missing-loop-or-switch",
                    f"{token} {ours_control[token]} vs {theirs_control[token]}",
                )
            )
    if theirs_control["if"] > ours_control["if"]:
        row.findings.append(
            Finding(
                "missing-conditional",
                f"if {ours_control['if']} vs {theirs_control['if']}",
            )
        )

    ours_calls = sum(
        count
        for name, count in call_names(ours).items()
        if name.startswith(("sub_", "func_0x", "FUN_"))
    )
    theirs_calls = sum(
        count
        for name, count in call_names(theirs).items()
        if name.startswith(("sub_", "func_0x", "FUN_"))
    )
    if ours_calls != theirs_calls:
        row.findings.append(Finding("call-census", f"{ours_calls} vs {theirs_calls}"))

    ours_void = returns_void(ours)
    theirs_void = returns_void(theirs)
    if ours_void != theirs_void:
        row.findings.append(
            Finding(
                "return-presence",
                f"ours {'void' if ours_void else 'value'} vs oracle "
                f"{'void' if theirs_void else 'value'}",
            )
        )

    ours_casts, theirs_casts = cast_count(ours), cast_count(theirs)
    if ours_casts > theirs_casts * 2 and ours_casts - theirs_casts >= 2:
        row.findings.append(Finding("excess-casts", f"{ours_casts} vs {theirs_casts}"))

    if re.search(r"\bunknown\b|\bu_[0-9a-f]+\b|\breg\b", ours):
        row.findings.append(Finding("unresolved-value", "renders an unnamed placeholder"))

    ours_params = len(re.findall(r"\barg\d+\b", ours))
    if ours_params == 0 and re.search(r"\bparam_\d+\b", theirs):
        row.findings.append(Finding("missing-parameters", "oracle recovers parameters, we do not"))

    if not row.findings:
        row.findings.append(Finding("agrees", "no classified difference"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-dir", required=True, type=Path)
    parser.add_argument("--ventris", required=True)
    parser.add_argument("--ghidra", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=4096)
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--reuse-oracle",
        action="store_true",
        help="skip Ghidra and reuse previously exported oracle files",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = read_manifest(args.ventris)
        entries = selected_entries(manifest, args.image_dir)
        if not entries:
            raise CensusError("no hash-verified corpus image is available")
        targets = targets_for(entries, args.image_dir)
        oracle_dir = args.out / "oracle"
        oracle_dir.mkdir(parents=True, exist_ok=True)
        if not args.reuse_oracle:
            for entry in entries:
                entry_targets = [t for t in targets if t.entry_id == entry["id"]]
                run_oracle(
                    args.ghidra, args.out / "project", oracle_dir, entry, entry_targets
                )

        rows = []
        for target in targets:
            row = Row(target=target)
            row.ventris, row.ventris_error = render_ventris(
                args.ventris, target, args.limit
            )
            exported = oracle_dir / f"{target.census_id}.ghidra-decompile"
            failed = oracle_dir / f"{target.census_id}.error"
            if exported.is_file():
                row.oracle = oracle_c(exported.read_text(encoding="utf-8"))
            elif failed.is_file():
                row.oracle_error = failed.read_text(encoding="utf-8").strip()
            else:
                row.oracle_error = "oracle was not exported"
            classify(row)
            rows.append(row)
    except (CensusError, corpus_smoke.SmokeError) as error:
        print(f"quality-census: FAIL {error}", file=sys.stderr)
        return 1

    # Count functions, not findings: a function that loses a `for` and a `while`
    # is one function to fix, and reporting two overstated the family's reach.
    families: Counter = Counter()
    for row in rows:
        for family in {finding.family for finding in row.findings}:
            families[family] += 1

    report = {
        "functions": len(rows),
        "entries": sorted({row.target.entry_id for row in rows}),
        "families": [
            {
                "family": family,
                "functions": count,
                "examples": [
                    f"{row.target.entry_id}/{row.target.name}: {finding.detail}"
                    for row in rows
                    for finding in row.findings
                    if finding.family == family
                ][:6],
            }
            for family, count in families.most_common()
        ],
        "rows": [
            {
                "entry": row.target.entry_id,
                "function": row.target.name,
                "address": row.target.address,
                "has_baseline": row.target.has_baseline,
                "findings": [
                    {"family": finding.family, "detail": finding.detail}
                    for finding in row.findings
                ],
            }
            for row in rows
        ],
    }
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    print(f"quality-census: {len(rows)} functions across {len(report['entries'])} images")
    for family in report["families"]:
        share = 100.0 * family["functions"] / len(rows)
        print(f"  {family['family']:26s} {family['functions']:3d} functions ({share:.0f}%)")
        for example in family["examples"][:3]:
            print(f"      {example}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
