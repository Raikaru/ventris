#!/usr/bin/env python3
"""Generate or check the README support matrix from committed gate files.

Usage:
    python scripts/gen_support_matrix.py          # Updates README.md in-place
    python scripts/gen_support_matrix.py --check  # Fails if README matrix is stale
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
REPORTS_DIR = ROOT / "benchmarks" / "reports"


def load_json(path: Path) -> dict | list | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def generate_matrix() -> str:
    # Read available gate files
    stage4 = load_json(REPORTS_DIR / "stage4-gate.json")
    ui_gate = load_json(REPORTS_DIR / "ui-gate.json")
    discovery_gate = load_json(REPORTS_DIR / "discovery-gate.json")
    parity_gate = load_json(REPORTS_DIR / "parity-gate.json")

    # x86-64 ELF is verified if stage4 or ui_gate passed
    elf_x86_gated = bool(
        (stage4 and stage4.get("functional_pass"))
        or (ui_gate and ui_gate.get("passed"))
    )

    # PE32+ x86-64 is verified by native test suite / stage4
    pe_x86_gated = bool(stage4 and stage4.get("functional_pass"))

    # Generic architectures (M1/M2 gates)
    aarch64_status = "selected SLEIGH bundle required; not parity-gated"
    arm_status = "selected SLEIGH bundle required; not parity-gated"
    mips_status = "selected SLEIGH bundle required; not parity-gated"
    riscv_status = "selected SLEIGH bundle required; not parity-gated"
    ppc_status = (
        "e500 BE32 parity verified on Agent Under Fire; broader targets not gated"
    )

    if parity_gate and parity_gate.get("passed"):
        aarch64_status = "**supported and gated**"
        arm_status = "**supported and gated**"
        mips_status = "**supported and gated**"
        riscv_status = "**supported and gated**"
        ppc_status = "**supported and gated**"
    elif discovery_gate and discovery_gate.get("passed"):
        aarch64_status = "discovery gated; decompile parity pending"
        arm_status = "discovery gated; decompile parity pending"
        mips_status = "discovery gated; decompile parity pending"
        riscv_status = "discovery gated; decompile parity pending"
        ppc_status = "e500 verified; discovery gated; broader parity pending"

    rows = [
        (
            "ELF x86-64",
            "supported",
            "**supported and gated**" if elf_x86_gated else "in progress",
        ),
        (
            "PE32+ x86-64",
            "supported",
            "**supported and gated**" if pe_x86_gated else "in progress",
        ),
        ("ELF AARCH64 LE64", "supported", aarch64_status),
        ("ELF ARM LE32", "supported", arm_status),
        ("ELF MIPS LE32", "supported", mips_status),
        ("ELF RISC-V LE64", "supported", riscv_status),
        ("ELF PowerPC LE32/LE64", "supported", ppc_status),
    ]

    header = [
        "| Input | Structural native import | Native flow/decode/decompile |",
        "|---|---|---|",
    ]
    table_lines = header + [f"| {r[0]} | {r[1]} | {r[2]} |" for r in rows]
    return "\n".join(table_lines)


def update_readme(check: bool) -> bool:
    if not README.is_file():
        raise FileNotFoundError(f"README not found at {README}")

    content = README.read_text(encoding="utf-8")
    generated_table = generate_matrix()

    pattern = re.compile(
        r"(## Support matrix\n\n)(?:\|[^\n]+\n)+",
        re.MULTILINE,
    )
    match = pattern.search(content)
    if not match:
        raise ValueError("Could not find '## Support matrix' section in README.md")

    expected_section = match.group(1) + generated_table + "\n"
    current_section = match.group(0)

    if current_section.strip() != (match.group(1) + generated_table).strip():
        if check:
            print("Support matrix in README.md is stale!", file=sys.stderr)
            print("Run 'python scripts/gen_support_matrix.py' to regenerate it.", file=sys.stderr)
            return False
        # Replace in place
        new_content = pattern.sub(expected_section, content)
        README.write_text(new_content, encoding="utf-8")
        print("Updated README.md support matrix successfully.")
        return True

    if check:
        print("Support matrix in README.md is up to date.")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check if README matrix is up to date without modifying",
    )
    args = parser.parse_args()

    ok = update_readme(check=args.check)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
