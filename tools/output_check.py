"""Check that rendered C is structurally well formed, on every corpus function.

The quality census measures how close the output is to Ghidra's. This checks
something weaker but absolute: that the output is valid C at all. Ghidra never
emits a variable twice, a jump to a label it did not print, or a statement after
an unconditional return, so any of those is an equivalence failure regardless of
how the census classifies the function.

Each defect here has been real:

* a parameter shadowed by a local of the same name, from a variable group that
  holds the parameter and was declared a second time;
* one global-pointer base declared once per structure that reached it;
* a jump left behind after the block it named was proved unreachable and never
  printed;
* a live loop emitted after an unconditional return, from a block placed out of
  construct order.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

TARGETS = {
    "gamecube-animal-crossing-gafe01": ("animal_crossing_gafe01.dol", ["--target", "gamecube", "--loader", "dol"]),
    "ps2-dungeon-game": ("dungeon_game.elf", ["--target", "ps2"]),
    "n64-perfect-dark-ntsc-final": ("perfect_dark_ntsc_final.z64", ["--target", "n64"]),
}

DECLARATION = re.compile(r"^    ([A-Za-z_][\w ]*?[\w*])\s+(\w+);$")
GLOBAL = re.compile(r"^\w[\w ]*\*\s*(\w+);$", re.M)
SIGNATURE = re.compile(r"^\w[\w *]*\bsub_\w+\(([^)]*)\)", re.M)
LABEL = re.compile(r"^\s*(loc_\w+):", re.M)
RETURN = re.compile(r"^(\s*)return\b")


def declarations(source: str) -> list[str]:
    """Local declarations in the function body, by declared name."""
    found = []
    for line in source.splitlines():
        matched = DECLARATION.match(line)
        # `return x;` has the shape of a declaration; the keyword excludes it.
        if matched and matched.group(1).split()[-1] != "return":
            found.append(matched.group(2))
    return found


def parameters(source: str) -> list[str]:
    signature = SIGNATURE.search(source)
    if not signature or signature.group(1).strip() in ("", "void"):
        return []
    names = []
    for part in signature.group(1).split(","):
        words = part.replace("*", " ").split()
        if words:
            names.append(words[-1])
    return names


def defects(source: str) -> list[str]:
    found = []

    declared = declarations(source)
    shadowed = sorted(set(declared) & set(parameters(source)))
    if shadowed:
        found.append(f"a parameter is declared again as a local: {shadowed}")
    repeated = sorted({name for name in declared if declared.count(name) > 1})
    if repeated:
        found.append(f"a local is declared twice: {repeated}")

    globals_ = GLOBAL.findall(source)
    repeated_globals = sorted({name for name in globals_ if globals_.count(name) > 1})
    if repeated_globals:
        found.append(f"a global is declared twice: {repeated_globals}")

    named = set(re.findall(r"goto (\w+)", source))
    printed = set(LABEL.findall(source))
    if named - printed:
        found.append(f"a jump names a label that is never printed: {sorted(named - printed)}")

    if source.count("{") != source.count("}"):
        found.append("braces are unbalanced")

    # A value with no definition and no register name renders as a bare
    # `loc_<space>_<offset>` identifier. Ghidra declares such a value - it prints
    # `int unaff_r2;` for a register the function never writes - so referencing
    # one without declaring it does not compile.
    used = set(re.findall(r"\bloc_\d+_[0-9a-f]+\b", source))
    introduced = set(re.findall(r"^\s*\w[\w ]*\s(loc_\d+_[0-9a-f]+);$", source, re.M))
    if used - introduced:
        found.append(f"an identifier is used but never declared: {sorted(used - introduced)}")

    lines = source.splitlines()
    for index, line in enumerate(lines):
        matched = RETURN.match(line)
        if not matched:
            continue
        indent = len(matched.group(1))
        for following in lines[index + 1 :]:
            if not following.strip():
                continue
            depth = len(following) - len(following.lstrip())
            if depth == indent and not following.strip().startswith("}"):
                found.append(f"a statement follows a return: {following.strip()[:40]}")
            break
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ventris", required=True)
    parser.add_argument("--image-dir", required=True)
    parser.add_argument("--oracle-dir", required=True)
    parser.add_argument("--limit", type=int, default=4096)
    arguments = parser.parse_args()

    images = pathlib.Path(arguments.image_dir)
    scanned = 0
    failures: dict[str, list[str]] = {}
    for exported in sorted(pathlib.Path(arguments.oracle_dir).glob("*.ghidra-decompile")):
        text = exported.read_text(errors="replace")
        entry = re.search(r"^entry (\d+)$", text, re.M)
        if not entry:
            continue
        key = next((name for name in TARGETS if exported.stem.startswith(name)), None)
        if key is None:
            continue
        image, options = TARGETS[key]
        rendered = subprocess.run(
            [
                arguments.ventris,
                "decompile",
                str(images / image),
                hex(int(entry.group(1))),
                *options,
                "--limit",
                str(arguments.limit),
            ],
            capture_output=True,
            text=True,
        ).stdout
        scanned += 1
        found = defects(rendered)
        if found:
            failures[exported.stem] = found

    for name, found in sorted(failures.items()):
        for defect in found:
            print(f"output-check: {name}: {defect}")
    verdict = "PASS" if not failures else "FAIL"
    print(f"output-check: {verdict} ({scanned} functions, {len(failures)} defective)")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
