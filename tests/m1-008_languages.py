#!/usr/bin/env python3
"""m1-008: native imports select the pinned ELF32/PE32 language definitions."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import struct
import subprocess
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target/debug/lre-cli"
# Temporary compiler probes do not add entries to the committed corpus matrix.
CASES = [
    ("elf32_i386", "i386-none-elf", [], "x86:LE:32:default", "little", False),
    ("elf32_arm_le", "arm-none-eabi", ["-march=armv7-a"], "ARM:LE:32:v7", "little", False),
    ("elf32_arm_be32", "armeb-none-eabi", ["-march=armv5t"], "ARM:BE:32:v7", "big", False),
    ("elf32_arm_be8", "armeb-none-eabi", ["-march=armv7-a"], "ARM:LEBE:32:v7LEInstruction", "big", True),
    ("pe32_i386", None, [], "x86:LE:32:default", "little", False),
    ("elf64_control", "x86_64-none-elf", [], "x86:LE:64:default", "little", False),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update-report", action="store_true")
    args = parser.parse_args()
    install = Path(os.environ.get("VENTRIS_GHIDRA", Path.home() / "ghidra_12.1.3_PUBLIC"))
    subprocess.run(["cargo", "build", "-q", "-p", "lre-cli"], cwd=ROOT, check=True)
    rows = []
    with tempfile.TemporaryDirectory(prefix="m1-008-") as temporary:
        work = Path(temporary)
        source = work / "entry.c"
        source.write_text("volatile unsigned int word = 0x12345678;\nint entry(void) { return word + 42; }\n")
        for name, target, flags, expected, endian, be8 in CASES:
            row = {"id": name, "sha256": None, "status": "skipped",
                   "metrics": {}, "thresholds": {}, "runs": 1,
                   "expected_language": expected}
            try:
                binary = work / f"{name}.elf" if target else ROOT / "tests/fixtures-src/tiny_pe32.exe"
                if target:
                    subprocess.run(["clang", f"--target={target}", *flags, "-fuse-ld=lld",
                                    "-nostdlib", "-Wl,-e,entry", str(source), "-o", str(binary)],
                                   check=True, capture_output=True, text=True)
                if not binary.is_file():
                    raise FileNotFoundError(f"Required binary missing: {binary}")
                data = binary.read_bytes()
                row["sha256"] = hashlib.sha256(data).hexdigest()
                bits = 64 if name == "elf64_control" else 32
                if target:
                    assert data[:4] == b"\x7fELF" and data[4] == (2 if bits == 64 else 1)
                    assert data[5] == (2 if endian == "big" else 1)
                    if "arm" in name:
                        order = ">" if endian == "big" else "<"
                        assert struct.unpack_from(order + "H", data, 18)[0] == 40
                        elf_flags = struct.unpack_from(order + "I", data, 36)[0]
                        assert bool(elf_flags & 0x00800000) == be8, "Compiler did not produce requested ARM encoding"
                        row["elf_flags"] = f"0x{elf_flags:08x}"
                else:
                    pe = struct.unpack_from("<I", data, 0x3c)[0]
                    assert data[pe:pe + 4] == b"PE\0\0"
                    assert struct.unpack_from("<H", data, pe + 4)[0] == 0x14c
                    assert struct.unpack_from("<H", data, pe + 24)[0] == 0x10b
                processor = "ARM" if "arm" in name else "x86"
                directory = install / "Ghidra/Processors" / processor / "data/languages"
                definitions = ET.parse(directory / f"{processor}.ldefs").getroot()
                definition = next((node for node in definitions.findall("language")
                                   if node.get("id") == expected), None)
                assert definition is not None, f"Pinned .ldefs entry missing: {expected}"
                assert definition.get("endian") == endian and definition.get("size") == str(bits)
                assert definition.get("instructionEndian", endian) == ("little" if be8 else endian)
                assert (directory / definition.attrib["slafile"]).is_file(), "Compiled language missing"
                project = work / name
                result = subprocess.run([str(CLI), "import-native", str(binary), "--name", name,
                                         "--project", str(project)], capture_output=True, text=True, timeout=60)
                assert result.returncode == 0, result.stdout + result.stderr
                selected = re.search(r"\(\d+ functions, ([^)]+)\)", result.stdout)
                assert selected, f"Missing import summary: {result.stdout}"
                row["selected_language"] = selected.group(1)
                assert selected.group(1) == expected, f"Expected {expected}, selected {selected.group(1)}"
                catalog = subprocess.run([str(CLI), "architectures", "--project", str(project)],
                                         capture_output=True, text=True, check=True, timeout=60)
                assert any(line.split("\t")[:4] == [expected, processor, endian, str(bits)]
                           for line in catalog.stdout.splitlines()), "Selected language absent from native catalog"
                row["status"] = "pass"
                row["slafile"] = definition.attrib["slafile"]
            except (OSError, subprocess.SubprocessError, ET.ParseError) as error:
                row["reason"] = str(error)
            except AssertionError as error:
                row.update(status="fail", error=str(error))
            rows.append(row)
            print(f"{row['status'].upper()} {name}: {row.get('error', row.get('reason', expected))}", flush=True)
        summary = {status: sum(row["status"] == status for row in rows)
                   for status in ("pass", "fail", "skipped")}
        report = {"gate": "m1-008", "milestone": "M1",
                  "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                  "date": datetime.now(timezone.utc).date().isoformat(),
                  "machine": {"os": platform.platform(), "cpu": platform.machine(),
                              "ram_gb": round(os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") / 2**30, 2)},
                  "corpus": rows, "summary": summary, "passed": summary["pass"] == len(CASES)}
        report_path = ROOT / "benchmarks/reports/m1-008.json" if args.update_report else work / "report.json"
        report_path.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"summary": summary, "passed": report["passed"]}))
        return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
