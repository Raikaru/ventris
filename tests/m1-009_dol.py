#!/usr/bin/env python3
"""m1-009: real main.dol mappings and exact-entry recall against matching boot.elf."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import sqlite3
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target/debug/lre-cli"
ORIG = Path.home() / "Projects/agent-under-fire/orig/GQFE78"
DOL_SHA = "2f082f5b7b3f060746ed28d3ee8970eec2e8613f97136733b2e374173e23d26b"
ORACLE_SHA = "29b2a3b48badbfef7b62542d14a0ca41f4bfc72a728bb4644c012bc69061446d"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dol", type=Path, default=ORIG / "sys/main.dol")
    parser.add_argument("--oracle", type=Path, default=ORIG / "files/boot.elf")
    parser.add_argument("--update-report", action="store_true")
    args = parser.parse_args()
    subprocess.run(["cargo", "build", "-q", "-p", "lre-cli"], cwd=ROOT, check=True)
    row = {"id": "GQFE78-main-dol", "sha256": None, "status": "skipped",
           "metrics": {}, "thresholds": {"fn.recall": 0.95}, "runs": 1}
    with tempfile.TemporaryDirectory(prefix="m1-009-") as temporary:
        work = Path(temporary)
        try:
            dol, elf = args.dol.read_bytes(), args.oracle.read_bytes()
            row["sha256"] = hashlib.sha256(dol).hexdigest()
            row["oracle_sha256"] = hashlib.sha256(elf).hexdigest()
            row["oracle"] = "GQFE78/files/boot.elf"
            assert row["sha256"] == DOL_SHA and row["oracle_sha256"] == ORACLE_SHA, "Required input/oracle hash mismatch"
            assert elf[:6] == b"\x7fELF\x01\x02", "Oracle must be ELF32 big endian"
            sections = []
            for i in range(18):
                offset, address, size = (struct.unpack_from(">I", dol, base + 4*i)[0] for base in (0, 0x48, 0x90))
                if size:
                    assert offset + size <= len(dol)
                    sections.append((i, offset, address, size))

            def dol_bytes_at(address, size):
                for _, offset, start, span in sections:
                    if start <= address and address + size <= start + span:
                        return dol[offset + address - start:offset + address - start + size]
                return None

            shoff = struct.unpack_from(">I", elf, 32)[0]
            entsize, count = struct.unpack_from(">HH", elf, 46)
            elf_sections = [struct.unpack_from(">10I", elf, shoff + i*entsize) for i in range(count)]
            oracle = set()
            for section in elf_sections:
                if section[2] & 2 and section[1] != 8 and section[5]:
                    assert elf[section[4]:section[4]+section[5]] == dol_bytes_at(section[3], section[5]), "Oracle allocated bytes do not match DOL at original addresses"
                if section[1] != 2:
                    continue
                for off in range(section[4], section[4]+section[5], section[9]):
                    _, address, size, info, _, index = struct.unpack_from(">IIIBBH", elf, off)
                    if info & 15 == 2 and index and address:
                        assert any(i < 7 and start <= address < start + span for i, _, start, span in sections)
                        code = elf_sections[index]
                        begin = code[4] + address - code[3]
                        assert elf[begin:begin+size] == dol_bytes_at(address, size), "Function oracle is not byte/address identical"
                        oracle.add(address)
            assert oracle, "Symbol oracle is empty"
            row["oracle_functions"] = len(oracle)
            console = Path(os.environ.get("VENTRIS_CONSOLE", ROOT / "native/build/decomp_native"))
            if not console.is_file():
                raise FileNotFoundError(f"Required SLEIGH console missing: {console}")
            # Import only the stripped DOL. Oracle addresses/names never reach the importer.
            imported = subprocess.run([str(CLI), "import-native", str(args.dol), "--name", "dol",
                                       "--project", str(work / "project")], capture_output=True, text=True, timeout=600)
            assert imported.returncode == 0, imported.stdout + imported.stderr
            with sqlite3.connect(work / "project/project.sqlite") as db:
                native = {int(r[0], 16) for r in db.execute("SELECT entry FROM functions WHERE program_id=(SELECT id FROM programs WHERE name='dol')")}
            matched = native & oracle
            row["native_functions"] = len(native)
            row["matched_functions"] = len(matched)
            row["metrics"] = {"fn.recall": len(matched)/len(oracle),
                              "fn.precision": len(matched)/len(native) if native else 0.0}
            row["missing_entries"] = [f"{a:08x}" for a in sorted(oracle-native)]
            # Verify sparse file offsets and BSS zero fill through the consumer memory API.
            def memory(binary, address, size):
                result = subprocess.run([str(CLI), "mem", str(binary), f"{address:x}", str(size),
                                         "--project", str(work / "memory")], capture_output=True, text=True, timeout=30)
                assert result.returncode == 0, result.stderr
                return bytes.fromhex(result.stdout)

            for _, offset, address, size in sections:
                assert memory(args.dol, address, min(size, 32)) == dol[offset:offset+min(size, 32)]
                assert memory(args.dol, address+size-16, 16) == dol[offset+size-16:offset+size]
            bss, bss_size = struct.unpack_from(">II", dol, 0xd8)
            assert memory(args.dol, bss, 32) == bytes(32)
            assert memory(args.dol, bss+bss_size-16, 16) == bytes(16)
            row["mapped_sections_checked"] = len(sections)
            row["bss_zero_fill_checked"] = True
            for label, offset, value in (("file_bounds", 0, len(dol)),
                                         ("address_wrap", 0x48, 0xfffffff0),
                                         ("section_overlap", 0x4c, sections[0][2])):
                bad = bytearray(dol)
                struct.pack_into(">I", bad, offset, value)
                malformed = work / f"{label}.dol"
                malformed.write_bytes(bad)
                result = subprocess.run([str(CLI), "mem", str(malformed), f"{bss:x}", "4",
                                         "--project", str(work / "invalid")], capture_output=True, text=True, timeout=30)
                assert result.returncode != 0, f"Accepted invalid DOL: {label}"
            assert row["metrics"]["fn.recall"] >= 0.95, f"Recall {len(matched)}/{len(oracle)} is below 0.95"
            row["status"] = "pass"
        except (OSError, subprocess.SubprocessError) as error:
            row["reason"] = str(error)
        except (AssertionError, ValueError, struct.error, sqlite3.Error) as error:
            row.update(status="fail", error=str(error))
        report = {"gate": "m1-009", "milestone": "M1",
                  "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                  "date": datetime.now(timezone.utc).date().isoformat(),
                  "machine": {"os": platform.platform(), "cpu": platform.machine(),
                              "ram_gb": round(os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") / 2**30, 2)},
                  "corpus": [row], "summary": {s: int(row["status"] == s) for s in ("pass", "fail", "skipped")},
                  "passed": row["status"] == "pass"}
        destination = ROOT / "benchmarks/reports/m1-009.json" if args.update_report else work / "report.json"
        destination.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
        return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
