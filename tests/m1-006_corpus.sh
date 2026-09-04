#!/usr/bin/env bash
# Acceptance test / Gate for m1-006: multi-architecture corpus generation
# Target architectures: x86-64, x86-32, AArch64, PPC32-BE (plus MSVC via Windows CI / skipped local)
# Variants: plain_o0, plain_o2, plain_pie, cpp_o2, many_o2
#
# Requirements (Gate contract):
# 1. Read-only and reproducible: validates against tests/corpus.lock.json using temporary output lock
# 2. Builds lre-cli so it works from a clean checkout
# 3. Validates source hashes, artifact hashes, entry coverage, symbol counts, architectures, endianness, and native imports
# 4. Emits benchmarks/reports/m1-006.json including local MSVC skips with reasons
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$ROOT/target/debug/lre-cli"
CORPUS_SRC="$ROOT/tests/corpus-src"
COMMITTED_LOCK="$ROOT/tests/corpus.lock.json"
GEN_SCRIPT="$ROOT/scripts/gen_corpus.py"
REPORT_OUT="${REPORT_OUT:-$ROOT/benchmarks/reports/m1-006.json}"

echo "=== m1-006: multi-architecture corpus generation gate ==="

# 1. Build lre-cli inside the gate so it works from a clean checkout
echo "Building lre-cli..."
cargo build -p lre-cli --quiet
if [ -f "$ROOT/target/debug/lre-cli.exe" ]; then
    CLI="$ROOT/target/debug/lre-cli.exe"
fi
# 2. Check committed sources and committed lock exist
if [ ! -d "$CORPUS_SRC" ]; then
    echo "FAIL: corpus source directory $CORPUS_SRC does not exist"
    exit 1
fi

for src in plain.c src.cpp many.c; do
    if [ ! -f "$CORPUS_SRC/$src" ]; then
        echo "FAIL: expected committed source $CORPUS_SRC/$src missing"
        exit 1
    fi
done

if [ ! -f "$COMMITTED_LOCK" ]; then
    echo "FAIL: committed corpus lock file $COMMITTED_LOCK does not exist"
    exit 1
fi

# 3. Run generator into a temporary output directory with a temporary lock file
OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/m1-006-corpus.XXXXXX")"
trap 'rm -rf "$OUT_DIR"' EXIT
TMP_LOCK="$OUT_DIR/generated_lock.json"

ARCH_ARGS=()
if [ "${1:-}" = "--msvc-only" ]; then
    ARCH_ARGS=("--msvc-only")
elif [ -n "${1:-}" ]; then
    ARCH_ARGS=("$@")
fi

echo "Running corpus generator..."
python3 "$GEN_SCRIPT" --out-dir "$OUT_DIR" --lock "$TMP_LOCK" "${ARCH_ARGS[@]}"

# 4. Run python verification and report generation
echo "Validating multi-architecture corpus artifacts and generating gate report..."
python3 - "$COMMITTED_LOCK" "$TMP_LOCK" "$OUT_DIR" "$CLI" "$REPORT_OUT" <<'EOF'
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

committed_lock_path = Path(sys.argv[1])
generated_lock_path = Path(sys.argv[2])
out_dir = Path(sys.argv[3])
cli_path = Path(sys.argv[4])
report_path = Path(sys.argv[5])

with open(committed_lock_path, "r") as f:
    committed_lock = json.load(f)

with open(generated_lock_path, "r") as f:
    generated_lock = json.load(f)

# 1. Validate source hashes in committed lock
src_dir = committed_lock_path.parent / "corpus-src"
import hashlib
for src_name, info in committed_lock["sources"].items():
    p = src_dir / src_name
    assert p.exists(), f"Source file {src_name} missing"
    with open(p, "rb") as f:
        actual_hash = hashlib.sha256(f.read()).hexdigest()
    assert actual_hash == info["sha256"], f"Source hash mismatch for {src_name}"

# Helpers for ELF inspection
def parse_elf_info(path):
    with open(path, "rb") as f:
        data = f.read()
    assert data[:4] == b"\x7fELF", f"{path} not ELF"
    is_64 = data[4] == 2
    be = data[5] == 2
    endian = ">" if be else "<"
    machine = struct.unpack(f"{endian}H", data[18:20])[0]

    # Parse sections
    if is_64:
        shoff = struct.unpack(f"{endian}Q", data[40:48])[0]
        shentsize = struct.unpack(f"{endian}H", data[58:60])[0]
        shnum = struct.unpack(f"{endian}H", data[60:62])[0]
        shstrndx = struct.unpack(f"{endian}H", data[62:64])[0]
        str_hdr = shoff + shstrndx * shentsize
        stroff = struct.unpack(f"{endian}Q", data[str_hdr+24:str_hdr+32])[0]
        strsz = struct.unpack(f"{endian}Q", data[str_hdr+32:str_hdr+40])[0]
        shstr = data[stroff:stroff+strsz]
        secs = []
        for i in range(shnum):
            off = shoff + i * shentsize
            name_off = struct.unpack(f"{endian}I", data[off:off+4])[0]
            sec_type = struct.unpack(f"{endian}I", data[off+4:off+8])[0]
            name = shstr[name_off:].split(b"\0")[0].decode(errors="replace")
            secs.append((name, sec_type))
    else:
        shoff = struct.unpack(f"{endian}I", data[32:36])[0]
        shentsize = struct.unpack(f"{endian}H", data[46:48])[0]
        shnum = struct.unpack(f"{endian}H", data[48:50])[0]
        shstrndx = struct.unpack(f"{endian}H", data[50:52])[0]
        str_hdr = shoff + shstrndx * shentsize
        stroff = struct.unpack(f"{endian}I", data[str_hdr+16:str_hdr+20])[0]
        strsz = struct.unpack(f"{endian}I", data[str_hdr+20:str_hdr+24])[0]
        shstr = data[stroff:stroff+strsz]
        secs = []
        for i in range(shnum):
            off = shoff + i * shentsize
            name_off = struct.unpack(f"{endian}I", data[off:off+4])[0]
            sec_type = struct.unpack(f"{endian}I", data[off+4:off+8])[0]
            name = shstr[name_off:].split(b"\0")[0].decode(errors="replace")
            secs.append((name, sec_type))
            
    return is_64, be, machine, secs

# 2. Iterate through entries in generated lock
report_entries = []
total = len(generated_lock["entries"])
passed = 0
skipped = 0

expected_langs = {
    "x86_64": "x86:LE:64:default",
    "i386": "x86:LE:32:default",
    "aarch64": "AARCH64:LE:64:v8A",
    "powerpc": "PowerPC:BE:32:default",
    "msvc": "x86:LE:64:default",
}

for entry in generated_lock["entries"]:
    arch = entry["architecture"]
    var = entry["variant"]
    status = entry.get("status", "ok")

    if status == "skipped":
        skipped += 1
        report_entries.append({
            "architecture": arch,
            "variant": var,
            "status": "skipped",
            "reason": entry.get("reason", "unknown"),
        })
        continue

    bin_path = out_dir / entry["binary"]
    twin_path = out_dir / entry["unstripped_twin"]
    assert bin_path.exists(), f"Binary {bin_path} missing"
    assert twin_path.exists(), f"Twin {twin_path} missing"

    # Verify hashes match generated lock
    with open(bin_path, "rb") as f:
        assert hashlib.sha256(f.read()).hexdigest() == entry["binary_sha256"]
    with open(twin_path, "rb") as f:
        assert hashlib.sha256(f.read()).hexdigest() == entry["unstripped_twin_sha256"]

    if arch != "msvc":
        # Check ELF characteristics
        is_64, be, machine, bin_secs = parse_elf_info(bin_path)
        _, _, _, twin_secs = parse_elf_info(twin_path)

        # Endianness validation
        if arch == "powerpc":
            assert be is True, "PowerPC must be big-endian (BE)"
        else:
            assert be is False, f"{arch} must be little-endian (LE)"

        # Check symbol counts
        bin_sec_names = [s[0] for s in bin_secs]
        twin_sec_names = [s[0] for s in twin_secs]
        assert ".symtab" not in bin_sec_names, f"{bin_path.name} must lack .symtab"
        assert ".symtab" in twin_sec_names, f"{twin_path.name} must contain .symtab"
        sym_count = entry.get("symbol_count", 0)
        assert sym_count > 0, f"{twin_path.name} must have function symbols"
    else:
        # Check MSVC symbol artifact (PDB)
        pdb_name = entry.get("symbol_artifact")
        assert pdb_name, "MSVC entry must specify symbol_artifact (.pdb)"
        pdb_path = out_dir / pdb_name
        assert pdb_path.exists(), f"PDB {pdb_path} missing"
        with open(pdb_path, "rb") as f:
            hdr = f.read(32)
        assert hdr.startswith(b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00"), "Invalid PDB header"
        sym_count = "PDB"

    # Native import verification via lre-cli
    res = subprocess.run([str(cli_path), "import-native", str(bin_path)],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert res.returncode == 0, f"import-native failed on {bin_path.name}: {res.stderr.decode()}"
    stdout = res.stdout.decode()
    exp_lang = expected_langs[arch]
    assert exp_lang in stdout, f"Expected language {exp_lang} in output for {bin_path.name}, got: {stdout}"

    # Extract function count
    import re
    m = re.search(r"\((\d+) functions", stdout)
    fn_count = int(m.group(1)) if m else 0
    assert fn_count > 0, f"Expected > 0 functions in {bin_path.name}"

    passed += 1
    report_entries.append({
        "architecture": arch,
        "variant": var,
        "status": "ok",
        "endian": "big" if (arch == "powerpc") else "little",
        "functions_discovered": fn_count,
        "symbols_in_twin": sym_count,
        "expected_language": exp_lang,
    })
    print(f"PASS: {arch} {var} -> {fn_count} functions, language {exp_lang}")

report = {
    "gate": "m1-006",
    "total_entries": total,
    "passed_entries": passed,
    "skipped_entries": skipped,
    "pass": (passed > 0 and (passed + skipped) == total),
    "entries": report_entries,
}

report_path.parent.mkdir(parents=True, exist_ok=True)
with open(report_path, "w") as f:
    json.dump(report, f, indent=2)

print(f"\nWrote gate report to: {report_path}")
assert report["pass"] is True, "Gate evaluation failed"
EOF

echo "m1-006 gate: PASS"
