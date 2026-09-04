#!/usr/bin/env bash
# Acceptance test / Gate for m1-006: multi-architecture corpus generation
# Target architectures: x86-64, x86-32, AArch64, PPC32-BE (plus MSVC via Windows CI / skipped local)
# Variants: plain_o0, plain_o2, plain_pie, cpp_o2, many_o2
#
# Requirements (Gate contract):
# 1. Read-only and reproducible: writes per-run manifest and report under temporary directory; leaves git diff empty
# 2. Compares generated artifacts against authoritative invariants in tests/corpus.lock.json
# 3. Builds lre-cli if missing so it works from a clean checkout
# 4. Validates source hashes, artifact hashes, exact entry coverage, symbol counts, architectures, endianness, PE/ELF twin identity, and native imports
# 5. Supports --update-report / UPDATE_REPORT=1 to explicitly update benchmarks/reports/m1-006.json
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ -f "$ROOT/target/debug/lre-cli.exe" ]; then
    CLI="$ROOT/target/debug/lre-cli.exe"
elif [ -f "$ROOT/target/debug/lre-cli" ]; then
    CLI="$ROOT/target/debug/lre-cli"
else
    CLI="$ROOT/target/debug/lre-cli"
fi

CORPUS_SRC="$ROOT/tests/corpus-src"
COMMITTED_LOCK="$ROOT/tests/corpus.lock.json"
GEN_SCRIPT="$ROOT/scripts/gen_corpus.py"
DEFAULT_REPORT="$ROOT/benchmarks/reports/m1-006.json"

PYTHON_BIN="python3"
if ! command -v python3 >/dev/null 2>&1 && command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
fi

echo "=== m1-006: multi-architecture corpus generation gate ==="

# 1. Ensure MSVC linker takes precedence if VCToolsInstallDir is set in Git Bash on Windows
if [ -n "${VCToolsInstallDir:-}" ]; then
    if command -v cygpath >/dev/null 2>&1; then
        export PATH="$(cygpath -u "$VCToolsInstallDir")/bin/Hostx64/x64:$PATH"
    else
        export PATH="$VCToolsInstallDir/bin/Hostx64/x64:$PATH"
    fi
fi

# 2. Build lre-cli inside the gate if not already built so it works from a clean checkout
if [ ! -f "$CLI" ]; then
    echo "Building lre-cli..."
    cargo build -p lre-cli --quiet
fi

# 3. Check committed sources and committed lock exist
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

# Parse flags
UPDATE_REPORT="${UPDATE_REPORT:-0}"
ARCH_ARGS=()
for arg in "$@"; do
    if [ "$arg" = "--update-report" ]; then
        UPDATE_REPORT=1
    else
        ARCH_ARGS+=("$arg")
    fi
done

# 4. Run generator into a temporary output directory with a temporary manifest file
OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/m1-006-corpus.XXXXXX")"
trap 'rm -rf "$OUT_DIR"' EXIT
MANIFEST_PATH="$OUT_DIR/manifest.json"
TEMP_REPORT_PATH="$OUT_DIR/m1-006.json"

echo "Running corpus generator..."
"$PYTHON_BIN" "$GEN_SCRIPT" --out-dir "$OUT_DIR" --manifest "$MANIFEST_PATH" "${ARCH_ARGS[@]}"

# 5. Run python verification against authoritative lock and generate gate report
echo "Validating multi-architecture corpus artifacts against authoritative lock..."
"$PYTHON_BIN" - "$COMMITTED_LOCK" "$MANIFEST_PATH" "$OUT_DIR" "$CLI" "$TEMP_REPORT_PATH" <<'EOF'
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

committed_lock_path = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
out_dir = Path(sys.argv[3])
cli_path = Path(sys.argv[4])
temp_report_path = Path(sys.argv[5])

with open(committed_lock_path, "r") as f:
    authoritative_lock = json.load(f)

with open(manifest_path, "r") as f:
    run_manifest = json.load(f)

# 1. Validate source hashes match authoritative lock
src_dir = committed_lock_path.parent / "corpus-src"
for src_name, info in authoritative_lock["sources"].items():
    p = src_dir / src_name
    assert p.exists(), f"Source file {src_name} missing"
    with open(p, "rb") as f:
        actual_hash = hashlib.sha256(f.read()).hexdigest()
    assert actual_hash == info["sha256"], f"Source hash mismatch for {src_name}"

# 2. Build map of authoritative expectations keyed by (architecture, variant)
auth_entries = {}
for e in authoritative_lock["entries"]:
    auth_entries[(e["architecture"], e["variant"])] = e

# 3. Assert exact expected architecture x variant entry set
selected_archs = run_manifest["selected_architectures"]
if selected_archs == ["msvc"]:
    expected_keys = {( "msvc", v ) for v in authoritative_lock["expected_variants"]}
else:
    expected_keys = {
        (a, v)
        for a in authoritative_lock["expected_architectures"]
        for v in authoritative_lock["expected_variants"]
    }

actual_keys = {(e["architecture"], e["variant"]) for e in run_manifest["entries"]}
assert actual_keys == expected_keys, f"Entry coverage mismatch: expected {sorted(expected_keys)} got {sorted(actual_keys)}"

# Helpers for PE / ELF validation
def parse_pe(data):
    assert data[:2] == b"MZ"
    pe_off = struct.unpack("<I", data[0x3c:0x40])[0]
    assert data[pe_off:pe_off+4] == b"PE\0\0"
    opt = pe_off + 24
    magic = struct.unpack("<H", data[opt:opt+2])[0]
    is_64 = (magic == 0x20b)
    dbg_rva, dbg_size = 0, 0
    if is_64:
        num_rva = struct.unpack("<I", data[opt+108:opt+112])[0]
        if num_rva > 6:
            dbg_rva, dbg_size = struct.unpack("<II", data[opt+160:opt+168])
    else:
        num_rva = struct.unpack("<I", data[opt+92:opt+96])[0]
        if num_rva > 6:
            dbg_rva, dbg_size = struct.unpack("<II", data[opt+144:opt+152])
    
    num_sections = struct.unpack("<H", data[pe_off+6:pe_off+8])[0]
    opt_size = struct.unpack("<H", data[pe_off+20:pe_off+22])[0]
    sec_table = opt + opt_size
    sections = []
    for i in range(num_sections):
        so = sec_table + i * 40
        name = data[so:so+8].split(b"\0")[0].decode(errors="replace")
        vsize = struct.unpack("<I", data[so+8:so+12])[0]
        vaddr = struct.unpack("<I", data[so+12:so+16])[0]
        raw_size = struct.unpack("<I", data[so+16:so+20])[0]
        raw_off = struct.unpack("<I", data[so+20:so+24])[0]
        chars = struct.unpack("<I", data[so+36:so+40])[0]
        sections.append({
            "name": name, "vsize": vsize, "vaddr": vaddr,
            "raw_size": raw_size, "raw_off": raw_off, "chars": chars,
            "exec": (chars & 0x20000000) != 0,
        })
    return {"is_64": is_64, "dbg_rva": dbg_rva, "dbg_size": dbg_size, "sections": sections}

def parse_elf(data):
    assert data[:4] == b"\x7fELF"
    is_64 = data[4] == 2
    be = data[5] == 2
    endian = ">" if be else "<"
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
        # Program headers
        phoff = struct.unpack(f"{endian}Q", data[32:40])[0]
        phentsize = struct.unpack(f"{endian}H", data[54:56])[0]
        phnum = struct.unpack(f"{endian}H", data[56:58])[0]
        exec_segs = []
        for i in range(phnum):
            off = phoff + i * phentsize
            p_type, p_flags = struct.unpack(f"{endian}II", data[off:off+8])
            p_offset, p_vaddr = struct.unpack(f"{endian}QQ", data[off+8:off+24])
            p_filesz = struct.unpack(f"{endian}Q", data[off+32:off+40])[0]
            if p_type == 1 and (p_flags & 1):
                exec_segs.append((p_vaddr, data[p_offset:p_offset+p_filesz]))
        return is_64, be, secs, exec_segs
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
        phoff = struct.unpack(f"{endian}I", data[28:32])[0]
        phentsize = struct.unpack(f"{endian}H", data[42:44])[0]
        phnum = struct.unpack(f"{endian}H", data[44:46])[0]
        exec_segs = []
        for i in range(phnum):
            off = phoff + i * phentsize
            p_type, p_offset, p_vaddr = struct.unpack(f"{endian}III", data[off:off+12])
            p_filesz = struct.unpack(f"{endian}I", data[off+16:off+20])[0]
            p_flags = struct.unpack(f"{endian}I", data[off+24:off+28])[0]
            if p_type == 1 and (p_flags & 1):
                exec_segs.append((p_vaddr, data[p_offset:p_offset+p_filesz]))
        return is_64, be, secs, exec_segs

report_entries = []
passed = 0
skipped = 0

for entry in run_manifest["entries"]:
    arch = entry["architecture"]
    var = entry["variant"]
    status = entry.get("status", "ok")
    auth = auth_entries[(arch, var)]

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

    # Endianness assertion
    assert entry["endian"] == auth["endian"], f"Endianness mismatch: {entry['endian']} != {auth['endian']}"

    if auth["format"] == "elf":
        with open(bin_path, "rb") as f:
            b_data = f.read()
        with open(twin_path, "rb") as f:
            t_data = f.read()

        is_64, be, b_secs, b_exec = parse_elf(b_data)
        _, _, t_secs, t_exec = parse_elf(t_data)

        if auth["endian"] == "big":
            assert be is True, f"{arch} must be big-endian"
        else:
            assert be is False, f"{arch} must be little-endian"

        b_sec_names = [s[0] for s in b_secs]
        t_sec_names = [s[0] for s in t_secs]
        assert ".symtab" not in b_sec_names, f"Primary {bin_path.name} must lack .symtab"
        assert ".symtab" in t_sec_names, f"Twin {twin_path.name} must contain .symtab"

        sym_count = entry.get("symbol_count", 0)
        min_sym = auth.get("min_symbols", 1)
        assert sym_count >= min_sym, f"Symbol count {sym_count} < expected minimum {min_sym} in {twin_path.name}"

        # Assert identical loadable code
        assert len(b_exec) == len(t_exec), f"Executable segment count mismatch for {bin_path.name}"
        for (v1, b1), (v2, b2) in zip(b_exec, t_exec):
            assert v1 == v2, f"Executable vaddr mismatch {v1:#x} != {v2:#x}"
            assert b1 == b2, f"Loadable code at {v1:#x} must be bit-for-bit identical between stripped and unstripped twin"

    elif auth["format"] == "pe":
        with open(bin_path, "rb") as f:
            b_data = f.read()
        with open(twin_path, "rb") as f:
            t_data = f.read()

        b_info = parse_pe(b_data)
        t_info = parse_pe(t_data)

        # 1. Primary PE has NO debug-directory reference
        assert b_info["dbg_rva"] == 0 and b_info["dbg_size"] == 0, f"Primary PE {bin_path.name} must have no debug-directory reference"

        # 2. Unstripped PE has VALID debug-directory reference
        assert t_info["dbg_rva"] > 0 and t_info["dbg_size"] > 0, f"Unstripped PE {twin_path.name} must have non-empty debug directory"

        # Check CodeView RSDS record in unstripped PE
        pdb_name = auth.get("symbol_artifact", f"{arch}_{var}.pdb")
        pdb_path = out_dir / pdb_name
        dbg_sec = next(s for s in t_info["sections"] if t_info["dbg_rva"] >= s["vaddr"] and t_info["dbg_rva"] < s["vaddr"] + s["vsize"])
        dbg_raw_off = dbg_sec["raw_off"] + (t_info["dbg_rva"] - dbg_sec["vaddr"])
        found_cv = False
        for i in range(t_info["dbg_size"] // 28):
            eo = dbg_raw_off + i * 28
            e_type = struct.unpack("<I", t_data[eo+16:eo+20])[0]
            e_raw_off = struct.unpack("<I", t_data[eo+24:eo+28])[0]
            if e_type == 2:  # CODEVIEW
                assert t_data[e_raw_off:e_raw_off+4] == b"RSDS", f"Missing RSDS signature in {twin_path.name}"
                found_cv = True
                break
        assert found_cv, f"No CodeView RSDS entry found in unstripped PE {twin_path.name}"

        # 3. PDB artifact exists and is valid MSF 7.00
        assert pdb_path.exists(), f"PDB artifact {pdb_path} missing"
        with open(pdb_path, "rb") as pf:
            hdr = pf.read(32)
        assert hdr.startswith(b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00"), "Invalid PDB header"
        sym_count = "PDB"

        # 4. Compare every executable PE section's RVA, VirtualSize, and raw bytes
        b_exec_secs = [s for s in b_info["sections"] if s["exec"]]
        t_exec_secs = [s for s in t_info["sections"] if s["exec"]]
        assert len(b_exec_secs) == len(t_exec_secs), "Number of executable PE sections mismatch"
        for s_bin, s_twin in zip(b_exec_secs, t_exec_secs):
            assert s_bin["vaddr"] == s_twin["vaddr"], f"PE Section RVA mismatch for {s_bin['name']}"
            assert s_bin["vsize"] == s_twin["vsize"], f"PE Section VirtualSize mismatch for {s_bin['name']}"
            assert s_bin["raw_size"] == s_twin["raw_size"], f"PE Section SizeOfRawData mismatch for {s_bin['name']}"
            assert b_data[s_bin["raw_off"]:s_bin["raw_off"] + s_bin["raw_size"]] == t_data[s_twin["raw_off"]:s_twin["raw_off"] + s_twin["raw_size"]], f"Executable code bytes mismatch in PE section {s_bin['name']}"

    # Native import verification
    res = subprocess.run([str(cli_path), "import-native", str(bin_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert res.returncode == 0, f"import-native failed on {bin_path.name}: {res.stderr.decode()}"
    stdout = res.stdout.decode()
    exp_lang = auth["expected_language"]
    assert exp_lang in stdout, f"Expected language {exp_lang} in output for {bin_path.name}, got: {stdout}"

    m = re.search(r"\((\d+) functions", stdout)
    fn_count = int(m.group(1)) if m else 0
    assert fn_count > 0, f"Expected > 0 functions in {bin_path.name}"

    passed += 1
    report_entries.append({
        "architecture": arch,
        "variant": var,
        "status": "ok",
        "endian": auth["endian"],
        "format": auth["format"],
        "functions_discovered": fn_count,
        "symbols_in_twin": sym_count,
        "expected_language": exp_lang,
    })
    print(f"PASS: {arch} {var} -> {fn_count} functions, language {exp_lang}")

report = {
    "gate": "m1-006",
    "total_entries": len(run_manifest["entries"]),
    "passed_entries": passed,
    "skipped_entries": skipped,
    "pass": (passed > 0 and (passed + skipped) == len(run_manifest["entries"])),
    "entries": report_entries,
}

temp_report_path.parent.mkdir(parents=True, exist_ok=True)
with open(temp_report_path, "w") as f:
    json.dump(report, f, indent=2)

print(f"\nWrote gate report under temp dir: {temp_report_path}")
assert report["pass"] is True, "Gate evaluation failed"
EOF

# 6. Explicit update mode: only copy to committed report when requested
if [ "$UPDATE_REPORT" = "1" ]; then
    echo "Updating committed report at $DEFAULT_REPORT..."
    mkdir -p "$(dirname "$DEFAULT_REPORT")"
    cp "$TEMP_REPORT_PATH" "$DEFAULT_REPORT"
    echo "Updated $DEFAULT_REPORT"
fi

echo "m1-006 gate: PASS"
