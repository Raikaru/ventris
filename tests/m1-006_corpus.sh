#!/usr/bin/env bash
# Acceptance test / Gate for m1-006: multi-architecture corpus generation
# Target architectures: x86-64, x86-32, AArch64, PPC32-BE (plus MSVC via Windows CI / skipped local)
# Variants: plain_o0, plain_o2, plain_pie, cpp_o2, many_o2
#
# Requirements (Gate contract):
# 1. Read-only and reproducible: writes per-run manifest and report under temporary directory; leaves git diff empty
# 2. Compares generated artifacts against authoritative invariants in tests/corpus.lock.json
# 3. Rebuilds lre-cli so the gate exercises current sources, even with a populated target directory
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

# Build current sources, independent of the caller's working directory.
cargo build --manifest-path "$ROOT/Cargo.toml" -p lre-cli --quiet
if [ -f "$ROOT/target/debug/lre-cli.exe" ]; then
    CLI="$ROOT/target/debug/lre-cli.exe"
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
MODE=normal
for arg in "$@"; do
    case "$arg" in
        --update-report) UPDATE_REPORT=1 ;;
        --msvc-only) MODE=msvc; ARCH_ARGS=(--msvc-only) ;;
        *) echo "Unsupported gate argument: $arg" >&2; exit 2 ;;
    esac
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
"$PYTHON_BIN" - "$COMMITTED_LOCK" "$MANIFEST_PATH" "$OUT_DIR" "$CLI" "$TEMP_REPORT_PATH" "$MODE" <<'EOF'
import hashlib
import json
import os
import re
import struct
import shutil
import subprocess
import sys
from pathlib import Path

committed_lock_path = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
out_dir = Path(sys.argv[3])
cli_path = Path(sys.argv[4])
temp_report_path = Path(sys.argv[5])
mode = sys.argv[6]
assert mode in ("normal", "msvc"), "Invalid gate mode"
sys.dont_write_bytecode = True
sys.path.insert(0, str(committed_lock_path.parent.parent / "scripts"))
from gen_corpus import count_symtab_functions, validate_pe_twin

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
    assert p.stat().st_size == info["size"], f"Source size mismatch for {src_name}"
assert run_manifest["sources"] == authoritative_lock["sources"], "Source manifest mismatch"

# 2. Build map of authoritative expectations keyed by (architecture, variant)
auth_entries = {}
for e in authoritative_lock["entries"]:
    key = (e["architecture"], e["variant"])
    assert key not in auth_entries, f"Duplicate lock entry: {key}"
    auth_entries[key] = e
lock_keys = {(a, v) for a in authoritative_lock["expected_architectures"]
             for v in authoritative_lock["expected_variants"]}
assert set(auth_entries) == lock_keys, "Lock matrix is incomplete"

# Gate mode comes from the invocation, never from untrusted manifest metadata.
selected_archs = ["msvc"] if mode == "msvc" else authoritative_lock["expected_architectures"]
assert run_manifest["selected_architectures"] == selected_archs, "Selected architecture mismatch"
expected_keys = {(a, v) for a in selected_archs for v in authoritative_lock["expected_variants"]}
actual_keys = [(e["architecture"], e["variant"]) for e in run_manifest["entries"]]
assert len(actual_keys) == len(set(actual_keys)), "Duplicate manifest entry"
assert set(actual_keys) == expected_keys, "Entry coverage mismatch"

# Reject metadata corruption before invoking the importer.
for entry in run_manifest["entries"]:
    key = (entry["architecture"], entry["variant"])
    auth = auth_entries[key]
    status = entry["status"]
    if status == "skipped":
        assert mode == "normal" and sys.platform != "win32" and key[0] == "msvc", f"Required entry skipped: {key}"
        assert entry.get("reason", "").strip(), f"Missing skip reason: {key}"
        continue
    assert status == "ok", f"Invalid entry status: {key}"
    for field in ("endian", "format", "command"):
        assert entry[field] == auth[field], f"{field} mismatch for {key}"
    for field in ("binary", "unstripped_twin", "symbol_artifact"):
        if field not in auth:
            continue
        name = auth[field]
        assert Path(name).name == name and name not in ("", ".", ".."), "Invalid artifact name"
        assert entry[field] == name, f"{field} mismatch for {key}"
        artifact = out_dir / name
        assert artifact.is_file(), f"Missing artifact: {name}"
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        assert digest == entry[field + "_sha256"], f"Artifact hash mismatch: {name}"


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

        sym_count = count_symtab_functions(twin_path)
        assert sym_count == entry["symbol_count"], f"Incorrect symbol count for {twin_path.name}"
        min_sym = auth.get("min_symbols", 1)
        assert sym_count >= min_sym, f"Symbol count {sym_count} < expected minimum {min_sym} in {twin_path.name}"

        # Assert identical loadable code
        assert b_exec and len(b_exec) == len(t_exec), f"Executable segment count mismatch for {bin_path.name}"
        for (v1, b1), (v2, b2) in zip(b_exec, t_exec):
            assert v1 == v2, f"Executable vaddr mismatch {v1:#x} != {v2:#x}"
            assert b1 == b2, f"Loadable code at {v1:#x} must be bit-for-bit identical between stripped and unstripped twin"

    elif auth["format"] == "pe":
        sym_count = validate_pe_twin(bin_path, twin_path, out_dir / auth["symbol_artifact"])
        assert sym_count == entry["symbol_count"], f"Incorrect PDB symbol count for {twin_path.name}"

    runtime_check = None
    if var == "cpp_o2":
        runners = {
            "i386": ("qemu-i386", "i686-linux-gnu"),
            "aarch64": ("qemu-aarch64", "aarch64-linux-gnu"),
            "powerpc": ("qemu-ppc", "powerpc-linux-gnu"),
        }
        command = []
        if arch in runners:
            emulator, target = runners[arch]
            assert shutil.which(emulator), f"Install qemu-user: missing {emulator}"
            prefix = committed_lock_path.parent.parent / "third_party/sysroots" / arch / "usr" / target
            command = [emulator, "-L", str(prefix)]
        for argument, expected_code, expected_output in (
            ("1", 0, "res: 52"), ("-1", 1, "caught: 1"),
        ):
            result = subprocess.run(command + [str(bin_path), argument], capture_output=True,
                                    text=True, timeout=10)
            assert (result.returncode, result.stdout.strip()) == (expected_code, expected_output), (
                f"{arch} exception/TLS runtime failed for {argument}: {result}"
            )
        runtime_check = {"positive": 0, "caught_exception": 1, "runner": command[0] if command else "native"}

    # Native import verification
    res = subprocess.run([str(cli_path), "import-native", str(bin_path), "--project", str(out_dir / "project")], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
        "runtime_check": runtime_check,
    })
    print(f"PASS: {arch} {var} -> {fn_count} functions, language {exp_lang}")

report = {
    "gate": "m1-006",
    "total_entries": len(run_manifest["entries"]),
    "passed_entries": passed,
    "skipped_entries": skipped,
    "pass": passed == (5 if mode == "msvc" else len(expected_keys) - skipped),
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
