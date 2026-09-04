#!/usr/bin/env python3
"""Multi-architecture corpus generation script for Ventris (m1-006).

Builds 5 corpus variants across target architectures:
- x86-64 (host)
- x86-32 (i386)
- aarch64
- powerpc (PPC32-BE)
- msvc (Windows host only)

Each entry produces an unstripped twin containing symbol tables (or PDB for MSVC)
and derives the primary release binary by stripping a copy of the twin, ensuring
code addresses and loadable code segments remain identical.
Emits a per-run manifest under --out-dir. --update-lock refreshes only source
digests in the recipe lock; matrix and recipes remain explicitly maintained.
"""

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS_SRC = ROOT / "tests" / "corpus-src"
SYSROOTS_DIR = ROOT / "third_party" / "sysroots"
FETCH_SYSROOTS_SCRIPT = ROOT / "tools" / "fetch_cross_sysroots.py"

ARCHITECTURES = {
    "x86_64": {
        "target": "x86_64-linux-gnu",
        "endian": "little",
        "format": "elf",
        "sysroot": None,
        "c_compiler": ["clang", "--target=x86_64-linux-gnu", "-fuse-ld=lld"],
        "cxx_compiler": ["clang++", "--target=x86_64-linux-gnu", "-fuse-ld=lld", "-nostdlib++"],
        "extra_flags": [],
    },
    "i386": {
        "target": "i686-linux-gnu",
        "endian": "little",
        "format": "elf",
        "sysroot": SYSROOTS_DIR / "i386",
        "c_compiler": ["clang", "--target=i686-linux-gnu", "-fuse-ld=lld"],
        "cxx_compiler": ["clang++", "--target=i686-linux-gnu", "-fuse-ld=lld", "-nostdlib++"],
        "extra_flags": [
            "-B", str(SYSROOTS_DIR / "i386" / "usr" / "lib" / "gcc-cross" / "i686-linux-gnu" / "12"),
            "-L", str(SYSROOTS_DIR / "i386" / "usr" / "lib" / "gcc-cross" / "i686-linux-gnu" / "12"),
        ],
    },
    "aarch64": {
        "target": "aarch64-linux-gnu",
        "endian": "little",
        "format": "elf",
        "sysroot": SYSROOTS_DIR / "aarch64",
        "c_compiler": ["clang", "--target=aarch64-linux-gnu", "-fuse-ld=lld"],
        "cxx_compiler": ["clang++", "--target=aarch64-linux-gnu", "-fuse-ld=lld", "-nostdlib++"],
        "extra_flags": [
            "-B", str(SYSROOTS_DIR / "aarch64" / "usr" / "lib" / "gcc-cross" / "aarch64-linux-gnu" / "12"),
            "-L", str(SYSROOTS_DIR / "aarch64" / "usr" / "lib" / "gcc-cross" / "aarch64-linux-gnu" / "12"),
        ],
    },
    "powerpc": {
        "target": "powerpc-linux-gnu",
        "endian": "big",
        "format": "elf",
        "sysroot": SYSROOTS_DIR / "powerpc",
        "c_compiler": ["clang", "--target=powerpc-linux-gnu", "-fuse-ld=lld"],
        "cxx_compiler": ["clang++", "--target=powerpc-linux-gnu", "-fuse-ld=lld", "-nostdlib++"],
        "extra_flags": [
            "-B", str(SYSROOTS_DIR / "powerpc" / "usr" / "lib" / "gcc-cross" / "powerpc-linux-gnu" / "12"),
            "-L", str(SYSROOTS_DIR / "powerpc" / "usr" / "lib" / "gcc-cross" / "powerpc-linux-gnu" / "12"),
        ],
    },
}

VARIANTS = {
    "plain_o0": {
        "source": "plain.c",
        "is_cpp": False,
        "flags": ["-O0", "-g"],
        "ext": ".bin",
    },
    "plain_o2": {
        "source": "plain.c",
        "is_cpp": False,
        "flags": ["-O2", "-g"],
        "ext": ".bin",
    },
    "plain_pie": {
        "source": "plain.c",
        "is_cpp": False,
        "flags": ["-O2", "-g", "-fPIE", "-pie"],
        "ext": ".bin",
    },
    "cpp_o2": {
        "source": "src.cpp",
        "is_cpp": True,
        "flags": ["-O2", "-g"],
        "ext": ".bin",
    },
    "many_o2": {
        "source": "many.c",
        "is_cpp": False,
        "flags": ["-O1", "-fno-inline", "-g"],
        "ext": ".bin",
    },
}


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def ensure_sysroots():
    manifest = SYSROOTS_DIR / "sysroot-manifest.json"
    if not manifest.exists():
        print("Fetching cross sysroots via tools/fetch_cross_sysroots.py...")
        subprocess.run([sys.executable, str(FETCH_SYSROOTS_SCRIPT)], check=True)


def build_binary(cmd: list, out_path: Path):
    cmd_str = " ".join(cmd)
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if res.returncode != 0:
        sys.stderr.write(f"Build failed for {out_path.name}:\nCommand: {cmd_str}\n{res.stderr.decode()}\n")
        sys.exit(1)


def find_strip_tool():
    for name in ["llvm-strip", "llvm-strip-19", "llvm-strip-18", "llvm-strip-17", "llvm-strip-16", "llvm-strip-15", "llvm-strip-14"]:
        if p := shutil.which(name):
            return p
    import glob
    for p in sorted(glob.glob("/usr/lib/llvm-*/bin/llvm-strip"), reverse=True):
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    for p in ["C:\\Program Files\\LLVM\\bin\\llvm-strip.exe", "C:\\ProgramData\\chocolatey\\bin\\llvm-strip.exe"]:
        if os.path.isfile(p):
            return p
    return None


def strip_pe_debug(bin_path: Path):
    with open(bin_path, "r+b") as f:
        data = bytearray(f.read())
        if len(data) < 0x40 or data[:2] != b"MZ":
            return
        pe_off = struct.unpack("<I", data[0x3c:0x40])[0]
        if pe_off + 28 > len(data) or data[pe_off:pe_off+4] != b"PE\0\0":
            return
        opt = pe_off + 24
        magic = struct.unpack("<H", data[opt:opt+2])[0]
        if magic == 0x20b:
            num_rva = struct.unpack("<I", data[opt+108:opt+112])[0]
            if num_rva > 6:
                dbg_dir_off = opt + 112 + 6 * 8
                if dbg_dir_off + 8 <= len(data):
                    data[dbg_dir_off:dbg_dir_off+8] = b"\x00" * 8
        elif magic == 0x10b:
            num_rva = struct.unpack("<I", data[opt+92:opt+96])[0]
            if num_rva > 6:
                dbg_dir_off = opt + 96 + 6 * 8
                if dbg_dir_off + 8 <= len(data):
                    data[dbg_dir_off:dbg_dir_off+8] = b"\x00" * 8
        f.seek(0)
        f.write(data)
        f.truncate()


def strip_binary(bin_path: Path):
    if str(bin_path).endswith(".exe"):
        strip_pe_debug(bin_path)
    else:
        strip_tool = find_strip_tool()
        if strip_tool:
            subprocess.run([strip_tool, "--strip-all", str(bin_path)], check=True)
        else:
            strip_tool_fallback = shutil.which("strip")
            if strip_tool_fallback:
                subprocess.run([strip_tool_fallback, "--strip-all", str(bin_path)], check=True)
            else:
                sys.stderr.write(f"Warning: neither llvm-strip nor strip found to strip {bin_path}\n")

def parse_elf_sections(data: bytes):
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
        return secs
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
        return secs


def get_loadable_exec(data: bytes):
    is_64 = data[4] == 2
    be = data[5] == 2
    endian = ">" if be else "<"
    if is_64:
        phoff = struct.unpack(f"{endian}Q", data[32:40])[0]
        phentsize = struct.unpack(f"{endian}H", data[54:56])[0]
        phnum = struct.unpack(f"{endian}H", data[56:58])[0]
        segments = []
        for i in range(phnum):
            off = phoff + i * phentsize
            p_type, p_flags = struct.unpack(f"{endian}II", data[off:off+8])
            p_offset, p_vaddr = struct.unpack(f"{endian}QQ", data[off+8:off+24])
            p_filesz = struct.unpack(f"{endian}Q", data[off+32:off+40])[0]
            if p_type == 1 and (p_flags & 1):
                segments.append((p_vaddr, data[p_offset:p_offset+p_filesz]))
        return segments
    else:
        phoff = struct.unpack(f"{endian}I", data[28:32])[0]
        phentsize = struct.unpack(f"{endian}H", data[42:44])[0]
        phnum = struct.unpack(f"{endian}H", data[44:46])[0]
        segments = []
        for i in range(phnum):
            off = phoff + i * phentsize
            p_type, p_offset, p_vaddr = struct.unpack(f"{endian}III", data[off:off+12])
            p_filesz = struct.unpack(f"{endian}I", data[off+16:off+20])[0]
            p_flags = struct.unpack(f"{endian}I", data[off+24:off+28])[0]
            if p_type == 1 and (p_flags & 1):
                segments.append((p_vaddr, data[p_offset:p_offset+p_filesz]))
        return segments


def count_symtab_functions(twin_path: Path) -> int:
    with open(twin_path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF":
        return 0
    is_64 = data[4] == 2
    be = data[5] == 2
    endian = ">" if be else "<"
    
    shoff = struct.unpack(f"{endian}Q" if is_64 else f"{endian}I", data[40:48] if is_64 else data[32:36])[0]
    shentsize = struct.unpack(f"{endian}H", data[58:60] if is_64 else data[46:48])[0]
    shnum = struct.unpack(f"{endian}H", data[60:62] if is_64 else data[48:50])[0]
    
    symtab_off = 0
    symtab_sz = 0
    symtab_entsz = 24 if is_64 else 16
    
    for i in range(shnum):
        off = shoff + i * shentsize
        sec_type = struct.unpack(f"{endian}I", data[off+4:off+8])[0]
        if sec_type == 2:  # SHT_SYMTAB
            symtab_off = struct.unpack(f"{endian}Q" if is_64 else f"{endian}I", data[off+24:off+32] if is_64 else data[off+16:off+20])[0]
            symtab_sz = struct.unpack(f"{endian}Q" if is_64 else f"{endian}I", data[off+32:off+40] if is_64 else data[off+20:off+24])[0]
            break
            
    if symtab_off == 0 or symtab_sz == 0:
        return 0
        
    count = symtab_sz // symtab_entsz
    func_count = 0
    for i in range(count):
        entry_off = symtab_off + i * symtab_entsz
        info_byte = data[entry_off + 4] if is_64 else data[entry_off + 12]
        st_type = info_byte & 0xf
        if st_type == 2:  # STT_FUNC
            func_count += 1
    return func_count


def validate_elf_twin(bin_path: Path, twin_path: Path) -> int:
    with open(bin_path, "rb") as f:
        bin_data = f.read()
    with open(twin_path, "rb") as f:
        twin_data = f.read()
    assert bin_data[:4] == b"\x7fELF", f"{bin_path} not an ELF"
    assert twin_data[:4] == b"\x7fELF", f"{twin_path} not an ELF"

    bin_secs = [name for name, typ in parse_elf_sections(bin_data)]
    twin_secs = [name for name, typ in parse_elf_sections(twin_data)]
    assert ".symtab" not in bin_secs, f"Stripped binary {bin_path.name} must lack .symtab"
    assert ".symtab" in twin_secs, f"Unstripped twin {twin_path.name} must contain .symtab"

    bin_exec = get_loadable_exec(bin_data)
    twin_exec = get_loadable_exec(twin_data)
    assert len(bin_exec) == len(twin_exec), "Number of executable segments mismatch"
    for (v1, b1), (v2, b2) in zip(bin_exec, twin_exec):
        assert v1 == v2, f"Executable vaddr mismatch {v1:#x} != {v2:#x}"
        assert b1 == b2, f"Loadable code at {v1:#x} must be bit-for-bit identical between stripped and unstripped twin"

    sym_count = count_symtab_functions(twin_path)
    assert sym_count > 0, f"Unstripped twin {twin_path.name} must contain STT_FUNC symbols (got 0)"
    return sym_count


def parse_pe_info(data: bytes):
    assert data[:2] == b"MZ"
    pe_off = struct.unpack("<I", data[0x3c:0x40])[0]
    assert data[pe_off:pe_off+4] == b"PE\0\0"
    machine = struct.unpack("<H", data[pe_off+4:pe_off+6])[0]
    num_sections = struct.unpack("<H", data[pe_off+6:pe_off+8])[0]
    opt_size = struct.unpack("<H", data[pe_off+20:pe_off+22])[0]
    opt = pe_off + 24
    magic = struct.unpack("<H", data[opt:opt+2])[0]
    is_64 = (magic == 0x20b)
    
    if is_64:
        num_rva = struct.unpack("<I", data[opt+108:opt+112])[0]
        dbg_entry_off = opt + 112 + 6 * 8
    else:
        num_rva = struct.unpack("<I", data[opt+92:opt+96])[0]
        dbg_entry_off = opt + 96 + 6 * 8
        
    dbg_rva, dbg_size = 0, 0
    if num_rva > 6 and dbg_entry_off + 8 <= opt + opt_size:
        dbg_rva, dbg_size = struct.unpack("<II", data[dbg_entry_off:dbg_entry_off+8])
        
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
            "name": name,
            "vsize": vsize,
            "vaddr": vaddr,
            "raw_size": raw_size,
            "raw_off": raw_off,
            "chars": chars,
            "exec": (chars & 0x20000000) != 0,
        })
    return {
        "is_64": is_64,
        "dbg_rva": dbg_rva,
        "dbg_size": dbg_size,
        "sections": sections,
    }


def validate_pe_twin(bin_path: Path, twin_path: Path, pdb_path: Path):
    with open(bin_path, "rb") as f:
        bin_data = f.read()
    with open(twin_path, "rb") as f:
        twin_data = f.read()
        
    bin_info = parse_pe_info(bin_data)
    twin_info = parse_pe_info(twin_data)
    
    # 1. Primary PE must lack debug directory reference
    assert bin_info["dbg_rva"] == 0 and bin_info["dbg_size"] == 0, (
        f"Primary PE {bin_path.name} must have no debug-directory reference (got rva={bin_info['dbg_rva']:#x}, size={bin_info['dbg_size']})"
    )
    
    # 2. Unstripped PE must have a valid debug-directory reference pointing to CodeView/PDB
    assert twin_info["dbg_rva"] > 0 and twin_info["dbg_size"] > 0, (
        f"Unstripped PE {twin_path.name} must have a non-empty debug directory"
    )
    
    # Map dbg_rva to raw file offset
    dbg_sec = next((s for s in twin_info["sections"] if twin_info["dbg_rva"] >= s["vaddr"] and twin_info["dbg_rva"] < s["vaddr"] + s["vsize"]), None)
    assert dbg_sec is not None, f"Debug directory RVA {twin_info['dbg_rva']:#x} not in any section"
    dbg_raw_off = dbg_sec["raw_off"] + (twin_info["dbg_rva"] - dbg_sec["vaddr"])
    
    # Locate CodeView entry (Type == 2)
    entry_count = twin_info["dbg_size"] // 28
    found_cv = False
    for i in range(entry_count):
        eo = dbg_raw_off + i * 28
        e_type = struct.unpack("<I", twin_data[eo+12:eo+16])[0]
        e_raw_off = struct.unpack("<I", twin_data[eo+24:eo+28])[0]
        if e_type == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
            sig = twin_data[e_raw_off:e_raw_off+4]
            assert sig == b"RSDS", f"Expected RSDS CodeView signature in {twin_path.name}, got {sig}"
            pdb_str = twin_data[e_raw_off+24:].split(b"\0")[0].decode(errors="replace")
            assert pdb_path.name in pdb_str or pdb_path.stem in pdb_str, (
                f"PDB reference mismatch: expected {pdb_path.name} in {pdb_str}"
            )
            found_cv = True
            break
    assert found_cv, f"No CodeView RSDS entry found in unstripped PE {twin_path.name}"
    
    # 3. PDB artifact itself must be valid
    assert pdb_path.exists(), f"PDB artifact {pdb_path} missing"
    assert pdb_path.stat().st_size > 0, f"PDB artifact {pdb_path} empty"
    with open(pdb_path, "rb") as f:
        pdb_hdr = f.read(32)
    assert pdb_hdr.startswith(b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00"), (
        f"Invalid PDB header in {pdb_path.name}"
    )
    
    # 4. Compare every executable section: RVA, VirtualSize, and raw bytes must be identical
    bin_exec_secs = [s for s in bin_info["sections"] if s["exec"]]
    twin_exec_secs = [s for s in twin_info["sections"] if s["exec"]]
    assert len(bin_exec_secs) == len(twin_exec_secs), "Number of executable PE sections mismatch"
    
    for s_bin, s_twin in zip(bin_exec_secs, twin_exec_secs):
        assert s_bin["name"] == s_twin["name"], f"Section name mismatch {s_bin['name']} != {s_twin['name']}"
        assert s_bin["vaddr"] == s_twin["vaddr"], f"Section RVA mismatch for {s_bin['name']}"
        assert s_bin["vsize"] == s_twin["vsize"], f"Section VirtualSize mismatch for {s_bin['name']}"
        assert s_bin["raw_size"] == s_twin["raw_size"], f"Section SizeOfRawData mismatch for {s_bin['name']}"
        
        b_bytes = bin_data[s_bin["raw_off"]:s_bin["raw_off"] + s_bin["raw_size"]]
        t_bytes = twin_data[s_twin["raw_off"]:s_twin["raw_off"] + s_twin["raw_size"]]
        assert b_bytes == t_bytes, f"Executable code bytes mismatch in section {s_bin['name']}"


def main():
    parser = argparse.ArgumentParser(description="Generate multi-architecture corpus and manifest.")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "tests" / "corpus-binaries",
                        help="Output directory for generated corpus binaries.")
    parser.add_argument("--manifest", type=Path, default=None,
                        help="Path for per-run output manifest (defaults to <out-dir>/manifest.json).")
    parser.add_argument("--lock", type=Path, default=ROOT / "tests" / "corpus.lock.json",
                        help="Path to authoritative corpus lock file.")
    parser.add_argument("--update-lock", action="store_true",
                        help="Refresh source digests only, preserving matrix and recipes; do not build.")
    parser.add_argument("--architectures", type=str, default="x86_64,i386,aarch64,powerpc,msvc",
                        help="Comma-separated list of architectures to build (or 'msvc').")
    parser.add_argument("--msvc-only", action="store_true",
                        help="Shorthand for --architectures msvc.")
    parser.add_argument("--skip-sysroots", action="store_true",
                        help="Skip checking/fetching cross sysroots.")
    args = parser.parse_args()

    with open(args.lock, "r") as f:
        lock_expectations = json.load(f)
    if args.update_lock:
        for name in lock_expectations["sources"]:
            source = CORPUS_SRC / name
            lock_expectations["sources"][name] = {
                "sha256": sha256_file(source), "size": source.stat().st_size,
            }
        args.lock.write_text(json.dumps(lock_expectations, indent=2) + "\n")
        print(f"Updated source digests in authoritative lock: {args.lock}")
        return

    selected_archs = ["msvc"] if args.msvc_only else [a.strip() for a in args.architectures.split(",") if a.strip()]

    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = args.manifest or (out_dir / "manifest.json")

    needs_cross = any(a in selected_archs for a in ["i386", "aarch64", "powerpc"])
    if needs_cross and not args.skip_sysroots and sys.platform != "win32":
        ensure_sysroots()


    manifest_data = {
        "schema_version": 1,
        "selected_architectures": selected_archs,
        "sources": {},
        "entries": [],
    }

    # Record source hashes
    for src_name in ["plain.c", "src.cpp", "many.c"]:
        src_path = CORPUS_SRC / src_name
        assert src_path.exists(), f"Source {src_name} missing"
        actual_h = sha256_file(src_path)
        expected_h = lock_expectations["sources"][src_name]["sha256"]
        assert actual_h == expected_h, f"Committed source hash mismatch for {src_name}"
        manifest_data["sources"][src_name] = {
            "sha256": actual_h,
            "size": src_path.stat().st_size,
        }

    # Build Linux cross targets
    for arch_name in selected_archs:
        if arch_name == "msvc":
            continue
        if arch_name not in ARCHITECTURES:
            sys.stderr.write(f"Unknown architecture: {arch_name}\n")
            sys.exit(1)
        arch_cfg = ARCHITECTURES[arch_name]
        for var_name, var_cfg in VARIANTS.items():
            base_name = f"{arch_name}_{var_name}"
            bin_path = out_dir / f"{base_name}{var_cfg['ext']}"
            twin_path = out_dir / f"{base_name}.unstripped"

            compiler = arch_cfg["cxx_compiler"] if var_cfg["is_cpp"] else arch_cfg["c_compiler"]
            src_file = CORPUS_SRC / var_cfg["source"]

            # Common base command
            base_cmd = list(compiler)
            if arch_cfg["sysroot"]:
                base_cmd.extend(["--sysroot", str(arch_cfg["sysroot"])])
            base_cmd.extend(arch_cfg["extra_flags"])

            # 1. Build unstripped twin once with debug symbols
            cmd_twin = base_cmd + var_cfg["flags"] + [str(src_file), "-o", str(twin_path)]
            build_binary(cmd_twin, twin_path)

            # 2. Derive stripped primary by copying and stripping
            shutil.copy2(twin_path, bin_path)
            strip_binary(bin_path)

            # 3. Validate twins and loadable code identity
            sym_count = validate_elf_twin(bin_path, twin_path)

            cmd_display_str = " ".join(cmd_twin).replace(str(ROOT) + "/", "").replace(str(out_dir) + "/", "$OUT/")
            full_display = f"{cmd_display_str} && llvm-strip --strip-all $OUT/{bin_path.name}"

            manifest_data["entries"].append({
                "architecture": arch_name,
                "endian": arch_cfg["endian"],
                "format": "elf",
                "variant": var_name,
                "status": "ok",
                "binary": bin_path.name,
                "binary_sha256": sha256_file(bin_path),
                "unstripped_twin": twin_path.name,
                "unstripped_twin_sha256": sha256_file(twin_path),
                "symbol_count": sym_count,
                "command": full_display,
            })
            print(f"Generated {bin_path.name} (stripped) and {twin_path.name} (unstripped, {sym_count} symbols)")

    # Handle MSVC if requested
    if "msvc" in selected_archs:
        has_cl = shutil.which("cl") is not None
        is_windows = sys.platform == "win32"

        for var_name, var_cfg in VARIANTS.items():
            base_name = f"msvc_{var_name}"
            bin_path = out_dir / f"{base_name}.exe"
            twin_path = out_dir / f"{base_name}.unstripped.exe"
            pdb_path = out_dir / f"{base_name}.pdb"

            if is_windows and has_cl:
                src_file = CORPUS_SRC / var_cfg["source"]
                msvc_flags = ["/O1"] if var_name == "many_o2" else (["/Od"] if var_name == "plain_o0" else ["/O2"])
                if var_cfg["is_cpp"]:
                    msvc_flags.append("/EHsc")
                
                # Build unstripped twin with PDB debug info
                cmd_twin = ["cl", "/nologo"] + msvc_flags + ["/Zi", "/FS", str(src_file), f"/Fe:{twin_path}", f"/Fd:{pdb_path}", "/link", "/DEBUG"]
                build_binary(cmd_twin, twin_path)

                # Derive stripped primary
                shutil.copy2(twin_path, bin_path)
                strip_binary(bin_path)

                # Validate MSVC twin: PE debug directory, PDB header, and code bytes identity
                validate_pe_twin(bin_path, twin_path, pdb_path)

                cmd_display = ["cl", "/nologo"] + msvc_flags + ["/Zi", "/FS", f"tests/corpus-src/{var_cfg['source']}", f"/Fe:$OUT/{twin_path.name}", f"/Fd:$OUT/{pdb_path.name}", "/link", "/DEBUG"]

                manifest_data["entries"].append({
                    "architecture": "msvc",
                    "endian": "little",
                    "format": "pe",
                    "variant": var_name,
                    "status": "ok",
                    "binary": bin_path.name,
                    "binary_sha256": sha256_file(bin_path),
                    "unstripped_twin": twin_path.name,
                    "unstripped_twin_sha256": sha256_file(twin_path),
                    "symbol_artifact": pdb_path.name,
                    "symbol_artifact_sha256": sha256_file(pdb_path),
                    "command": " ".join(cmd_display),
                })
                print(f"Generated {bin_path.name}, {twin_path.name}, and {pdb_path.name}")
            else:
                manifest_data["entries"].append({
                    "architecture": "msvc",
                    "endian": "little",
                    "format": "pe",
                    "variant": var_name,
                    "status": "skipped",
                    "reason": "MSVC requires Windows host with Visual Studio",
                    "binary": f"{base_name}.exe",
                    "unstripped_twin": f"{base_name}.unstripped.exe",
                    "symbol_artifact": f"{base_name}.pdb",
                })

    # Write per-run manifest under output directory
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(manifest_path, "w") as f:
        json.dump(manifest_data, f, indent=2)
    print(f"Wrote per-run artifact manifest: {manifest_path}")



if __name__ == "__main__":
    main()
