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
Emits a lockfile with metadata, commands, and hashes.
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
        "sysroot": None,
        "c_compiler": ["clang", "--target=x86_64-linux-gnu", "-fuse-ld=lld"],
        "cxx_compiler": ["clang++", "--target=x86_64-linux-gnu", "-fuse-ld=lld", "-nostdlib++"],
        "extra_flags": [],
    },
    "i386": {
        "target": "i686-linux-gnu",
        "endian": "little",
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
    strip_tool = shutil.which("llvm-strip") or shutil.which("strip")
    if strip_tool:
        subprocess.run([strip_tool, "--strip-all", str(bin_path)], check=True)
    elif str(bin_path).endswith(".exe"):
        strip_pe_debug(bin_path)
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
    secs = parse_elf_sections(data)
    
    # Find SHT_SYMTAB (type 2)
    symtab_off = 0
    symtab_sz = 0
    symtab_entsz = 24 if is_64 else 16
    
    shoff = struct.unpack(f"{endian}Q" if is_64 else f"{endian}I", data[40:48] if is_64 else data[32:36])[0]
    shentsize = struct.unpack(f"{endian}H", data[58:60] if is_64 else data[46:48])[0]
    shnum = struct.unpack(f"{endian}H", data[60:62] if is_64 else data[48:50])[0]
    
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


def validate_pdb(pdb_path: Path):
    assert pdb_path.exists(), f"PDB artifact {pdb_path} missing"
    assert pdb_path.stat().st_size > 0, f"PDB artifact {pdb_path} empty"
    with open(pdb_path, "rb") as f:
        hdr = f.read(32)
    assert hdr.startswith(b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00"), f"Invalid PDB header signature in {pdb_path}"


def main():
    parser = argparse.ArgumentParser(description="Generate multi-architecture corpus and lockfile.")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "tests" / "corpus-binaries",
                        help="Output directory for generated corpus binaries.")
    parser.add_argument("--lock", type=Path, default=ROOT / "tests" / "corpus.lock.json",
                        help="Path to corpus lock file.")
    parser.add_argument("--architectures", type=str, default="x86_64,i386,aarch64,powerpc,msvc",
                        help="Comma-separated list of architectures to build (or 'msvc').")
    parser.add_argument("--msvc-only", action="store_true",
                        help="Shorthand for --architectures msvc.")
    parser.add_argument("--skip-sysroots", action="store_true",
                        help="Skip checking/fetching cross sysroots.")
    args = parser.parse_args()

    selected_archs = ["msvc"] if args.msvc_only else [a.strip() for a in args.architectures.split(",") if a.strip()]

    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    needs_cross = any(a in selected_archs for a in ["i386", "aarch64", "powerpc"])
    if needs_cross and not args.skip_sysroots and sys.platform != "win32":
        ensure_sysroots()

    lock_data = {
        "schema_version": 1,
        "sources": {},
        "entries": [],
    }

    # Record source hashes
    for src_name in ["plain.c", "src.cpp", "many.c"]:
        src_path = CORPUS_SRC / src_name
        if src_path.exists():
            lock_data["sources"][src_name] = {
                "sha256": sha256_file(src_path),
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

            cmd_twin_display_str = " ".join(cmd_twin).replace(str(ROOT) + "/", "").replace(str(out_dir) + "/", "$OUT/")
            full_display = f"{cmd_twin_display_str} && llvm-strip --strip-all $OUT/{bin_path.name}"

            lock_data["entries"].append({
                "architecture": arch_name,
                "endian": arch_cfg["endian"],
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
                msvc_flags = ["/O2"] if "o2" in var_name or "pie" in var_name else ["/Od"]
                if var_cfg["is_cpp"]:
                    msvc_flags.append("/EHsc")
                
                # Build unstripped twin with PDB debug info
                cmd_twin = ["cl", "/nologo"] + msvc_flags + ["/Zi", "/FS", str(src_file), f"/Fe:{twin_path}", f"/Fd:{pdb_path}", "/link", "/DEBUG"]
                build_binary(cmd_twin, twin_path)

                # Derive stripped primary
                shutil.copy2(twin_path, bin_path)
                strip_binary(bin_path)

                # Validate PDB artifact
                validate_pdb(pdb_path)

                cmd_display = ["cl", "/nologo"] + msvc_flags + ["/Zi", "/FS", f"tests/corpus-src/{var_cfg['source']}", f"/Fe:$OUT/{twin_path.name}", f"/Fd:$OUT/{pdb_path.name}", "/link", "/DEBUG"]

                lock_data["entries"].append({
                    "architecture": "msvc",
                    "endian": "little",
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
                lock_data["entries"].append({
                    "architecture": "msvc",
                    "endian": "little",
                    "variant": var_name,
                    "status": "skipped",
                    "reason": "MSVC requires Windows host with Visual Studio (verified via Windows CI)",
                    "binary": f"{base_name}.exe",
                    "unstripped_twin": f"{base_name}.unstripped.exe",
                    "symbol_artifact": f"{base_name}.pdb",
                })

    # If building a subset, preserve any existing other entries from lock file
    if args.lock.exists():
        try:
            with open(args.lock, "r") as f:
                existing = json.load(f)
            # Merge existing entries for architectures not currently generated
            existing_archs = {e["architecture"] for e in existing.get("entries", [])}
            new_archs = {e["architecture"] for e in lock_data["entries"]}
            for e in existing.get("entries", []):
                if e["architecture"] not in new_archs:
                    lock_data["entries"].append(e)
            # Sort entries deterministically
            arch_order = {"x86_64": 0, "i386": 1, "aarch64": 2, "powerpc": 3, "msvc": 4}
            lock_data["entries"].sort(key=lambda e: (arch_order.get(e["architecture"], 99), e.get("variant", "")))
        except Exception:
            pass

    args.lock.parent.mkdir(parents=True, exist_ok=True)
    with open(args.lock, "w") as f:
        json.dump(lock_data, f, indent=2)
    print(f"Wrote corpus lock: {args.lock}")


if __name__ == "__main__":
    main()
