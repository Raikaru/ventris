#!/usr/bin/env python3
"""Multi-architecture corpus generation script for Ventris (m1-006).

Builds 5 corpus variants across target architectures:
- x86-64 (host)
- x86-32 (i386)
- aarch64
- powerpc (PPC32-BE)
- msvc (Windows host only, skipped on non-Windows)

Each entry produces a release binary and an unstripped twin containing symbol tables.
Emits tests/corpus.lock.json with metadata, commands, and hashes.
"""

import argparse
import hashlib
import json
import os
import shutil
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
        "sysroot": None,
        "c_compiler": ["clang", "--target=x86_64-linux-gnu", "-fuse-ld=lld"],
        "cxx_compiler": ["clang++", "--target=x86_64-linux-gnu", "-fuse-ld=lld", "-nostdlib++"],
        "extra_flags": [],
        "extra_link": [],
    },
    "i386": {
        "target": "i686-linux-gnu",
        "sysroot": SYSROOTS_DIR / "i386",
        "c_compiler": ["clang", "--target=i686-linux-gnu", "-fuse-ld=lld"],
        "cxx_compiler": ["clang++", "--target=i686-linux-gnu", "-fuse-ld=lld", "-nostdlib++"],
        "extra_flags": [
            "-B", str(SYSROOTS_DIR / "i386" / "usr" / "lib" / "gcc-cross" / "i686-linux-gnu" / "12"),
            "-L", str(SYSROOTS_DIR / "i386" / "usr" / "lib" / "gcc-cross" / "i686-linux-gnu" / "12"),
        ],
        "extra_link": [],
    },
    "aarch64": {
        "target": "aarch64-linux-gnu",
        "sysroot": SYSROOTS_DIR / "aarch64",
        "c_compiler": ["clang", "--target=aarch64-linux-gnu", "-fuse-ld=lld"],
        "cxx_compiler": ["clang++", "--target=aarch64-linux-gnu", "-fuse-ld=lld", "-nostdlib++"],
        "extra_flags": [
            "-B", str(SYSROOTS_DIR / "aarch64" / "usr" / "lib" / "gcc-cross" / "aarch64-linux-gnu" / "12"),
            "-L", str(SYSROOTS_DIR / "aarch64" / "usr" / "lib" / "gcc-cross" / "aarch64-linux-gnu" / "12"),
        ],
        "extra_link": [],
    },
    "powerpc": {
        "target": "powerpc-linux-gnu",
        "sysroot": SYSROOTS_DIR / "powerpc",
        "c_compiler": ["clang", "--target=powerpc-linux-gnu", "-fuse-ld=lld"],
        "cxx_compiler": ["clang++", "--target=powerpc-linux-gnu", "-fuse-ld=lld", "-nostdlib++"],
        "extra_flags": [
            "-B", str(SYSROOTS_DIR / "powerpc" / "usr" / "lib" / "gcc-cross" / "powerpc-linux-gnu" / "12"),
            "-L", str(SYSROOTS_DIR / "powerpc" / "usr" / "lib" / "gcc-cross" / "powerpc-linux-gnu" / "12"),
        ],
        "extra_link": [],
    },
}

VARIANTS = {
    "plain_o0": {
        "source": "plain.c",
        "is_cpp": False,
        "flags": ["-O0", "-g"],
        "unstripped_flags": ["-O0", "-g"],
        "ext": ".bin",
    },
    "plain_o2": {
        "source": "plain.c",
        "is_cpp": False,
        "flags": ["-O2", "-s"],
        "unstripped_flags": ["-O2", "-g"],
        "ext": ".bin",
    },
    "plain_pie": {
        "source": "plain.c",
        "is_cpp": False,
        "flags": ["-O2", "-s", "-fPIE", "-pie"],
        "unstripped_flags": ["-O2", "-g", "-fPIE", "-pie"],
        "ext": ".bin",
    },
    "cpp_o2": {
        "source": "src.cpp",
        "is_cpp": True,
        "flags": ["-O2", "-s"],
        "unstripped_flags": ["-O2", "-g"],
        "ext": ".bin",
    },
    "many_o2": {
        "source": "many.c",
        "is_cpp": False,
        "flags": ["-O1", "-fno-inline", "-s"],
        "unstripped_flags": ["-O1", "-fno-inline", "-g"],
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


def main():
    parser = argparse.ArgumentParser(description="Generate multi-architecture corpus and lockfile.")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "tests" / "corpus-binaries",
                        help="Output directory for generated corpus binaries.")
    parser.add_argument("--lock", type=Path, default=ROOT / "tests" / "corpus.lock.json",
                        help="Path to corpus lock file.")
    parser.add_argument("--skip-sysroots", action="store_true",
                        help="Skip checking/fetching cross sysroots.")
    args = parser.parse_args()

    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    if not args.skip_sysroots and sys.platform != "win32":
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
    for arch_name, arch_cfg in ARCHITECTURES.items():
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

            # 1. Build release / stripped binary
            cmd_bin = base_cmd + var_cfg["flags"] + [str(src_file), "-o", str(bin_path)]
            build_binary(cmd_bin, bin_path)

            # 2. Build unstripped twin with debug symbols
            cmd_twin = base_cmd + var_cfg["unstripped_flags"] + [str(src_file), "-o", str(twin_path)]
            build_binary(cmd_twin, twin_path)

            cmd_display = base_cmd + var_cfg["flags"] + [f"tests/corpus-src/{var_cfg['source']}", "-o", f"$OUT/{bin_path.name}"]

            lock_data["entries"].append({
                "architecture": arch_name,
                "variant": var_name,
                "status": "ok",
                "binary": bin_path.name,
                "binary_sha256": sha256_file(bin_path),
                "unstripped_twin": twin_path.name,
                "unstripped_twin_sha256": sha256_file(twin_path),
                "command": " ".join(cmd_display),
            })
            print(f"Generated {bin_path.name} and {twin_path.name}")
    # Handle MSVC
    has_cl = shutil.which("cl") is not None
    is_windows = sys.platform == "win32"

    for var_name, var_cfg in VARIANTS.items():
        base_name = f"msvc_{var_name}"
        bin_path = out_dir / f"{base_name}.exe"
        twin_path = out_dir / f"{base_name}.unstripped"

        if is_windows and has_cl:
            # Build using MSVC cl.exe
            src_file = CORPUS_SRC / var_cfg["source"]
            msvc_flags = ["/O2"] if "o2" in var_name or "pie" in var_name else ["/Od"]
            if var_cfg["is_cpp"]:
                msvc_flags.append("/EHsc")
            cmd_bin = ["cl", "/nologo"] + msvc_flags + [str(src_file), f"/Fe:{bin_path}"]
            build_binary(cmd_bin, bin_path)
            cmd_twin = ["cl", "/nologo", "/Zi"] + msvc_flags + [str(src_file), f"/Fe:{twin_path}"]
            build_binary(cmd_twin, twin_path)

            lock_data["entries"].append({
                "architecture": "msvc",
                "variant": var_name,
                "status": "ok",
                "binary": bin_path.name,
                "binary_sha256": sha256_file(bin_path),
                "unstripped_twin": twin_path.name,
                "unstripped_twin_sha256": sha256_file(twin_path),
                "command": " ".join(cmd_bin),
            })
        else:
            lock_data["entries"].append({
                "architecture": "msvc",
                "variant": var_name,
                "status": "skipped",
                "reason": "MSVC requires Windows host with Visual Studio (verified via Windows CI)",
                "binary": f"{base_name}.exe",
                "unstripped_twin": f"{base_name}.unstripped",
            })

    # Write lockfile
    args.lock.parent.mkdir(parents=True, exist_ok=True)
    with open(args.lock, "w") as f:
        json.dump(lock_data, f, indent=2)
    print(f"Wrote corpus lock: {args.lock}")


if __name__ == "__main__":
    main()
