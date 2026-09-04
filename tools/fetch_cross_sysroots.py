#!/usr/bin/env python3
"""Fetch and install Debian multiarch sysroots for cross-compilation.

This tool pins the exact package versions used by the m1-006 corpus generator
so non-x86 binaries can be linked with real glibc, PLT, and dynamic relocations.
Run it once per checkout/CI image to populate `third_party/sysroots/`.
"""

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "curl/7.88.1"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def verify(sha256: str, data: bytes) -> bool:
    return hashlib.sha256(data).hexdigest() == sha256


def extract_deb(data: bytes, dest: Path) -> None:
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        (tdp / "pkg.deb").write_bytes(data)
        subprocess.run(["ar", "-x", str(tdp / "pkg.deb")], cwd=tdp, check=True)
        for name in os.listdir(td):
            if name.startswith("data.tar"):
                subprocess.run(
                    ["tar", "-xf", str(tdp / name), "-C", str(dest)],
                    check=True,
                )


# Pinned Debian bookworm cross packages.
SYSROOT_PACKAGES = {
    "aarch64": {
        "target": "aarch64-linux-gnu",
        "prefix": "aarch64-linux-gnu",
        "lib_dir": "aarch64-linux-gnu",
        "packages": [
            {
                "name": "libc6-dev-arm64-cross",
                "version": "2.36-8cross1",
                "filename": "pool/main/c/cross-toolchain-base/libc6-dev-arm64-cross_2.36-8cross1_all.deb",
                "sha256": "5e4cf6abf0e89e89c4b3006bb8b7dc47aa831df25d94df9134929b8b968cacb4",
            },
            {
                "name": "libc6-arm64-cross",
                "version": "2.36-8cross1",
                "filename": "pool/main/c/cross-toolchain-base/libc6-arm64-cross_2.36-8cross1_all.deb",
                "sha256": "91936cbbee75771c360ed16513f6e734a25ca5517fe7c3e13dfd7835d7553186",
            },
            {
                "name": "linux-libc-dev-arm64-cross",
                "version": "6.1.4-1cross1",
                "filename": "pool/main/c/cross-toolchain-base/linux-libc-dev-arm64-cross_6.1.4-1cross1_all.deb",
                "sha256": "66457f015d16b7d372db6591cff38db0da928362ff2ea1fa75491e28f6904d81",
            },
            {
                "name": "libgcc-12-dev-arm64-cross",
                "version": "12.2.0-14cross1",
                "filename": "pool/main/g/gcc-12-cross/libgcc-12-dev-arm64-cross_12.2.0-14cross1_all.deb",
                "sha256": "ff1324e262bae2c3aad685c2ed52bd531ab0a2a337a0fe35c3b720947d55b2ba",
            },
            {
                "name": "libgcc-s1-arm64-cross",
                "version": "12.2.0-14cross1",
                "filename": "pool/main/g/gcc-12-cross/libgcc-s1-arm64-cross_12.2.0-14cross1_all.deb",
                "sha256": "af1e686fc6a416228222e7bfb68317dd2fa2685236301ae29141fc6108a66cac",
            },
            {
                "name": "libstdc++-12-dev-arm64-cross",
                "version": "12.2.0-14cross1",
                "filename": "pool/main/g/gcc-12-cross/libstdc++-12-dev-arm64-cross_12.2.0-14cross1_all.deb",
                "sha256": "942b5710c6b9792578dfa64f7a4633bc0d3cb205b56ded11297e240ff824f5da",
            },
            {
                "name": "libstdc++6-arm64-cross",
                "version": "12.2.0-14cross1",
                "filename": "pool/main/g/gcc-12-cross/libstdc++6-arm64-cross_12.2.0-14cross1_all.deb",
                "sha256": "9cba984b64d0cf11698978fc5e0fe93c7441d29b9f42f70f1c6c734cc9e2ea41",
            },
        ],
    },
    "i386": {
        "target": "i686-linux-gnu",
        "prefix": "i686-linux-gnu",
        "lib_dir": "i386-linux-gnu",
        "packages": [
            {
                "name": "libc6-dev-i386-cross",
                "version": "2.36-8cross1",
                "filename": "pool/main/c/cross-toolchain-base/libc6-dev-i386-cross_2.36-8cross1_all.deb",
                "sha256": "75d249b63e127b93b6d13e22f3d44941cedc1daef27ca3dff65db33abe1869aa",
            },
            {
                "name": "libc6-i386-cross",
                "version": "2.36-8cross1",
                "filename": "pool/main/c/cross-toolchain-base/libc6-i386-cross_2.36-8cross1_all.deb",
                "sha256": "59ccde027a453b6a00e45de4ed6ec9e5c50ac43d41bbed4ddcfc518beeef1360",
            },
            {
                "name": "linux-libc-dev-i386-cross",
                "version": "6.1.4-1cross1",
                "filename": "pool/main/c/cross-toolchain-base/linux-libc-dev-i386-cross_6.1.4-1cross1_all.deb",
                "sha256": "4d464d9fa6f3a30079985e47f97d106318edfc38d87020b0ffe09cbc2d7ff2df",
            },
            {
                "name": "libgcc-12-dev-i386-cross",
                "version": "12.2.0-14cross1",
                "filename": "pool/main/g/gcc-12-cross/libgcc-12-dev-i386-cross_12.2.0-14cross1_all.deb",
                "sha256": "0e4f8934ba2467302cdcc3c74fca09f30152c9c99b99f6b489900339a40ed916",
            },
            {
                "name": "libgcc-s1-i386-cross",
                "version": "12.2.0-14cross1",
                "filename": "pool/main/g/gcc-12-cross/libgcc-s1-i386-cross_12.2.0-14cross1_all.deb",
                "sha256": "0b31dd92565a7dbbc030c7643297d6030ebc4407f41d6f06b30513e6f43e4d31",
            },
            {
                "name": "libstdc++-12-dev-i386-cross",
                "version": "12.2.0-14cross1",
                "filename": "pool/main/g/gcc-12-cross/libstdc++-12-dev-i386-cross_12.2.0-14cross1_all.deb",
                "sha256": "d63165e2605dd9c1740126fd0e4b7faec0eebd3f0f2f62d85b6727777610de6e",
            },
            {
                "name": "libstdc++6-i386-cross",
                "version": "12.2.0-14cross1",
                "filename": "pool/main/g/gcc-12-cross/libstdc++6-i386-cross_12.2.0-14cross1_all.deb",
                "sha256": "2302c4b9f6f705fe55fe039b4a64658df8a841c30ba886e92bc43f1704623e5f",
            },
        ],
    },
    "powerpc": {
        "target": "powerpc-linux-gnu",
        "prefix": "powerpc-linux-gnu",
        "lib_dir": "powerpc-linux-gnu",
        "packages": [
            {
                "name": "libc6-dev-powerpc-cross",
                "version": "2.36-8cross1",
                "filename": "pool/main/c/cross-toolchain-base-ports/libc6-dev-powerpc-cross_2.36-8cross1_all.deb",
                "sha256": "0e7404f947518b30e3607a79762eb8e20d60742be783c36fb6e8dc824bf94f7c",
            },
            {
                "name": "libc6-powerpc-cross",
                "version": "2.36-8cross1",
                "filename": "pool/main/c/cross-toolchain-base-ports/libc6-powerpc-cross_2.36-8cross1_all.deb",
                "sha256": "76d9f5930d8f0b956cac09bda94c08f30b68ea71fe07d88abcbc447e993864cd",
            },
            {
                "name": "linux-libc-dev-powerpc-cross",
                "version": "6.1.4-1cross1",
                "filename": "pool/main/c/cross-toolchain-base-ports/linux-libc-dev-powerpc-cross_6.1.4-1cross1_all.deb",
                "sha256": "e0c284abd22b7efdff2327060dd846d0405d1f0dcfd6e70e39016234e0bced92",
            },
            {
                "name": "libgcc-12-dev-powerpc-cross",
                "version": "12.2.0-13cross1",
                "filename": "pool/main/g/gcc-12-cross-ports/libgcc-12-dev-powerpc-cross_12.2.0-13cross1_all.deb",
                "sha256": "84826eb88f569888deac26ee849b767b9006ae4abe4011e61c14ad7f05529577",
            },
            {
                "name": "libgcc-s1-powerpc-cross",
                "version": "12.2.0-13cross1",
                "filename": "pool/main/g/gcc-12-cross-ports/libgcc-s1-powerpc-cross_12.2.0-13cross1_all.deb",
                "sha256": "7ba63eb8bb4ca392a0cbe8616086e4630f04c768dc0327fe8d2a2c8b258e4b28",
            },
            {
                "name": "libstdc++-12-dev-powerpc-cross",
                "version": "12.2.0-13cross1",
                "filename": "pool/main/g/gcc-12-cross-ports/libstdc++-12-dev-powerpc-cross_12.2.0-13cross1_all.deb",
                "sha256": "86272dcd16116d32f91fe82eee69672c1d590d1c8163f39bb7ec74eeb033b83d",
            },
            {
                "name": "libstdc++6-powerpc-cross",
                "version": "12.2.0-13cross1",
                "filename": "pool/main/g/gcc-12-cross-ports/libstdc++6-powerpc-cross_12.2.0-13cross1_all.deb",
                "sha256": "248999a52b8e3baa8892b9f815d37ede7e2d5af915c373fc8995e43c0517ccb3",
            },
        ],
    },
}


def install_arch(dest: Path, arch: str, cfg: dict, base_url: str, dry_run: bool) -> dict:
    print(f"== {arch} ({cfg['target']})")
    arch_dir = dest / arch
    if not dry_run:
        arch_dir.mkdir(parents=True, exist_ok=True)
    for pkg in cfg["packages"]:
        url = f"{base_url}/{pkg['filename']}"
        print(f"   fetching {pkg['name']} {pkg['version']}")
        data = fetch(url)
        if not verify(pkg["sha256"], data):
            print(
                f"ERROR: SHA256 mismatch for {pkg['name']}: expected {pkg['sha256']}, got {hashlib.sha256(data).hexdigest()}",
                file=sys.stderr,
            )
            sys.exit(1)
        if not dry_run:
            extract_deb(data, arch_dir)
    return {
        "target": cfg["target"],
        "sysroot": str(arch_dir),
        "gcc_path": str(arch_dir / "usr" / "lib" / "gcc-cross" / cfg["prefix"] / "12"),
        "libc_include": str(arch_dir / "usr" / cfg["prefix"] / "include"),
        "libc_lib": str(arch_dir / "usr" / cfg["prefix"] / "lib"),
    }

def smoke_test(manifest: dict) -> None:
    for arch, paths in manifest.items():
        src = f"/tmp/hello_{arch}.c"
        out = f"/tmp/hello_{arch}_real"
        with open(src, "w") as f:
            f.write('#include <stdio.h>\nint main(){ printf("hello\\n"); return 0; }\n')
        target = paths["target"]
        sysroot = paths["sysroot"]
        gcc_path = paths["gcc_path"]
        cmd = [
            "clang",
            f"--target={target}",
            f"--sysroot={sysroot}",
            "-fuse-ld=lld",
            "-O2",
            "-fPIE",
            "-pie",
            src,
            "-o",
            out,
            f"-B{gcc_path}",
            f"-L{gcc_path}",
            f"-I{paths['libc_include']}",
            f"-L{paths['libc_lib']}",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            print(f"ERROR: {arch} link failed:\n{res.stderr}", file=sys.stderr)
            sys.exit(1)
        print(f"   {arch}: linked OK -> {out}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Install pinned Debian cross sysroots.")
    parser.add_argument(
        "--dest",
        default="third_party/sysroots",
        help="Destination directory for sysroots (default: third_party/sysroots)",
    )
    parser.add_argument(
        "--base-url",
        default="https://deb.debian.org/debian",
        help="Debian mirror (default: https://deb.debian.org/debian)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Download packages and verify hashes but do not extract",
    )
    args = parser.parse_args()

    dest = Path(args.dest).resolve()
    if not args.dry_run:
        dest.mkdir(parents=True, exist_ok=True)

    manifest = {}
    for arch, cfg in SYSROOT_PACKAGES.items():
        paths = install_arch(dest, arch, cfg, args.base_url, args.dry_run)
        manifest[arch] = paths

    if not args.dry_run:
        smoke_test(manifest)
        manifest_path = dest / "sysroot-manifest.json"
        with open(manifest_path, "w") as f:
            import json
            json.dump(manifest, f, indent=2)
        print(f"\nWrote manifest: {manifest_path}")
    else:
        print("\nDry run completed; all package hashes verified.")


if __name__ == "__main__":
    main()
