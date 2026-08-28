#!/usr/bin/env python3
"""Copy a directory to an SSH host, resumably, over a link that drops.

`scp -r` restarts from zero when the connection dies, so on a flaky link a large
tree may never finish. This tool makes progress monotonic instead: it compares a
local inventory against the remote one, sends only what is missing or the wrong
size, and does it in bounded batches so a drop costs one batch rather than the
whole transfer.

Each batch streams through `tar` over a single ssh connection, which is far
faster than one connection per file for a tree with thousands of small ones.

Modes do *not* survive a Windows source. NTFS has no executable bit, so every
file arrives `rw-r--r--`. Both of Ghidra's executable kinds break, and each
fails later and less obviously than the last: `support/analyzeHeadless` simply
will not launch, and the native `Decompiler/os/linux_x86_64/decompile` gets far
enough to import a program before dying with "cannot open decompiler: Exec
failed, error: 13". `--fix-exec-bits` restores the bit on both - scripts by
their `#!` prefix, native binaries by their ELF magic.

Idempotent by construction: run it again after a failure, or after changing a
few files, and it sends only the difference.
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence

SSH_OPTIONS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5"]


def run_ssh(host: str, command: str, timeout: float = 120.0) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["ssh", *SSH_OPTIONS, host, command],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def local_inventory(root: Path, excludes: Sequence[str]) -> dict[str, int]:
    """Maps each file's POSIX-style relative path to its size."""
    found: dict[str, int] = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if any(fnmatch.fnmatch(relative, pattern) for pattern in excludes):
            continue
        if any(fnmatch.fnmatch(part, pattern) for pattern in excludes for part in relative.split("/")):
            continue
        found[relative] = path.stat().st_size
    return found


def remote_inventory(host: str, dest: PurePosixPath) -> dict[str, int]:
    completed = run_ssh(
        host, f"test -d {dest} && find {dest} -type f -printf '%P\\t%s\\n' || true"
    )
    found: dict[str, int] = {}
    for line in completed.stdout.splitlines():
        if "\t" not in line:
            continue
        name, _, size = line.rpartition("\t")
        try:
            found[name] = int(size)
        except ValueError:
            continue
    return found


def batches(names: Iterable[str], sizes: dict[str, int], budget: int) -> list[list[str]]:
    """Groups files so each batch is roughly `budget` bytes.

    A batch is the unit of loss when the link drops, so it is bounded by bytes
    rather than by file count: one 200 MB file and two thousand 4 KB ones should
    both cost about the same to retry.
    """
    grouped: list[list[str]] = []
    current: list[str] = []
    accumulated = 0
    for name in names:
        current.append(name)
        accumulated += sizes.get(name, 0)
        if accumulated >= budget:
            grouped.append(current)
            current, accumulated = [], 0
    if current:
        grouped.append(current)
    return grouped


def send_batch(host: str, root: Path, dest: PurePosixPath, names: Sequence[str]) -> tuple[bool, str]:
    """Streams one batch through tar; returns success and any error text."""
    listing = "\n".join(names) + "\n"
    tar_create = [
        "tar",
        "-C",
        os.fspath(root),
        "-cf",
        "-",
        "--files-from=-",
    ]
    receive = f"mkdir -p {dest} && tar -C {dest} -xf -"
    try:
        creator = subprocess.Popen(
            tar_create, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        receiver = subprocess.Popen(
            ["ssh", *SSH_OPTIONS, host, receive],
            stdin=creator.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if creator.stdout is not None:
            creator.stdout.close()
        assert creator.stdin is not None
        creator.stdin.write(listing.encode("utf-8"))
        creator.stdin.close()
        _, receiver_error = receiver.communicate(timeout=900)
        creator.wait(timeout=60)
    except subprocess.TimeoutExpired:
        for process in (locals().get("creator"), locals().get("receiver")):
            if process is not None:
                process.kill()
        return False, "timed out"
    except Exception as error:  # noqa: BLE001 - report and let the retry decide
        return False, str(error)
    if receiver.returncode != 0:
        return False, receiver_error.decode("utf-8", "replace").strip()[-300:]
    return True, ""


def restore_exec_bits(host: str, dest: PurePosixPath) -> tuple[int, str]:
    """Restores the executable bit on remote scripts and native binaries.

    Two kinds of file need it, and missing either fails late and obscurely:

    * scripts, identified by a `#!` prefix - Ghidra's `support/analyzeHeadless`;
    * ELF binaries, identified by the `\\x7fELF` magic - Ghidra ships native
      helpers under `Features/*/os/<platform>/`, and a non-executable
      `Decompiler/os/linux_x86_64/decompile` surfaces only once a decompilation
      is attempted, as "cannot open decompiler: Exec failed, error: 13".

    Written as POSIX `sh` with no process substitution, because the remote login
    shell is not guaranteed to be bash - an earlier attempt using
    `< <(find ...)` silently reported zero changes on a tree full of shebangs.
    `od` reads the magic, since `sh` cannot hold NUL bytes in a variable.
    """
    script = (
        f"cd {dest} || exit 1; n=0; "
        "for f in $(find . -type f ! -name '*.jar' ! -name '*.zip' ! -name '*.bat' "
        "! -name '*.class' ! -name '*.txt' ! -name '*.html'); do "
        'head -c 2 "$f" 2>/dev/null | grep -q "^#!" && { chmod +x "$f"; n=$((n+1)); continue; }; '
        'if [ "$(od -A n -t x1 -N 4 "$f" 2>/dev/null | tr -d " ")" = "7f454c46" ]; then '
        'chmod +x "$f"; n=$((n+1)); fi; '
        'done; echo "chmod_count=$n"'
    )
    completed = run_ssh(host, script, timeout=900)
    for line in completed.stdout.splitlines():
        if line.startswith("chmod_count="):
            return int(line.split("=")[1]), ""
    return 0, (completed.stderr or completed.stdout).strip()[-300:]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--src", required=True, type=Path)
    parser.add_argument("--dest", required=True, help="remote directory")
    parser.add_argument("--exclude", action="append", default=[], help="glob, repeatable")
    parser.add_argument("--batch-mb", type=float, default=24.0)
    parser.add_argument("--passes", type=int, default=8, help="retry sweeps before giving up")
    parser.add_argument(
        "--fix-exec-bits",
        action="store_true",
        help="restore executable bits lost when syncing from Windows",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.src.expanduser().resolve()
    if not root.is_dir():
        print(f"{root} is not a directory", file=sys.stderr)
        return 2
    dest = PurePosixPath(args.dest)

    wanted = local_inventory(root, args.exclude)
    total_bytes = sum(wanted.values())
    print(f"local: {len(wanted)} files, {total_bytes / 1e6:.1f} MB")

    for attempt in range(1, args.passes + 1):
        try:
            present = remote_inventory(args.host, dest)
        except subprocess.TimeoutExpired:
            print(f"pass {attempt}: could not read remote inventory; retrying")
            time.sleep(5 * attempt)
            continue
        missing = [name for name, size in wanted.items() if present.get(name) != size]
        if not missing:
            print(f"in sync: {len(wanted)} files present at the right size")
            if args.fix_exec_bits:
                count, error = restore_exec_bits(args.host, dest)
                if error:
                    print(f"could not restore executable bits: {error}")
                    return 1
                print(f"restored the executable bit on {count} files")
            return 0
        missing_bytes = sum(wanted[name] for name in missing)
        print(
            f"pass {attempt}: {len(missing)} files / {missing_bytes / 1e6:.1f} MB to send"
        )
        groups = batches(sorted(missing), wanted, int(args.batch_mb * 1e6))
        for index, group in enumerate(groups, 1):
            size = sum(wanted[name] for name in group) / 1e6
            ok, error = send_batch(args.host, root, dest, group)
            state = "ok" if ok else f"FAILED ({error})"
            print(f"  batch {index}/{len(groups)}  {len(group):5d} files  {size:7.1f} MB  {state}")
            if not ok:
                time.sleep(3)
        time.sleep(2)

    present = remote_inventory(args.host, dest)
    still = [name for name, size in wanted.items() if present.get(name) != size]
    print(f"gave up after {args.passes} passes; {len(still)} files still missing")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
