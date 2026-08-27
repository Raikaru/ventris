#!/usr/bin/env python3
"""Run every gate once and print one summary.

The gates were being driven by hand, which cost more than the gates themselves.
Two wastes in particular:

* ``cargo test`` was run twice per iteration - once to grep for failures, once to
  sum the per-target ``test result:`` lines into a total. Compilation is the
  entire cost of that command, so the second run was pure duplication.
* ``cargo build`` and ``cargo test`` were run separately even though the tests
  cannot pass without the build succeeding, so a broken build paid for two
  compile attempts before reporting.

This runs each stage once, in dependency order, and stops at the first stage
that fails. The census needs the release binary, so it follows the build; the
corpus gate and the census are independent of each other and run together.

Timings are printed per stage because a gate that has quietly become slow is a
gate that stops being run.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_IMAGE_DIR = Path("C:/tmp/plinth-real-corpus")
DEFAULT_GHIDRA = Path("C:/tools/ghidra_12.1.3_PUBLIC")
DEFAULT_CENSUS_OUT = Path("C:/tmp/census-cur")

TEST_RESULT = re.compile(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed", re.M)


class Stage:
    def __init__(self, name: str) -> None:
        self.name = name
        self.seconds = 0.0
        self.ok = False
        self.detail = ""


def run(args: list[str], cwd: Path = ROOT, env: dict[str, str] | None = None):
    merged = dict(os.environ)
    if env:
        merged.update(env)
    return subprocess.run(
        args, cwd=os.fspath(cwd), capture_output=True, text=True, env=merged
    )


def stage_build() -> Stage:
    stage = Stage("build")
    start = time.time()
    completed = run(["cargo", "build", "--release", "-q"])
    stage.seconds = time.time() - start
    stage.ok = completed.returncode == 0
    if not stage.ok:
        errors = [
            line
            for line in completed.stderr.splitlines()
            if line.startswith("error") or "-->" in line
        ]
        stage.detail = "\n".join(errors[:20]) or completed.stderr[-2000:]
    return stage


def stage_tests(package: str | None) -> Stage:
    """Runs the suite once and reads both the failures and the totals from it."""
    stage = Stage("tests" if package is None else f"tests({package})")
    args = ["cargo", "test", "--release", "-q"]
    if package is not None:
        args += ["-p", package, "--lib"]
    start = time.time()
    completed = run(args)
    stage.seconds = time.time() - start
    passed = failed = 0
    for status, ok_count, fail_count in TEST_RESULT.findall(completed.stdout):
        passed += int(ok_count)
        failed += int(fail_count)
    stage.ok = completed.returncode == 0 and failed == 0
    if stage.ok:
        stage.detail = f"{passed} passing"
    else:
        names = [
            line.strip().removesuffix(" --- FAILED")
            for line in completed.stdout.splitlines()
            if line.rstrip().endswith("--- FAILED")
        ]
        stage.detail = f"{passed} passing, {failed} failing"
        if names:
            stage.detail += "\n  " + "\n  ".join(names[:20])
        elif completed.returncode != 0:
            stage.detail += "\n  " + completed.stderr.strip()[-1500:]
    return stage


def stage_corpus(image_dir: Path) -> Stage:
    stage = Stage("corpus")
    start = time.time()
    completed = run(
        [
            sys.executable,
            os.fspath(ROOT / "tools" / "corpus_smoke.py"),
            "--image-dir",
            os.fspath(image_dir),
            "--ventris",
            os.fspath(ROOT / "target" / "release" / "ventris.exe"),
            "--json",
        ]
    )
    stage.seconds = time.time() - start
    stage.ok = completed.returncode == 0
    try:
        report = json.loads(completed.stdout)
        entries = report.get("entries", [])
        functions = sum(len(entry.get("functions", [])) for entry in entries)
        failures = [
            f"{entry.get('id')}/{function.get('name')}"
            for entry in entries
            for function in entry.get("functions", [])
            if function.get("status") != "pass"
        ]
        stage.detail = f"{functions} functions, {len(failures)} failing"
        if failures:
            stage.detail += "\n  " + "\n  ".join(failures[:20])
            stage.ok = False
    except json.JSONDecodeError:
        stage.detail = completed.stderr.strip()[-1500:]
    return stage


def stage_census(image_dir: Path, ghidra: Path, out: Path, reuse: bool) -> Stage:
    stage = Stage("census")
    destination = Path("C:/tmp/census-gate.json")
    args = [
        sys.executable,
        os.fspath(ROOT / "tools" / "quality_census.py"),
        "--image-dir",
        os.fspath(image_dir),
        "--ventris",
        os.fspath(ROOT / "target" / "release" / "ventris.exe"),
        "--ghidra",
        os.fspath(ghidra),
        "--out",
        os.fspath(out),
        "--json",
        "--jobs",
        str(os.cpu_count() or 8),
    ]
    if reuse:
        args.append("--reuse-oracle")
    start = time.time()
    completed = run(args)
    stage.seconds = time.time() - start
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError:
        stage.ok = False
        stage.detail = completed.stderr.strip()[-1500:]
        return stage
    destination.write_text(json.dumps(report, indent=1), encoding="utf-8")
    families = sorted(
        ((family["family"], family["functions"]) for family in report["families"]),
        key=lambda row: -row[1],
    )
    stage.ok = True
    stage.detail = "  ".join(f"{name}={count}" for name, count in families)
    return stage


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-dir", type=Path, default=DEFAULT_IMAGE_DIR)
    parser.add_argument("--ghidra", type=Path, default=DEFAULT_GHIDRA)
    parser.add_argument("--census-out", type=Path, default=DEFAULT_CENSUS_OUT)
    parser.add_argument(
        "--fresh-oracle",
        action="store_true",
        help="re-export the Ghidra oracle instead of reusing the cached one",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="build and the decompiler's own lib tests only; skips both corpora",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    stages: list[Stage] = []

    build = stage_build()
    stages.append(build)
    if not build.ok:
        report(stages)
        return 1

    if args.quick:
        stages.append(stage_tests("ventris-decompiler"))
        return report(stages)

    # The suite is independent of both corpora, and the corpora are independent
    # of each other, so all three run at once. The build had to finish first
    # because the corpora exercise the binary it produces.
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = [
            pool.submit(stage_tests, None),
            pool.submit(stage_corpus, args.image_dir),
            pool.submit(
                stage_census,
                args.image_dir,
                args.ghidra,
                args.census_out,
                not args.fresh_oracle,
            ),
        ]
        stages.extend(future.result() for future in futures)
    return report(stages)


def report(stages: list[Stage]) -> int:
    width = max(len(stage.name) for stage in stages)
    total = sum(stage.seconds for stage in stages)
    print()
    for stage in stages:
        mark = "ok  " if stage.ok else "FAIL"
        print(f"{mark} {stage.name:{width}}  {stage.seconds:6.1f}s  {stage.detail}")
    print(f"     {'wall':{width}}  {total:6.1f}s (stages after the build run together)")
    return 0 if all(stage.ok for stage in stages) else 1


if __name__ == "__main__":
    raise SystemExit(main())
