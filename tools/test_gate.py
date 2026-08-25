#!/usr/bin/env python3
"""Runs the Rust test suite and fails loudly when nothing ran.

`cargo test` reports a compile failure in test-only code by printing an error and
producing *no* test results. A filter that looks for the word `FAILED` therefore
reports green over zero tests, which has silently passed a broken suite twice in
this repository's history: once when a blind rename made a function call itself,
and once when `cargo fix` removed six imports that only `cfg(test)` code used.

The fix is to assert on what a passing run must contain rather than on the absence
of a word: at least one result line per test binary, a known-minimum total, and
zero failures.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

RESULT = re.compile(
    r"test result: (?P<status>\w+)\. (?P<passed>\d+) passed; (?P<failed>\d+) failed"
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--minimum",
        type=int,
        default=1,
        help="fail when fewer than this many tests ran at all",
    )
    parser.add_argument(
        "--cargo",
        default="cargo",
        help="cargo executable",
    )
    args, passthrough = parser.parse_known_args(argv)

    command = [args.cargo, "test", "--workspace", "--locked", *passthrough]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    output = completed.stdout + completed.stderr

    results = list(RESULT.finditer(output))
    passed = sum(int(match["passed"]) for match in results)
    failed = sum(int(match["failed"]) for match in results)
    compile_errors = [
        line
        for line in output.splitlines()
        if line.startswith("error") and "test failed" not in line
    ]

    print(f"test-gate: binaries={len(results)} passed={passed} failed={failed}")
    if compile_errors:
        print(f"test-gate: FAIL {len(compile_errors)} compile errors", file=sys.stderr)
        for line in compile_errors[:5]:
            print(f"  {line}", file=sys.stderr)
        return 1
    if not results:
        print(
            "test-gate: FAIL no test results at all — the suite did not run",
            file=sys.stderr,
        )
        return 1
    if passed < args.minimum:
        print(
            f"test-gate: FAIL only {passed} tests ran, expected at least {args.minimum}",
            file=sys.stderr,
        )
        return 1
    if failed:
        print(f"test-gate: FAIL {failed} tests failed", file=sys.stderr)
        for line in output.splitlines():
            if "FAILED" in line or "panicked at" in line:
                print(f"  {line.strip()}", file=sys.stderr)
        return 1
    if completed.returncode != 0:
        print(
            f"test-gate: FAIL cargo exited {completed.returncode} with no failed test",
            file=sys.stderr,
        )
        return 1
    print("test-gate: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
