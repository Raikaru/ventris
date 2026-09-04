#!/usr/bin/env bash
# m1-003-e acceptance: batched flow in the console must complete console-path
# libc import in under 5.0 seconds.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -f /usr/lib64/libc.so.6 ]]; then
    echo "SKIP: /usr/lib64/libc.so.6 not present"
    exit 77
fi

BIN=/usr/lib64/libc.so.6
CONSOLE_PROJECT=/tmp/m1-003-batched-console
rm -rf "$CONSOLE_PROJECT"

cargo build -q -p lre-cli --no-default-features
CONSOLE=target/debug/lre-cli

START=$(python3 -c 'import time; print(time.time())')
$CONSOLE import-native "$BIN" --name libc --project "$CONSOLE_PROJECT" 2>/dev/null
END=$(python3 -c 'import time; print(time.time())')

ELAPSED=$(python3 -c "print($END - $START)")
echo "console-path libc import wall time: ${ELAPSED}s"

UNDER_5S=$(python3 -c "print(1 if $ELAPSED < 5.0 else 0)")
if [[ $UNDER_5S -ne 1 ]]; then
    echo "FAIL: console-path libc import took ${ELAPSED}s >= 5.0s" >&2
    exit 1
fi

echo "m1-003-e: PASS (${ELAPSED}s < 5.0s)"
