#!/usr/bin/env bash
# m1-003 acceptance: flow_discover and sweep_calls for x86 must reach the
# same entry-address set whether the in-Rust hand decoder or the console
# flow request is doing the work.
#
# This test is intentionally committed while the console path is unwired, so
# it fails.  It will pass once m1-003-c lands.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -f /usr/lib64/libc.so.6 ]]; then
    echo "SKIP: /usr/lib64/libc.so.6 not present"
    exit 77
fi

BIN=/usr/lib64/libc.so.6
HAND_PROJECT=/tmp/m1-003-hand
CONSOLE_PROJECT=/tmp/m1-003-console
rm -rf "$HAND_PROJECT" "$CONSOLE_PROJECT"

cargo build -q -p lre-cli
HAND=target/debug/lre-cli

$HAND import-native "$BIN" --name libc --project "$HAND_PROJECT" 2>/dev/null
$HAND functions libc --project "$HAND_PROJECT" \
    | awk 'NF==3 {print $1}' | sort > /tmp/m1-003-hand.txt

cargo build -q -p lre-cli --no-default-features
CONSOLE=target/debug/lre-cli

$CONSOLE import-native "$BIN" --name libc --project "$CONSOLE_PROJECT" 2>/dev/null
$CONSOLE functions libc --project "$CONSOLE_PROJECT" \
    | awk 'NF==3 {print $1}' | sort > /tmp/m1-003-console.txt

HAND_COUNT=$(wc -l < /tmp/m1-003-hand.txt)
CONSOLE_COUNT=$(wc -l < /tmp/m1-003-console.txt)
INTERSECTION=$(comm -12 /tmp/m1-003-hand.txt /tmp/m1-003-console.txt | wc -l)

precision="0"
recall="0"
if [[ $CONSOLE_COUNT -gt 0 ]]; then
    precision=$(awk -v I="$INTERSECTION" -v C="$CONSOLE_COUNT" 'BEGIN { printf "%.6f", I/C }')
fi
if [[ $HAND_COUNT -gt 0 ]]; then
    recall=$(awk -v I="$INTERSECTION" -v H="$HAND_COUNT" 'BEGIN { printf "%.6f", I/H }')
fi

echo "fn.precision = $precision"
echo "fn.recall = $recall"

if diff -q /tmp/m1-003-hand.txt /tmp/m1-003-console.txt >/dev/null; then
    exit 0
fi

echo "set difference (hand has, console does not):" >&2
comm -23 /tmp/m1-003-hand.txt /tmp/m1-003-console.txt | head -20 >&2

echo "set difference (console has, hand does not):" >&2
comm -13 /tmp/m1-003-hand.txt /tmp/m1-003-console.txt | head -20 >&2

exit 1
