#!/usr/bin/env bash
# M0-003 acceptance: locate a native-imported function with at least 200
# recovered basic blocks.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="${LRE_CLI:-$ROOT/target/debug/lre-cli}"
BINARY="${1:?usage: $0 /path/to/binary}"
PROGRAM="${PROGRAM:-largest-target}"
PROJECT="$(mktemp -d /tmp/ventris-largest-graph.XXXXXX)"
trap 'rm -rf "$PROJECT"' EXIT

"$CLI" import-native "$BINARY" --name "$PROGRAM" --project "$PROJECT" >/dev/null
result="$("$CLI" graph "$PROGRAM" --largest --binary "$BINARY" --project "$PROJECT")"

printf '%s' "$result" | python3 -c '
import json
import sys

result = json.load(sys.stdin)
blocks = result.get("blocks")
if not isinstance(blocks, int) or blocks < 200:
    raise SystemExit(f"largest function has {blocks!r} basic blocks; expected >= 200")
if not result.get("address") or not result.get("name"):
    raise SystemExit(f"largest function is missing address/name: {result!r}")
name = result["name"]
address = result["address"]
print(f"largest-BB acceptance: pass ({name} at {address}, {blocks} blocks)")
'
