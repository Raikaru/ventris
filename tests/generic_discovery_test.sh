#!/usr/bin/env bash
# M1-002 acceptance: verify generic worklist discovery over pcode flow
# achieves fn.recall >= 0.986 on libc and discovers functions on PPC.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ -x "$ROOT/target/release/lre-cli" ]; then
    CLI="${LRE_CLI:-$ROOT/target/release/lre-cli}"
else
    CLI="${LRE_CLI:-$ROOT/target/debug/lre-cli}"
fi
LIBC_BIN="${1:-/usr/lib64/libc.so.6}"
PPC_BIN="/home/raikaru/Projects/agent-under-fire/orig/GQFE78/files/base.elf"

if [ ! -f "$LIBC_BIN" ]; then
    echo "libc binary not found: $LIBC_BIN" >&2
    exit 1
fi

PROJECT="$(mktemp -d /tmp/ventris-m1-002.XXXXXX)"
trap 'rm -rf "$PROJECT"' EXIT

# Step 1: Import libc and verify function count matches or exceeds recall >= 0.986 (>= 3931 functions)
VENTRIS_GENERIC_DISCOVERY=1 "$CLI" import-native "$LIBC_BIN" --name libc --project "$PROJECT" >/dev/null

python3 - "$PROJECT/project.sqlite" "$ROOT/oracle/01cccbe278d898add05282986a9346d4dda4b3d2b84bc496f9c04c66016528db.json" <<'PY'
import json, sqlite3, sys

db_path = sys.argv[1]
oracle_path = sys.argv[2]
with open(oracle_path) as f:
    oracle = {entry.lower().zfill(8) for entry in json.load(f)["entries"]}

conn = sqlite3.connect(db_path)
cur = conn.cursor()

cur.execute("SELECT entry FROM functions WHERE program_id = (SELECT id FROM programs WHERE name = 'libc')")
native = {row[0].lower().zfill(8) for row in cur.fetchall()}

matched = native & oracle
precision = len(matched) / len(native) if native else 0.0
recall = len(matched) / len(oracle) if oracle else 0.0

if recall < 0.986:
    sys.exit(f"FAIL: fn.recall = {recall:.4f} ({len(matched)}/{len(oracle)}) < 0.986 requirement")

if precision < 0.980:
    sys.exit(f"FAIL: fn.precision = {precision:.4f} ({len(matched)}/{len(native)}) < 0.980 requirement")

print(f"libc: fn.precision = {precision:.4f} ({len(matched)}/{len(native)}), fn.recall = {recall:.4f} ({len(matched)}/{len(oracle)}) >= 0.986")
PY

# Step 2: If PPC base.elf exists, verify generic discovery finds PPC functions beyond initial seeds
if [ -f "$PPC_BIN" ]; then
    VENTRIS_GENERIC_DISCOVERY=1 "$CLI" import-native "$PPC_BIN" --name base --project "$PROJECT" >/dev/null
    python3 - "$PROJECT/project.sqlite" <<'PY'
import sqlite3, sys

db_path = sys.argv[1]
conn = sqlite3.connect(db_path)
cur = conn.cursor()

cur.execute("SELECT count(*) FROM functions WHERE program_id = (SELECT id FROM programs WHERE name = 'base')")
count = cur.fetchone()[0]

# Initial symtab has 644 functions. Generic discovery through pcode must find additional functions (> 644)
if count <= 644:
    sys.exit(f"FAIL: generic discovery on PPC recovered {count} functions; expected > 644 (found no additional flow targets)")

print(f"PPC base.elf: recovered {count} functions (> 644 initial seeds)")
PY
fi

echo "m1-002 acceptance: pass"
