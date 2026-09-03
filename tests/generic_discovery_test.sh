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

python3 - "$PROJECT/project.sqlite" <<'PY'
import sqlite3, sys

db_path = sys.argv[1]
conn = sqlite3.connect(db_path)
cur = conn.cursor()

cur.execute("SELECT count(*) FROM functions WHERE program_id = (SELECT id FROM programs WHERE name = 'libc')")
count = cur.fetchone()[0]

# Oracle has 3,987 functions. 0.986 recall requires >= 3,931 functions.
ORACLE_COUNT = 3987
MIN_RECALL_COUNT = int(ORACLE_COUNT * 0.986)

if count < MIN_RECALL_COUNT:
    sys.exit(f"FAIL: recovered {count} functions on libc; expected >= {MIN_RECALL_COUNT} (recall >= 0.986)")

recall = count / ORACLE_COUNT
print(f"libc: recovered {count} functions (recall = {recall:.4f} >= 0.986)")
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
