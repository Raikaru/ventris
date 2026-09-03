#!/usr/bin/env bash
# M0-007 acceptance: verify recovery of RIP-relative data xrefs, CRT helpers,
# and complete branch/call xref kinds in the native import pipeline.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="${LRE_CLI:-$ROOT/target/debug/lre-cli}"
TINY_BIN="$ROOT/tests/fixtures-src/tiny_bin"
LIBC_BIN="${1:-/usr/lib64/libc.so.6}"

if [ ! -f "$TINY_BIN" ]; then
    echo "fixture not found: $TINY_BIN" >&2
    exit 1
fi

PROJECT="$(mktemp -d /tmp/ventris-data-xrefs.XXXXXX)"
trap 'rm -rf "$PROJECT"' EXIT

# Step 1: Import tiny_bin and verify CRT helper discovery + all 4 xref kinds
"$CLI" import-native "$TINY_BIN" --name tiny --project "$PROJECT" >/dev/null

python3 - "$PROJECT/project.sqlite" <<'PY'
import sqlite3, sys

db_path = sys.argv[1]
conn = sqlite3.connect(db_path)
cur = conn.cursor()

cur.execute("SELECT name FROM functions")
names = {r[0] for r in cur.fetchall()}

required_crt = {"_init", "_fini", "register_tm_clones", "deregister_tm_clones", "main", "add"}
missing = required_crt - names
if missing:
    sys.exit(f"missing expected CRT/function symbols: {missing}")

cur.execute("SELECT DISTINCT kind FROM xrefs")
kinds = {r[0] for r in cur.fetchall()}

required_kinds = {"DATA", "UNCONDITIONAL_CALL", "CONDITIONAL_JUMP", "UNCONDITIONAL_JUMP"}
missing_kinds = required_kinds - kinds
if missing_kinds:
    sys.exit(f"missing expected xref kinds in tiny_bin: {missing_kinds}")

cur.execute("SELECT count(*) FROM xrefs WHERE kind = 'DATA'")
data_count = cur.fetchone()[0]
if data_count <= 0:
    sys.exit("expected > 0 DATA xrefs in tiny_bin")

print(f"tiny_bin: verified {len(names)} functions (including CRT) and {len(kinds)} xref kinds ({data_count} DATA xrefs)")
PY

# Step 2: If libc is present, verify scale data xref recovery (>= 1,000)
if [ -f "$LIBC_BIN" ]; then
    "$CLI" import-native "$LIBC_BIN" --name libc --project "$PROJECT" >/dev/null
    python3 - "$PROJECT/project.sqlite" <<'PY'
import sqlite3, sys

db_path = sys.argv[1]
conn = sqlite3.connect(db_path)
cur = conn.cursor()

cur.execute("SELECT program_id FROM functions WHERE name = '__vfscanf_internal' LIMIT 1")
row = cur.fetchone()
if not row:
    sys.exit("libc functions not found")
libc_pid = row[0]

cur.execute("SELECT count(*) FROM xrefs WHERE program_id = ? AND kind = 'DATA'", (libc_pid,))
libc_data = cur.fetchone()[0]
if libc_data < 1000:
    sys.exit(f"expected >= 1000 DATA xrefs on libc, got {libc_data}")

print(f"data xrefs acceptance: pass (recovered {libc_data} DATA xrefs on libc)")
PY
else
    echo "data xrefs acceptance: pass (tiny_bin verified; libc skipped)"
fi
