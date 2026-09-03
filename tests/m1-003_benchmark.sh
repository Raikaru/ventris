#!/usr/bin/env bash
# m1-003-d acceptance: the m1-003 benchmark report must exist, follow the
# standard gate schema, and record the keep/delete disasm.rs decision.
#
# The report is produced by scripts/bench_m1_003.py (run manually or in CI).
# This script only validates the committed result.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPORT="$ROOT/benchmarks/reports/m1-003.json"

if [[ ! -f "$REPORT" ]]; then
    echo "FAIL: $REPORT not found" >&2
    exit 1
fi

python3 - "$REPORT" <<'PY'
import json, sys
from pathlib import Path

p = Path(sys.argv[1])
with p.open() as f:
    r = json.load(f)

# Standard gate schema (II.2)
for key in ("gate", "milestone", "date", "machine", "targets", "decision", "passed"):
    if key not in r:
        sys.exit(f"FAIL: missing top-level key {key}")

if r["gate"] != "m1-003":
    sys.exit(f"FAIL: gate is {r['gate']}, expected m1-003")

if not isinstance(r["targets"], list) or len(r["targets"]) == 0:
    sys.exit("FAIL: targets must be a non-empty list")

for t in r["targets"]:
    for path in ("hand", "console"):
        if path not in t:
            sys.exit(f"FAIL: target {t.get('id')} missing {path}")
        for m in ("median_wall_s", "count", "precision", "recall"):
            if m not in t[path]:
                sys.exit(f"FAIL: target {t['id']}.{path} missing {m}")

if "speedup" not in r["decision"]:
    sys.exit("FAIL: decision missing speedup")

if "keep_disasm_rs" not in r["decision"]:
    sys.exit("FAIL: decision missing keep_disasm_rs")

if "reason" not in r["decision"]:
    sys.exit("FAIL: decision missing reason")

if not r["passed"]:
    sys.exit(f"FAIL: passed is false; reason: {r['decision'].get('reason')}")

# The decision rule must be present in STATUS.md as a number and a sentence.
status = (ROOT := Path(sys.argv[1]).parent.parent / "STATUS.md").read_text()
if "m1-003-d" not in status:
    sys.exit("FAIL: m1-003-d outcome not recorded in STATUS.md")

print("m1-003-d benchmark acceptance: pass")
PY
