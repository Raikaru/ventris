#!/usr/bin/env bash
# M0-005 acceptance: verify that ui.list.filter_ms on a fresh libc import
# strictly satisfies the frozen <= 100.0 ms threshold.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="${VENTRIS_QT_APP:-/tmp/ventris-qt-build/ventris-qt}"
BINARY="${1:-/usr/lib64/libc.so.6}"
PROGRAM="${PROGRAM:-libc}"

if [ ! -f "$BINARY" ]; then
    echo "binary not found: $BINARY" >&2
    exit 1
fi

if [ ! -x "$APP" ]; then
    echo "Qt app not found or not executable: $APP" >&2
    exit 1
fi

PROJECT="$(mktemp -d /tmp/ventris-filter-test.XXXXXX)"
trap 'rm -rf "$PROJECT"' EXIT

REPORT="$PROJECT/ui-gate.json"
QT_QPA_PLATFORM=offscreen python3 "$ROOT/benchmarks/ui_gate.py" \
    --app "$APP" \
    --binary "$BINARY" \
    --program "$PROGRAM" \
    --project "$PROJECT" \
    --runs 1 \
    --output "$REPORT" >/dev/null || true

python3 - "$REPORT" <<'PY'
import json, sys

report_path = sys.argv[1]
with open(report_path, "r", encoding="utf-8") as f:
    doc = json.load(f)

corpus = doc.get("corpus", [])
if not corpus:
    sys.exit("no corpus entries in gate report")

metrics = corpus[0].get("metrics", {})
thresholds = corpus[0].get("thresholds", {})

filter_ms = metrics.get("ui.list.filter_ms")
load_ms = metrics.get("ui.list.load_ms")
filter_threshold = thresholds.get("ui.list.filter_ms", 100.0)
load_threshold = thresholds.get("ui.list.load_ms", 500.0)

if filter_ms is None or not isinstance(filter_ms, (int, float)) or filter_ms <= 0:
    sys.exit(f"invalid ui.list.filter_ms: {filter_ms}")

if load_ms is None or not isinstance(load_ms, (int, float)) or load_ms <= 0:
    sys.exit(f"invalid ui.list.load_ms: {load_ms}")

if filter_ms > filter_threshold:
    sys.exit(f"ui.list.filter_ms {filter_ms:.2f} ms exceeds threshold {filter_threshold} ms")

if load_ms > load_threshold:
    sys.exit(f"ui.list.load_ms {load_ms:.2f} ms exceeds threshold {load_threshold} ms")

print(f"filter latency acceptance: pass (fresh import on libc: load={load_ms:.2f}ms, filter={filter_ms:.2f}ms <= {filter_threshold}ms)")
PY
