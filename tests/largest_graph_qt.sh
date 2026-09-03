#!/usr/bin/env bash
# M0-004 acceptance: locate the largest-BB function (>= 200 basic blocks)
# and measure/verify Qt layout and paint execution within frozen thresholds.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="${LRE_CLI:-$ROOT/target/debug/lre-cli}"
APP="${VENTRIS_QT_APP:-/tmp/ventris-qt-build/ventris-qt}"
BINARY="${1:-/usr/lib64/libc.so.6}"
PROGRAM="${PROGRAM:-largest-target}"

if [ ! -f "$BINARY" ]; then
    echo "binary not found: $BINARY" >&2
    exit 1
fi

if [ ! -x "$APP" ]; then
    echo "Qt app not found or not executable: $APP" >&2
    exit 1
fi

# Step 1: Locate largest-BB function and assert >= 200 basic blocks.
PROJECT="$(mktemp -d /tmp/ventris-largest-bb-qt.XXXXXX)"
trap 'rm -rf "$PROJECT"' EXIT

"$CLI" import-native "$BINARY" --name "$PROGRAM" --project "$PROJECT" >/dev/null
largest_json="$("$CLI" graph "$PROGRAM" --largest --binary "$BINARY" --project "$PROJECT")"

largest_info="$(printf '%s' "$largest_json" | python3 -c '
import json, sys
data = json.load(sys.stdin)
blocks = data.get("blocks", 0)
if blocks < 200:
    sys.exit(f"expected >= 200 blocks, got {blocks}")
name = data.get("name", "")
addr = data.get("address", "")
print(f"{name}|{addr}|{blocks}")
')"

IFS='|' read -r fn_name fn_addr fn_blocks <<< "$largest_info"

# Step 2: Measure Qt layout and paint execution via offscreen gate.
REPORT="$PROJECT/ui-gate.json"
QT_QPA_PLATFORM=offscreen python3 "$ROOT/benchmarks/ui_gate.py" \
    --app "$APP" \
    --binary "$BINARY" \
    --program "$PROGRAM" \
    --project "$PROJECT" \
    --runs 1 \
    --output "$REPORT" >/dev/null || true

# Step 3: Verify metrics against frozen thresholds.
python3 - "$REPORT" "$fn_name" "$fn_addr" "$fn_blocks" <<'PY'
import json, sys

report_path, name, addr, blocks = sys.argv[1:5]
with open(report_path, "r", encoding="utf-8") as f:
    doc = json.load(f)

corpus = doc.get("corpus", [])
if not corpus:
    sys.exit("no corpus entries in gate report")

metrics = corpus[0].get("metrics", {})
thresholds = corpus[0].get("thresholds", {})

layout_ms = metrics.get("ui.graph.layout_ms")
paint_ms = metrics.get("ui.graph.paint_ms")
layout_threshold = thresholds.get("ui.graph.layout_ms", 200.0)
paint_threshold = thresholds.get("ui.graph.paint_ms", 50.0)

if layout_ms is None or not isinstance(layout_ms, (int, float)) or layout_ms <= 0:
    sys.exit(f"invalid ui.graph.layout_ms: {layout_ms}")

if paint_ms is None or not isinstance(paint_ms, (int, float)) or paint_ms <= 0:
    sys.exit(f"invalid ui.graph.paint_ms: {paint_ms}")

if layout_ms > layout_threshold:
    sys.exit(f"ui.graph.layout_ms {layout_ms:.2f} exceeds threshold {layout_threshold}")

if paint_ms > paint_threshold:
    sys.exit(f"ui.graph.paint_ms {paint_ms:.2f} exceeds threshold {paint_threshold}")

print(f"largest-BB Qt layout/paint acceptance: pass ({name} at {addr}, {blocks} blocks: layout={layout_ms:.2f}ms, paint={paint_ms:.2f}ms)")
PY
