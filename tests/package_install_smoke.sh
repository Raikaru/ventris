#!/usr/bin/env bash
# M0-006 acceptance: build the CPack release archive, extract to a clean
# installation prefix, run the offscreen gate on libc, and verify that all
# six metrics pass (including ui.install.ok: true).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${VENTRIS_BUILD_DIR:-/tmp/ventris-qt-build}"
BINARY="${1:-/usr/lib64/libc.so.6}"

if [ ! -f "$BINARY" ]; then
    echo "binary not found: $BINARY" >&2
    exit 1
fi

# Step 1: Build the CPack package.
cmake --build "$BUILD_DIR" --target package >/dev/null

PACKAGE="$(ls -t "$BUILD_DIR"/ventris-*.tar.gz 2>/dev/null | head -n1)"
if [ -z "$PACKAGE" ] || [ ! -f "$PACKAGE" ]; then
    echo "no CPack package found in $BUILD_DIR" >&2
    exit 1
fi

# Step 2: Extract to a clean temporary installation prefix.
INSTALL_DIR="$(mktemp -d /tmp/ventris-install-smoke.XXXXXX)"
trap 'rm -rf "$INSTALL_DIR"' EXIT

tar -xzf "$PACKAGE" -C "$INSTALL_DIR"

INSTALLED_APP="$(find "$INSTALL_DIR" -name ventris-qt -type f -perm -111 | head -n1)"
if [ -z "$INSTALLED_APP" ] || [ ! -x "$INSTALLED_APP" ]; then
    echo "installed ventris-qt not found in $INSTALL_DIR" >&2
    exit 1
fi

# Step 3: Run the offscreen gate with install validation enabled.
PROJECT="$INSTALL_DIR/project"
REPORT="$INSTALL_DIR/ui-gate.json"

QT_QPA_PLATFORM=offscreen VENTRIS_UI_INSTALL_OK=1 python3 "$ROOT/benchmarks/ui_gate.py" \
    --app "$INSTALLED_APP" \
    --binary "$BINARY" \
    --program libc \
    --project "$PROJECT" \
    --runs 1 \
    --output "$REPORT" >/dev/null

# Step 4: Verify that the gate passed and all metrics satisfied thresholds.
python3 - "$REPORT" <<'PY'
import json, sys

report_path = sys.argv[1]
with open(report_path, "r", encoding="utf-8") as f:
    doc = json.load(f)

if not doc.get("passed"):
    sys.exit(f"gate did not pass: {doc.get('summary')}")

corpus = doc.get("corpus", [])
if not corpus:
    sys.exit("no corpus entries in report")

entry = corpus[0]
if entry.get("status") != "pass":
    sys.exit(f"corpus status is not pass: {entry.get('status')}")

metrics = entry.get("metrics", {})
thresholds = entry.get("thresholds", {})

if not metrics.get("ui.install.ok"):
    sys.exit("ui.install.ok is not true")

for name, threshold in thresholds.items():
    val = metrics.get(name)
    if val is None or not isinstance(val, (int, float)) or val > threshold:
        sys.exit(f"metric {name}={val} exceeds threshold {threshold}")

load_ms = metrics["ui.list.load_ms"]
filter_ms = metrics["ui.list.filter_ms"]
sync_ms = metrics["ui.sync_ms"]
layout_ms = metrics["ui.graph.layout_ms"]
paint_ms = metrics["ui.graph.paint_ms"]

print(
    f"package install acceptance: pass (clean install from {entry['id']}: "
    f"load={load_ms:.2f}ms, filter={filter_ms:.2f}ms, sync={sync_ms:.2f}ms, "
    f"layout={layout_ms:.2f}ms, paint={paint_ms:.2f}ms, install=ok)"
)
PY
