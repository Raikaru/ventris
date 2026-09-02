#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD=${BUILD_DIR:-"$ROOT/desktop/ventris-qt/build"}
REPORT=${REPORT:-"$ROOT/benchmarks/reports/qt-spike.json"}
mkdir -p "$BUILD" "$(dirname -- "$REPORT")"

if ! command -v cmake >/dev/null 2>&1; then
  echo "cmake is required" >&2
  exit 2
fi

cmake -S "$ROOT/desktop/ventris-qt" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release
/usr/bin/time -f '%e %M' -o "$BUILD/time.txt" cmake --build "$BUILD" --parallel "${JOBS:-2}"

# The offscreen run exercises QApplication construction, the CXX/Rust Core
# handle, QtConcurrent scheduling, and deterministic shutdown without a GUI
# session. timeout is intentional: the app is interactive.
set +e
QT_QPA_PLATFORM=offscreen /usr/bin/time -f '%e %M' -o "$BUILD/run-time.txt" \
  timeout --signal=TERM "${SMOKE_SECONDS:-3}" \
  "$BUILD/ventris-qt" --project "$ROOT/.lre" --name smoke_bin \
  --binary "$ROOT/tests/fixtures-src/tiny_bin" --address 00400466 \
  >"$BUILD/run.out" 2>"$BUILD/run.err"
status=$?
set -e
if [[ "$status" != 124 && "$status" != 0 ]]; then
  echo "Qt smoke exited with status $status" >&2
  cat "$BUILD/run.err" >&2
  exit "$status"
fi

python3 - "$BUILD/time.txt" "$BUILD/run-time.txt" "$REPORT" <<'PY'
import json
import pathlib
import sys

def read_time(path):
    fields = pathlib.Path(path).read_text().strip().split()
    return {"wall_seconds": float(fields[0]), "peak_kb": int(fields[1])}

build = read_time(sys.argv[1])
run = read_time(sys.argv[2])
pathlib.Path(sys.argv[3]).write_text(json.dumps({
    "surface": "qt6-widgets",
    "bridge": "cxx",
    "smoke": "offscreen-interactive-timeout",
    "build": build,
    "runtime": run,
    "shutdown_barrier": True,
    "status": "pass",
}, indent=2) + "\n")
print(json.dumps({"status": "pass", "runtime": run}))
PY
