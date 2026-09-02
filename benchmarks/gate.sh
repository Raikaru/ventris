#!/usr/bin/env bash
# Stage-4 gate: the full JVM-free supported workflow, measured and bounded.
#
#   import-native -> functions -> xrefs -> rename -> open -> disasm-native
#   -> decompile-native        (the JVM never starts; the bridge is not used)
#
# Asserts peak RSS per native phase stays under GATE_KB (default 100000 KB
# = 100 MB; the stock-Ghidra baseline is ~375 MiB peak) and total wall time
# under GATE_WALL_S (default 120 s). Writes benchmarks/reports/stage4-gate.json.
#
# Env: VENTRIS_SLA (required; compiled x86-64.sla), VENTRIS_GHIDRA
#      (install root), VENTRIS_CONSOLE (optional; else native/build or
#      /tmp/spike), RUNS (default 3).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:-$ROOT/tests/fixtures-src/tiny_bin}"
OUTDIR="${2:-/tmp/lre-gate-run}"
RUNS="${RUNS:-3}"
GATE_KB="${GATE_KB:-100000}"
GATE_WALL_S="${GATE_WALL_S:-120}"
CLI="$ROOT/target/debug/lre-cli"

[ -x "$ROOT/native/build/ghidra_opt" ] || {
    echo "missing native/build/ghidra_opt — build: native/build_ghidra_opt.sh" >&2
    exit 1
}
[ -n "${VENTRIS_SLA:-}" ] || {
    echo "set VENTRIS_SLA to a compiled x86-64.sla" >&2
    exit 1
}
CONSOLE="${VENTRIS_CONSOLE:-$ROOT/native/build/decomp_native}"
[ -x "$CONSOLE" ] || CONSOLE=/tmp/spike/decomp_native
[ -x "$CONSOLE" ] || {
    echo "no SLEIGH console — set VENTRIS_CONSOLE or build native/build_console.sh" >&2
    exit 1
}
export VENTRIS_CONSOLE="$CONSOLE"
export VENTRIS_SLA

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

results="[]"
for i in $(seq 1 "$RUNS"); do
    PROJECT="$OUTDIR/gate-project-$i"
    start=$(date +%s.%N)

    # import-native (no JVM): parse + flow discovery + store
    /usr/bin/time -v "$CLI" import-native "$BIN" --name gate --project "$PROJECT" \
        > "$OUTDIR/import_$i.out" 2> "$OUTDIR/import_$i.time" || { cat "$OUTDIR/import_$i.out" >&2; exit 1; }
    # store-only facts (no JVM)
    "$CLI" functions gate --project "$PROJECT" > "$OUTDIR/functions_$i.out"
    "$CLI" xrefs gate --to 00400466 --project "$PROJECT" > "$OUTDIR/xrefs_$i.out"
    "$CLI" rename gate 00400466 gate_add --project "$PROJECT" > /dev/null
    "$CLI" open gate --project "$PROJECT" > "$OUTDIR/open_$i.out"
    # disasm-native (SLEIGH console, no JVM)
    /usr/bin/time -v "$CLI" disasm-native "$BIN" 00400466 -n 4 \
        > "$OUTDIR/disasm_$i.out" 2> "$OUTDIR/disasm_$i.time" || { cat "$OUTDIR/disasm_$i.out" >&2; exit 1; }
    # decompile-native (patched ghidra_opt, no JVM)
    /usr/bin/time -v "$CLI" decompile-native "$BIN" 00400466 --name gate --project "$PROJECT" \
        > "$OUTDIR/decompile_$i.out" 2> "$OUTDIR/decompile_$i.time" || { cat "$OUTDIR/decompile_$i.out" >&2; exit 1; }

    end=$(date +%s.%N)
    elapsed=$(echo "$end - $start" | bc)
    rss() { grep 'Maximum resident set size' "$1" | grep -o '[0-9]*' || echo 0; }
    results=$(python3 -c "
import json, sys
r = json.loads(sys.argv[1])
r.append({
  'run': $i, 'wall_s': round($elapsed, 2),
  'import_kb': int('$(rss "$OUTDIR/import_$i.time")'),
  'disasm_kb': int('$(rss "$OUTDIR/disasm_$i.time")'),
  'decompile_kb': int('$(rss "$OUTDIR/decompile_$i.time")'),
})
print(json.dumps(r))" "$results")
done

python3 - "$ROOT" "$results" "$OUTDIR" "$GATE_KB" "$GATE_WALL_S" <<'EOF'
import json, sys, pathlib
root = pathlib.Path(sys.argv[1])
runs = json.loads(sys.argv[2])
outdir = pathlib.Path(sys.argv[3])
gate_kb = int(sys.argv[4])
gate_wall = float(sys.argv[5])
def med(v):
    v = sorted(v)
    return v[len(v)//2] if v else 0
def peak(k):
    return max(r[k] for r in runs)
report = {
    "workflow": ["import-native", "functions", "xrefs", "rename", "open",
                 "disasm-native", "decompile-native"],
    "runs": runs,
    "median_wall_s": med([r["wall_s"] for r in runs]),
    "peak_import_kb": peak("import_kb"),
    "peak_disasm_kb": peak("disasm_kb"),
    "peak_decompile_kb": peak("decompile_kb"),
    "gates": {"peak_kb": gate_kb, "wall_s": gate_wall,
              "stock_ghidra_baseline_kb": 384000},
    "pass": (peak("import_kb") <= gate_kb
             and peak("disasm_kb") <= gate_kb
             and peak("decompile_kb") <= gate_kb
             and med([r["wall_s"] for r in runs]) <= gate_wall),
}
# Re-verify the end-to-end artifacts really are the expected content.
add = (outdir / "decompile_1.out").read_text()
assert "return param_2 + param_1" in add, f"decompile output unexpected: {add!r}"
dis = (outdir / "disasm_1.out").read_text()
assert "PUSH      RBP" in dis, f"disasm output unexpected: {dis!r}"
funcs = (outdir / "functions_1.out").read_text()
assert "00400466" in funcs, "function list missing add"
print(json.dumps(report, indent=2))
reports_dir = root / "benchmarks" / "reports"
reports_dir.mkdir(parents=True, exist_ok=True)
(reports_dir / "stage4-gate.json").write_text(json.dumps(report, indent=2) + "\n")
if report["pass"]:
    print(f"GATE PASS: peak {max(report['peak_import_kb'], report['peak_disasm_kb'], report['peak_decompile_kb'])} KB (limit {gate_kb}), "
          f"median wall {report['median_wall_s']} s (limit {gate_wall})")
    print(f"  vs stock Ghidra baseline ~{report['gates']['stock_ghidra_baseline_kb']} KB peak")
else:
    print(f"GATE FAIL: see {reports_dir / 'stage4-gate.json'}")
    sys.exit(1)
EOF
