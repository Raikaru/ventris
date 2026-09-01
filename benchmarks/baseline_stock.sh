#!/usr/bin/env bash
# Stock Ghidra baseline benchmark (spec 21.1): measures process-tree PSS and
# latency for import+analyze on the tiny fixture, using stock analyzeHeadless.
# Results are machine-readable JSON on stdout; Ghidra chatter goes to the log.
set -u
GHIDRA="${VENTRIS_GHIDRA:-$HOME/ghidra_12.1.3_PUBLIC}"
FIXTURE="${1:-tests/fixtures-src/tiny_bin}"
OUTDIR="${2:-/tmp/lre-baseline}"
RUNS="${RUNS:-3}"

mkdir -p "$OUTDIR"
rm -rf "$OUTDIR/baseline.proj" "$OUTDIR/baseline.rep"

# Warm-up + timed runs. analyzeHeadless -import does import+analyze+save.
results="[]"
for i in $(seq 1 "$RUNS"); do
  start=$(date +%s.%N)
  # Run in its own session; capture peak RSS of the whole process tree via
  # /usr/bin/time -v on the launcher (java child trees included).
  /usr/bin/time -v "$GHIDRA/support/analyzeHeadless" \
    "$OUTDIR" "baseline" -import "$FIXTURE" -deleteProject \
    > "$OUTDIR/run_$i.log" 2>&1
  rc=$?
  end=$(date +%s.%N)
  elapsed=$(echo "$end - $start" | bc)
  maxrss_kb=$(grep 'Maximum resident set size' "$OUTDIR/run_$i.log" | grep -o '[0-9]*')
  results=$(python3 -c "
import json,sys
r=json.loads(sys.argv[1])
r.append({'run': $i, 'exit': $rc, 'wall_s': round($elapsed,2), 'maxrss_kb': $maxrss_kb})
print(json.dumps(r))" "$results")
done

python3 - "$results" "$OUTDIR" <<'EOF'
import json, sys, platform, os
runs = json.loads(sys.argv[1])
ok = [r for r in runs if r['exit'] == 0]
wall = sorted(r['wall_s'] for r in ok)
rss  = sorted(r['maxrss_kb'] for r in ok)
def med(v): return v[len(v)//2] if v else None
report = {
  'component': 'stock-ghidra-analyzeHeadless',
  'ghidra': os.environ.get('VENTRIS_GHIDRA', os.path.expanduser('~/ghidra_12.1.3_PUBLIC')),
  'host': {'kernel': platform.release(), 'machine': platform.machine(),
           'cpu': os.cpu_count()},
  'runs': runs,
  'median_wall_s': med(wall),
  'median_maxrss_kb': med(rss),
  'maxrss_is_tree_peak': True,
  'note': 'maxrss from /usr/bin/time -v covers the launcher process tree (ru_maxrss of waited children), i.e. JVM peak RSS including the decompiler child.',
}
out = sys.argv[2] + '/baseline-stock.json'
open(out, 'w').write(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
EOF
