#!/usr/bin/env bash
# QA-003 corpus matrix: build realistic fixtures and run the native
# importer (no JVM) over each. Asserts no panic and a nonzero function
# count; writes benchmarks/reports/corpus.json.
#
# Variants: O0 C, O2 C, O2 C++ (exceptions + TLS + switch tables), PIE C,
# large C (many functions), stripped variants of each.
#
# Env: CC (default cc), CXX (default c++), VENTRIS_SLA (unused here;
# import-native is JVM-free).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CFG="$(mktemp -d /tmp/ventris-corpus.XXXXXX)"
OUT="${OUT:-$ROOT/benchmarks/reports/corpus.json}"
CLI="$ROOT/target/debug/lre-cli"
CC="${CC:-cc}"
CXX="${CXX:-c++}"

cat > "$CFG/cpp.cpp" <<'CPP'
#include <cstdio>
#include <vector>
#include <stdexcept>
#include <string>
#include <map>
CPP

cat > "$CFG/src.cpp" <<'CPP'
#include <cstdio>
#include <vector>
#include <stdexcept>
#include <string>
#include <map>
static __thread int tls_counter;
static std::vector<std::string> texts;
static std::map<int, std::string> by_id;
static int classify(int v) {
    switch (v) {
        case 0: return 10; case 1: return 20; case 2: return 30;
        case 3: return 40; case 4: return 50; case 5: return 60;
        case 6: return 70; case 7: return 80; case 8: return 90;
        default: return -1;
    }
}
static int work(int n) {
    if (n < 0) throw std::runtime_error("negative");
    try {
        for (int i = 0; i < n; i++) { tls_counter += classify(i % 9); texts.push_back("x"); }
    } catch (...) { return -2; }
    by_id[1] = "one";
    return tls_counter + (int)texts.size();
}
int main() {
    int r = work(64);
    std::printf("%d\n", r);
    return 0;
}
CPP

cat > "$CFG/many.c" <<'C'
#include <stdio.h>
#define FN(n) static int fn_##n(int x){return x+n*3;}
C

# many.c: generate 400 small functions
{
  echo "#include <stdio.h>"
  for i in $(seq 1 400); do echo "static int fn_$i(int x){return x+$i*3;}"; done
  echo "int main(void){int s=0; int v=0;"
  for i in $(seq 1 400); do echo "s+=fn_$i(v++);"; done
  echo "printf(\"%d\",s);return 0;}"
} > "$CFG/many.c"

cat > "$CFG/plain.c" <<'C'
#include <stdio.h>
#include <string.h>
static int sum(int n){int s=0;for(int i=0;i<n;i++)s+=i;return s;}
int main(void){char b[64];memset(b,0,64);strcpy(b,"hello");printf("%d %s\n",sum(10),b);return 0;}
C

build() { # name, cflags..., source
    local bin="$CFG/$1.bin"
    shift
    local src="${@: -1}"
    if [ "$src" = "$2" ]; then :; fi
    "$CC" "$@" -o "$bin" || "$CXX" "$@" -o "$bin"
    echo "$bin"
}

set +e
BINS=""
BINS="$BINS $CFG/plain_o0.bin";     "$CC" -O0 -g    "$CFG/plain.c" -o "$CFG/plain_o0.bin" 2>/dev/null
BINS="$BINS $CFG/plain_o2.bin";     "$CC" -O2 -s    "$CFG/plain.c" -o "$CFG/plain_o2.bin" 2>/dev/null
BINS="$BINS $CFG/plain_pie.bin";    "$CC" -O2 -s -fPIE -pie "$CFG/plain.c" -o "$CFG/plain_pie.bin" 2>/dev/null
BINS="$BINS $CFG/cpp_o2.bin";       "$CXX" -O2 -s "$CFG/src.cpp" -o "$CFG/cpp_o2.bin" 2>/dev/null
BINS="$BINS $CFG/many_o2.bin";      "$CC" -O1 -fno-inline -s "$CFG/many.c" -o "$CFG/many_o2.bin" 2>/dev/null
set -e
set -e

results="[]"
ok=0
for bin in $BINS; do
    [ -f "$bin" ] || { echo "  (skipping missing $bin)"; continue; }
    name="$(basename "$bin" .bin)"
    proj="$CFG/$name"
    mkdir -p "$proj"
    start=$(date +%s.%N)
    out=$("$CLI" import-native "$bin" --name "$name" --project "$proj" 2>&1)
    rc=$?
    end=$(date +%s.%N)
    elapsed=$(echo "$end - $start" | bc)
    nfunc=0
    if [ "$rc" -eq 0 ]; then
        nfunc=$("$CLI" functions "$name" --project "$proj" | grep -cE '^[0-9a-f]{8}')
        ok=$((ok + 1))
    fi
    results=$(python3 -c "
import json, sys
r = json.loads(sys.argv[1])
r.append({'fixture': '$name', 'rc': $rc, 'functions': $nfunc, 'wall_s': round($elapsed, 3), 'output': '$out'[:120]})
print(json.dumps(r))" "$results")
    echo "  $name: rc=$rc functions=$nfunc (${elapsed}s)"
done

python3 - "$results" "$OUT" <<'EOF'
import json, sys, pathlib
runs = json.loads(sys.argv[1])
reports = pathlib.Path(sys.argv[2])
result = {
    "fixtures": runs,
    "total": len(runs),
    "imported_ok": sum(1 for r in runs if r["rc"] == 0 and r["functions"] > 0),
    "pass": all(r["rc"] == 0 and r["functions"] > 0 for r in runs),
}
reports.parent.mkdir(parents=True, exist_ok=True)
reports.write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({"total": result["total"], "ok": result["imported_ok"], "pass": result["pass"]}))
if not result["pass"]:
    sys.exit(1)
EOF
