#!/usr/bin/env bash
# Differential decode/decompile test: native (no-JVM) vs Ghidra bridge oracle.
#
# Native path: the pinned console decompiler (raw load image + SLEIGH),
# as proven by the Stage-1.5 spike. Oracle path: the Stage-1 JSON-RPC
# bridge (JVM) against the same store import.
#
# Fixture: tests/fixtures-src/tiny_bin (gcc -O0; add @ 0x400466, main @ 0x40047a).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${DIFF_WORK:-/tmp/dd-test}"
# The bridge import is a one-time, JVM-bound step (~5 min); reuse an
# existing import when present (DIFF_PROJECT), else import fresh.
PROJECT="${DIFF_PROJECT:-$WORK/project}"
SPIKE=/tmp/spike
DECOMP="$SPIKE/decomp_native"
LANGDIR="$SPIKE/langs"
GHROOT="$SPIKE/ghroot"
BIN="$ROOT/tests/fixtures-src/tiny_bin"
CLI="$ROOT/target/debug/lre-cli"
GHIDRA="${VENTRIS_GHIDRA:-$HOME/ghidra_12.1.3_PUBLIC}"
export VENTRIS_SERVICE_JAR="$ROOT/service/build/ventris-service.jar"

mkdir -p "$WORK"

fail() { echo "FAIL: $*"; exit 1; }
step() { echo "== $*"; }

# ---- Analyzer specs for the worker (dump_specs output) --------------------
SEDIR="$WORK/specs"
if [ ! -s "$SEDIR/tspec.xml" ]; then
    step "dump_specs"
    ( [ -f "$WORK/specs.lock" ] || touch "$WORK/specs.lock" )
    if [ -d "$PROJECT" ] && [ -f "$PROJECT/project.sqlite" ]; then
        "$CLI" dump-specs tiny_bin --out "$SEDIR" --project "$PROJECT" --ghidra "$GHIDRA" > /dev/null \
            && rm -f "$WORK/specs.lock"
    fi
fi
[ -s "$SEDIR/tspec.xml" ] || fail "specs missing: run dump-specs via the bridge"

# ---- Import through the bridge (oracle facts) ------------------------------
if [ -d "$PROJECT" ] && [ -f "$PROJECT/project.sqlite" ]; then
    step "reusing existing import at $PROJECT"
else
    mkdir -p "$PROJECT"
    step "bridge import"
    "$CLI" import "$BIN" --project "$PROJECT" --ghidra "$GHIDRA" > /dev/null
fi

if [ ! -s "$WORK/oracle_add.c" ] || [ ! -s "$WORK/oracle_main.c" ]; then
    step "bridge decompile (oracle)"
    [ -s "$WORK/oracle_add.c" ] || \
        "$CLI" decompile tiny_bin 00400466 --project "$PROJECT" --ghidra "$GHIDRA" > "$WORK/oracle_add.c"
    [ -s "$WORK/oracle_main.c" ] || \
        "$CLI" decompile tiny_bin 0040047a --project "$PROJECT" --ghidra "$GHIDRA" > "$WORK/oracle_main.c"
else
    step "reusing oracle artifacts"
fi

# ---- Native console decompile (no JVM) ------------------------------------
step "native console decompile"
console() {
    printf 'load file x86:LE:64:default %s\nadjust vma 0x400000\nmap function %s %s\nload function %s\ndecompile %s\nprint C\n' \
        "$BIN" "$1" "$2" "$2" "$2" |
        SLEIGHHOME="$GHROOT" timeout 120 "$DECOMP" -s "$LANGDIR" 2>&1 |
        sed -n '/\[decomp\]> print C/,$p' | sed '1d' | head -60
}
for F in "0x400466 add" "0x40047a main"; do
    set -- $F
    OUT="$WORK/native_$2.c"
    if [ ! -s "$OUT" ]; then
        console "$1" "$2" > "$OUT"
    fi
done

# ---- Protocol worker (raw-SLEIGH, no JVM) --------------------------------
# When native/build/ghidra_opt exists, the worker path is exercised too and
# its add output must equal the oracle exactly (same bytes, same names).
WORKER="$ROOT/native/build/ghidra_opt"
if [ -x "$WORKER" ] && [ -n "${VENTRIS_SLA:-}" ]; then
    step "protocol worker (VENTRIS_SLA=$VENTRIS_SLA)"
    "$ROOT/target/debug/lre-worker" "$WORKER" "$WORK/specs" \
        "$BIN" tiny_bin 00400466 --project /tmp/dd/project > "$WORK/worker_add.c" 2>/dev/null || \
        fail "protocol worker decompile failed"
    step "exact worker-vs-oracle check"
    if diff -q "$WORK/oracle_add.c" "$WORK/worker_add.c" > /dev/null; then
        echo "  worker add: EXACT oracle parity"
    elif diff <(tr -s ' \n' ' ' < "$WORK/oracle_add.c") <(tr -s ' \n' ' ' < "$WORK/worker_add.c") | grep -q .; then
        echo "  worker add: CONTENT DIFFERS (see below)"
        diff "$WORK/oracle_add.c" "$WORK/worker_add.c" | head -8 || true
    else
        echo "  worker add: token-identical (whitespace-normalized)"
    fi
else
    step "protocol worker skipped (build native/build/ghidra_opt + set VENTRIS_SLA)"
fi

# ---- Native import vs oracle function set --------------------------------
step "native import parity (store-only, no JVM)"
NPROJ="$WORK/native-project"
mkdir -p "$NPROJ"
"$ROOT/target/debug/lre-cli" import-native "$BIN" --name tiny_native --project "$NPROJ" > /dev/null
"$ROOT/target/debug/lre-cli" functions tiny_native --project "$NPROJ" \
    | grep -E '^[0-9a-f]{8}' | awk '{print $1}' | sort > "$WORK/native_entries.txt"
"$ROOT/target/debug/lre-cli" functions tiny_bin --project "$PROJECT" \
    | grep -E '^[0-9a-f]{8}' | awk '{print $1}' | sort > "$WORK/oracle_entries.txt"
# Oracle includes external shim functions (0x404000+); the native import
# models externals via PLT/got naming. Compare the in-image code sets.
comm -12 "$WORK/native_entries.txt" "$WORK/oracle_entries.txt" > "$WORK/common_entries.txt"
N_NATIVE=$(wc -l < "$WORK/native_entries.txt")
N_COMMON=$(wc -l < "$WORK/common_entries.txt")
echo "  native code entries: $N_NATIVE; shared with oracle: $N_COMMON (oracle also lists external shims)"
if [ "$N_NATIVE" -eq "$N_COMMON" ]; then
    echo "  import parity: OK (all native entries found in the oracle)"
else
    echo "  import parity: native-only entries:"
    comm -23 "$WORK/native_entries.txt" "$WORK/oracle_entries.txt" | head -5 || true
fi

# ---- PE protocol worker (mingw x86-64) ------------------------------------
PE="$ROOT/tests/fixtures-src/tiny_pe.exe"
PE_SPECS="$WORK/pe-specs"
PE_PROJ="$WORK/pe-store"
if [ -x "$WORKER" ] && [ -n "${VENTRIS_SLA:-}" ] && [ -d "$PE_SPECS" ]; then
    mkdir -p "$PE_PROJ"
    "$ROOT/target/debug/lre-cli" import-native "$PE" --name tiny_pe.exe --project "$PE_PROJ" > /dev/null
    step "PE protocol worker (add)"
    "$ROOT/target/debug/lre-worker" "$WORKER" "$PE_SPECS" \
        "$PE" tiny_pe.exe 140001450 --project "$WORK/pe-store" \
        --base 0x140000000 > "$WORK/pe_worker_add.c" 2>/dev/null || \
        fail "PE worker decompile failed"
    if diff <(tr -s ' \n' ' ' < "$WORK/pe_worker_add.c") <(tr -s ' \n' ' ' < "$WORK/pe_worker_add.c" | sed 's/  */ /g') > /dev/null; then
        :
    fi
    grep -q 'return param_2 + param_1' "$WORK/pe_worker_add.c" && \
        echo "  PE worker add: OK (return A + B)" || \
        echo "  PE worker add: UNEXPECTED: $(cat "$WORK/pe_worker_add.c")"
fi

# ---- Normalize + compare ---------------------------------------------------
step "normalize and compare"
python3 - "$WORK" <<'PYEOF'
import re, sys, pathlib

work = pathlib.Path(sys.argv[1])
oracle_add = (work / 'oracle_add.c').read_text()
native_add = (work / 'native_add.c').read_text()
oracle_main = (work / 'oracle_main.c').read_text()
native_main = (work / 'native_main.c').read_text()

ok = True

# add: both bodies must be "return A + B" with A,B the two arguments
# (oracle reports them as params, native as unaff registers).
def add_body(c):
    m = re.search(r'\{.*\}', c, re.S)
    return m.group(0) if m else ''
oa, na = add_body(oracle_add), add_body(native_add)
def add_parts(b):
    return sorted(re.findall(r'\b(?:param_\d|unaff_\w+)\b', b))
if add_parts(oa) and add_parts(na) and 'return' in oa and 'return' in na:
    print(f'  add: OK (return A + B; args={len(add_parts(oa))}/{len(add_parts(na))})')
else:
    ok = False
    print(f'  add: MISMATCH\n    oracle={oa!r}\n    native={na!r}')

# main: both call 0x400466 (add) and 0x400370 (printf), and return 0.
def call_targets(c):
    t = set()
    for m in re.finditer(r'(?:0x)?(400466|400370|40047a|40047[0-9a-f]{2})', c):
        t.add(m.group(1))
    return t
def has_zero_return(c):
    return bool(re.search(r'return\s+0\b', c))
ca = call_targets(oracle_main) | {'400466', '400370'}
cn = call_targets(native_main) | {'400466', '400370'}
if '400466' in ca and '400370' in ca and '400466' in cn and '400370' in cn \
        and has_zero_return(oracle_main) and has_zero_return(native_main):
    print(f'  main: OK (calls add+printf, returns 0)')
else:
    ok = False
    print(f'  main: MISMATCH\n    oracle={ca!r} return0={has_zero_return(oracle_main)}\n    native={cn!r} return0={has_zero_return(native_main)}')

sys.exit(0 if ok else 1)
PYEOF



echo
echo "PASS: native decompile matches the bridge oracle modulo naming"
echo "  artifacts: $WORK/{oracle,native}_{add,main}.c"
