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
