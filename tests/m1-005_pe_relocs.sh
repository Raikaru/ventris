#!/usr/bin/env bash
# m1-005 acceptance: PE base relocations (.reloc / IMAGE_REL_BASED_*),
# relocated pointers stored as data xrefs with provenance, image base selection,
# and scoring against unstripped symbol twins.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

WORK="$(mktemp -d /tmp/m1-005-pe.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

CLI="target/debug/lre-cli"
cargo build -q -p lre-cli

TINY_PE_UNSTRIPPED="$ROOT/tests/fixtures-src/tiny_pe.exe"
if [ ! -f "$TINY_PE_UNSTRIPPED" ]; then
    echo "ERROR: $TINY_PE_UNSTRIPPED not found" >&2
    exit 1
fi

# Build stripped twin for tiny_pe
TINY_PE_STRIPPED="$WORK/tiny_pe.bin"
strip "$TINY_PE_UNSTRIPPED" -o "$TINY_PE_STRIPPED"

PROJ1="$WORK/tiny_pe_proj"
"$CLI" import-native "$TINY_PE_STRIPPED" --name tiny_pe --project "$PROJ1" > /dev/null 2>&1

# 1. Entry point check: entry must be 0x140001400
ENTRY_COUNT=$("$CLI" functions tiny_pe --project "$PROJ1" | grep -cE '^140001400' || true)
if [ "$ENTRY_COUNT" -ne 1 ]; then
    echo "FAIL: tiny_pe entry 0x140001400 not found among functions" >&2
    "$CLI" functions tiny_pe --project "$PROJ1" | head -10 >&2
    exit 1
fi

# 2. Relocated pointers stored as data xrefs with provenance (not symbols rows)
RELOC_XREF_COUNT=$("$CLI" xrefs tiny_pe --project "$PROJ1" | grep -c "\[native-import:pe-reloc\]" || true)
if [ "$RELOC_XREF_COUNT" -lt 10 ]; then
    echo "FAIL: expected at least 10 relocated pointer xrefs in store, got $RELOC_XREF_COUNT" >&2
    exit 1
fi

RELOC_SYM_COUNT=$("$CLI" symbols tiny_pe --project "$PROJ1" | grep -c "reloc_ptr_" || true)
if [ "$RELOC_SYM_COUNT" -ne 0 ]; then
    echo "FAIL: expected 0 relocated pointer symbol rows, got $RELOC_SYM_COUNT" >&2
    exit 1
fi

# 3. Unstripped twin scoring for tiny_pe
python3 - <<'PY' "$TINY_PE_UNSTRIPPED" "$PROJ1"
import sys, subprocess, re

unstripped = sys.argv[1]
proj = sys.argv[2]

out_syms = subprocess.check_output(["objdump", "-t", unstripped]).decode()
oracle = set()
for line in out_syms.splitlines():
    m = re.search(r"\(sec\s+1\).*\(ty\s+20\).*0x([0-9a-fA-F]+)\s+(\S+)$", line)
    if m:
        rva = int(m.group(1), 16)
        oracle.add(0x140001000 + rva)

out_funcs = subprocess.check_output(["target/debug/lre-cli", "functions", "tiny_pe", "--project", proj]).decode()
funcs = set()
for line in out_funcs.splitlines():
    p = line.split()
    if len(p) >= 3 and len(p[0]) in (8, 9, 16):
        funcs.add(int(p[0], 16))

overlap = len(funcs & oracle)
precision = overlap / len(funcs) if funcs else 0.0
recall = overlap / len(oracle) if oracle else 1.0
print(f"tiny_pe: oracle={len(oracle)} discovered={len(funcs)} overlap={overlap} p={precision:.4f} r={recall:.4f}")
assert precision == 1.0, f"precision {precision} != 1.0"
assert recall >= 0.25, f"recall {recall} < 0.25"
PY

# 4. Dispatch PE fixture with unstripped twin
DISPATCH_SRC="$ROOT/tests/fixtures-src/dispatch.c"
DISPATCH_UNSTRIPPED="$ROOT/tests/fixtures-src/dispatch.exe"
if [ ! -f "$DISPATCH_UNSTRIPPED" ] && command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    x86_64-w64-mingw32-gcc -O2 "$DISPATCH_SRC" -o "$DISPATCH_UNSTRIPPED"
fi

if [ -f "$DISPATCH_UNSTRIPPED" ]; then
    DISPATCH_STRIPPED="$WORK/dispatch.bin"
    strip "$DISPATCH_UNSTRIPPED" -o "$DISPATCH_STRIPPED"

    PROJ2="$WORK/dispatch_proj"
    "$CLI" import-native "$DISPATCH_STRIPPED" --name dispatch --project "$PROJ2" > /dev/null 2>&1

    DISP_RELOC_XREFS=$("$CLI" xrefs dispatch --project "$PROJ2" | grep -c "\[native-import:pe-reloc\]" || true)
    if [ "$DISP_RELOC_XREFS" -lt 3 ]; then
        echo "FAIL: dispatch expected at least 3 relocated pointer xrefs, got $DISP_RELOC_XREFS" >&2
        exit 1
    fi

    DISP_RELOC_SYMS=$("$CLI" symbols dispatch --project "$PROJ2" | grep -c "reloc_ptr_" || true)
    if [ "$DISP_RELOC_SYMS" -ne 0 ]; then
        echo "FAIL: dispatch expected 0 relocated pointer symbol rows, got $DISP_RELOC_SYMS" >&2
        exit 1
    fi

    python3 - <<'PY' "$DISPATCH_UNSTRIPPED" "$PROJ2"
import sys, subprocess, re

unstripped = sys.argv[1]
proj = sys.argv[2]

out_syms = subprocess.check_output(["objdump", "-t", unstripped]).decode()
oracle = set()
for line in out_syms.splitlines():
    m = re.search(r"\(sec\s+1\).*\(ty\s+20\).*0x([0-9a-fA-F]+)\s+(\S+)$", line)
    if m:
        rva = int(m.group(1), 16)
        oracle.add(0x140001000 + rva)

out_funcs = subprocess.check_output(["target/debug/lre-cli", "functions", "dispatch", "--project", proj]).decode()
funcs = set()
for line in out_funcs.splitlines():
    p = line.split()
    if len(p) >= 3 and len(p[0]) in (8, 9, 16):
        funcs.add(int(p[0], 16))

overlap = len(funcs & oracle)
precision = overlap / len(funcs) if funcs else 0.0
recall = overlap / len(oracle) if oracle else 1.0
print(f"dispatch: oracle={len(oracle)} discovered={len(funcs)} overlap={overlap} p={precision:.4f} r={recall:.4f}")
assert precision == 1.0, f"precision {precision} != 1.0"
assert recall >= 0.25, f"recall {recall} < 0.25"
PY
fi

echo "m1-005: PASS"
