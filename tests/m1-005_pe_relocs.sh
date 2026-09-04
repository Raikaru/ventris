#!/usr/bin/env bash
# m1-005 acceptance: PE base relocations (.reloc / IMAGE_REL_BASED_*),
# relocated pointers into the store, image base selection, and function discovery
# on PE corpus entries.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

WORK="$(mktemp -d /tmp/m1-005-pe.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

CLI="target/debug/lre-cli"
cargo build -q -p lre-cli

TINY_PE="$ROOT/tests/fixtures-src/tiny_pe.exe"
if [ ! -f "$TINY_PE" ]; then
    echo "ERROR: $TINY_PE not found" >&2
    exit 1
fi

PROJ1="$WORK/tiny_pe_proj"
"$CLI" import-native "$TINY_PE" --name tiny_pe --project "$PROJ1" > /dev/null 2>&1

# 1. Entry point check: entry must be 0x140001400 (not unshifted/bugged header value)
ENTRY_COUNT=$("$CLI" functions tiny_pe --project "$PROJ1" | grep -cE '^140001400' || true)
if [ "$ENTRY_COUNT" -ne 1 ]; then
    echo "FAIL: tiny_pe entry 0x140001400 not found among functions" >&2
    "$CLI" functions tiny_pe --project "$PROJ1" | head -10 >&2
    exit 1
fi

# 2. Relocated pointer symbols in the store
RELOC_SYM_COUNT=$("$CLI" symbols tiny_pe --project "$PROJ1" | grep -c "reloc_ptr_" || true)
if [ "$RELOC_SYM_COUNT" -lt 10 ]; then
    echo "FAIL: expected at least 10 relocated pointer symbols in store, got $RELOC_SYM_COUNT" >&2
    exit 1
fi

# 3. Discovered function count from base relocations and call sweep
FUNC_COUNT=$("$CLI" functions tiny_pe --project "$PROJ1" | grep -cE '^[0-9a-f]{8,16}' || true)
if [ "$FUNC_COUNT" -lt 15 ]; then
    echo "FAIL: expected at least 15 discovered functions in tiny_pe, got $FUNC_COUNT" >&2
    exit 1
fi

# 4. Compiled PE binary with dispatch table (if mingw is present)
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    cat > "$WORK/dispatch.c" <<'EOF'
#include <stdio.h>
typedef int (*calc_fn)(int);
static int f_double(int x) { return x * 2; }
static int f_square(int x) { return x * x; }
static int f_cube(int x) { return x * x * x; }
static calc_fn dispatch_table[] = { f_double, f_square, f_cube };
int main(int argc, char **argv) {
    if (argc > 1) {
        printf("%d\n", dispatch_table[argc % 3](argc));
    }
    return 0;
}
EOF
    x86_64-w64-mingw32-gcc -O2 -s "$WORK/dispatch.c" -o "$WORK/dispatch.exe"
    PROJ2="$WORK/dispatch_proj"
    "$CLI" import-native "$WORK/dispatch.exe" --name dispatch --project "$PROJ2" > /dev/null 2>&1

    DISP_RELOC_SYMS=$("$CLI" symbols dispatch --project "$PROJ2" | grep -c "reloc_ptr_" || true)
    if [ "$DISP_RELOC_SYMS" -lt 3 ]; then
        echo "FAIL: dispatch.exe expected at least 3 relocated pointer symbols, got $DISP_RELOC_SYMS" >&2
        exit 1
    fi

    DISP_FUNCS=$("$CLI" functions dispatch --project "$PROJ2" | grep -cE '^[0-9a-f]{8,16}' || true)
    if [ "$DISP_FUNCS" -lt 5 ]; then
        echo "FAIL: dispatch.exe expected at least 5 discovered functions, got $DISP_FUNCS" >&2
        exit 1
    fi
fi

echo "m1-005: PASS"
