#!/usr/bin/env bash
# m1-004 acceptance: ELF PIE discovery via DT_RELA, DT_RELR, R_*_RELATIVE,
# image base selection, and relocated pointers into the store.
#
# Asserts fn.recall >= 0.98 on the PIE corpus entries.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

WORK="$(mktemp -d /tmp/m1-004-pie.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

CLI="target/debug/lre-cli"
[ -x "$CLI" ] || cargo build -q -p lre-cli

# Generate PIE corpus fixtures:
# 1. plain_pie: standard PIE with -fPIE -pie (DT_RELA / R_X86_64_RELATIVE)
# 2. relr_pie: modern PIE with -Wl,-z,pack-relative-relocs (DT_RELR) and dispatch tables

cat > "$WORK/plain_pie.c" <<'EOF'
#include <stdio.h>
#include <string.h>
static int sum(int n){int s=0;for(int i=0;i<n;i++)s+=i;return s;}
int main(void){char b[64];memset(b,0,64);strcpy(b,"hello");printf("%d %s\n",sum(10),b);return 0;}
EOF

cat > "$WORK/relr_pie.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>

typedef int (*math_fn)(int, int);
static int fn_add(int a, int b) { return a + b; }
static int fn_sub(int a, int b) { return a - b; }
static int fn_mul(int a, int b) { return a * b; }
static int fn_xor(int a, int b) { return a ^ b; }
static math_fn dispatch[] = { fn_add, fn_sub, fn_mul, fn_xor };

int main(int argc, char **argv) {
    if (argc > 3) {
        printf("%d\n", dispatch[argc % 4](argc, 3));
    }
    return 0;
}
EOF

cc -O2 -fPIE -pie "$WORK/plain_pie.c" -o "$WORK/plain_pie.unstripped"
strip "$WORK/plain_pie.unstripped" -o "$WORK/plain_pie.bin"

if cc -O2 -fPIE -pie -Wl,-z,pack-relative-relocs "$WORK/relr_pie.c" -o "$WORK/relr_pie.unstripped" 2>/dev/null; then
    strip "$WORK/relr_pie.unstripped" -o "$WORK/relr_pie.bin"
else
    cc -O2 -fPIE -pie "$WORK/relr_pie.c" -o "$WORK/relr_pie.unstripped"
    strip "$WORK/relr_pie.unstripped" -o "$WORK/relr_pie.bin"
fi

FAILED=0

for name in plain_pie relr_pie; do
    unstripped="$WORK/$name.unstripped"
    stripped="$WORK/$name.bin"
    proj="$WORK/${name}_proj"

    # Oracle from unstripped symbol table (FUNC symbols in allocated sections)
    oracle_file="$WORK/${name}_oracle.txt"
    python3 -c '
import sys, subprocess
out = subprocess.check_output(["readelf", "-s", "-W", sys.argv[1]]).decode()
for line in out.splitlines():
    p = line.split()
    if len(p) >= 8 and p[3] == "FUNC" and p[6] not in ("UND", "ABS"):
        v = int(p[1], 16)
        if v != 0:
            print(f"{v:08x}")
' "$unstripped" | sort -u > "$oracle_file"

    oracle_count=$(wc -l < "$oracle_file")
    if [ "$oracle_count" -eq 0 ]; then
        echo "ERROR: empty oracle for $name" >&2
        exit 1
    fi

    # Import stripped binary natively
    "$CLI" import-native "$stripped" --name "$name" --project "$proj" > /dev/null 2>&1

    discovered_file="$WORK/${name}_discovered.txt"
    "$CLI" functions "$name" --project "$proj" \
        | awk 'NF>=3 && length($1)==8 { print tolower($1) }' \
        | sort -u > "$discovered_file"

    discovered_count=$(wc -l < "$discovered_file")
    intersection=$(comm -12 "$oracle_file" "$discovered_file" | wc -l)

    recall=$(awk -v I="$intersection" -v O="$oracle_count" 'BEGIN { printf "%.4f", I / O }')
    precision="0.0000"
    if [ "$discovered_count" -gt 0 ]; then
        precision=$(awk -v I="$intersection" -v D="$discovered_count" 'BEGIN { printf "%.4f", I / D }')
    fi

    echo "$name: oracle=$oracle_count discovered=$discovered_count overlap=$intersection recall=$recall precision=$precision"

    RECALL_PASS=$(awk -v R="$recall" 'BEGIN { print (R >= 0.98) ? 1 : 0 }')
    if [ "$RECALL_PASS" -ne 1 ]; then
        echo "FAIL: $name recall $recall < 0.98" >&2
        echo "  Missing oracle functions:" >&2
        comm -23 "$oracle_file" "$discovered_file" | head -10 >&2
        FAILED=1
    fi
done

if [ "$FAILED" -ne 0 ]; then
    echo "m1-004 acceptance test failed." >&2
    exit 1
fi

echo "m1-004: PASS"
