#!/usr/bin/env bash
# Console-driven function discovery for stripped binaries.
# Iteratively maps/disassembles functions with the pinned console (real
# SLEIGH disassembly), follows direct calls + the _start `MOV RDI,main`
# convention, and prints "entry size" lines for every function plus
# "from to" lines for every xref.
#
# Usage: discover.sh <binary> [seeds...]
set -u
BIN="${1:?binary}"; shift
CONSOLE="${VENTRIS_CONSOLE:-/tmp/spike/decomp_native}"
GHROOT="${VENTRIS_GHROOT:-/tmp/spike/ghroot}"
LANGS="${VENTRIS_LANGS:-/tmp/spike/langs}"

SEEDS=()
SEEN_FILE=$(mktemp)
for s in "$@"; do
    d=$((s))
    SEEDS+=("$d")
    echo "$d" >> "$SEEN_FILE"
done
ROUNDS=0
FUNCS=()
CALLS=()

# run one round: script -> console output in a temp file
for ((ROUNDS = 0; ROUNDS < 8; ROUNDS++)); do
    [ "${#SEEDS[@]}" -eq 0 ] && break
    SCRIPT=$(mktemp)
    echo "load file x86:LE:64:default $BIN" >> "$SCRIPT"
    echo "adjust vma 0x400000" >> "$SCRIPT"
    i=0
    for s in "${SEEDS[@]}"; do
        printf 'map function 0x%x f%d\n' "$s" "$i" >> "$SCRIPT"
        echo "load function f$i" >> "$SCRIPT"
        echo "disassemble" >> "$SCRIPT"
        i=$((i + 1))
    done
    OUT=$(mktemp)
    SLEIGHHOME="$GHROOT" timeout 60 "$CONSOLE" -s "$LANGS" < "$SCRIPT" > "$OUT" 2>&1
    NEW=()
    LAST=""
    while IFS= read -r line; do
        case "$line" in
        "0x"*)
            addr="${line%%:*}"
            addr="${addr#0x}"
            if [[ "$addr" =~ ^[0-9a-fA-F]+$ ]]; then
                LAST=$((16#$addr))
                # MOV RDI,imm = the __libc_start_main main-argument convention
                if [[ "$line" == *"CALL"* ]]; then
                    # 0x...: CALL 0x... — direct; skip qword-ptr indirect.
                    operand="${line##*CALL}"
                    operand="${operand//[[:space:]]/}"
                    if [[ "$operand" =~ ^0x[0-9a-fA-F]+$ ]] && [ -n "$LAST" ]; then
                        target=$((16#${operand#0x}))
                        CALLS+=("$LAST $target")
                        if ! grep -q "^$target$" "$SEEN_FILE" && [ "${#SEEDS[@]}" -lt 64 ]; then
                            echo "$target" >> "$SEEN_FILE"
                            NEW+=("$target")
                        fi
                    fi
                fi
                if [[ "$line" == *"MOV"*"RDI,0x"* ]]; then
                    cand="${line##*RDI,}"
                    cand="${cand%% *}"
                    cand="${cand//,}"
                    if [[ "$cand" =~ ^0x[0-9a-fA-F]+$ ]]; then
                        c=$((16#${cand#0x}))
                        if ! grep -q "^$c$" "$SEEN_FILE"; then
                            echo "$c" >> "$SEEN_FILE"
                            NEW+=("$c")
                        fi
                    fi
                fi
            fi
            ;;
        *"CALL"*)
            # 0x...: CALL 0x...  (direct) — skip "qword ptr" indirect forms
            operand="${line##*CALL}"
            operand="${operand//[[:space:]]/}"
            if [[ "$operand" =~ ^0x[0-9a-fA-F]+$ ]] && [ -n "$LAST" ]; then
                target=$((16#${operand#0x}))
                CALLS+=("$LAST $target")
                if ! grep -q "^$target$" "$SEEN_FILE" && [ "${#SEEDS[@]}" -lt 64 ]; then
                    echo "$target" >> "$SEEN_FILE"
                    NEW+=("$target")
                fi
            fi
            ;;
        esac
    done < "$OUT"
    SEEDS=("${NEW[@]}")
    rm -f "$SCRIPT" "$OUT"
done

# Emit: "entry size" per discovered function (size = distance to the next
# seen function), then "from to" per direct call.
python3 - $(cat "$SEEN_FILE") <<'PY'
import sys
vals = sorted({int(x) for x in sys.argv[1:] if x != "0"})
for i, a in enumerate(vals):
    nxt = vals[i + 1] if i + 1 < len(vals) else a + 16
    print(f"F {a} {nxt - a}")
PY
printf '%s\n' "${CALLS[@]}" | sort -u | awk '{print "X", $1, $2}'
