#!/usr/bin/env bash
# Builds the out-of-tree `ghidra_opt` with the raw-SLEIGH translator hook.
#
# The pinned third_party/ghidra tree is NEVER modified in place; this script
# copies the decompiler sources aside, applies native/ghidra-opt-sleigh.patch,
# and builds. At runtime, when the worker sets VENTRIS_SLA to a compiled
# .sla, the binary self-disassembles (Sleigh translator) instead of asking
# the client for per-instruction pcode — closing the getPcode gap for the
# JVM-free worker path (see STATUS.md, stages/notes).
#
# Usage: native/build_ghidra_opt.sh [--jobs N] [OUTDIR]
#   OUTDIR default: native/build; produces OUTDIR/ghidra_opt
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PATCH="$ROOT/native/ghidra-opt-sleigh.patch"
JOBS=1
OUT="$ROOT/native/build"
while [ "${1:-}" != "" ]; do
    case "$1" in
        --jobs) JOBS="$2"; shift 2 ;;
        *) OUT="$1"; shift ;;
    esac
done

BUILD=$(mktemp -d /tmp/ghidra-opt-build.XXXXXX)
trap 'rm -rf "$BUILD"' EXIT
cp -r "$ROOT/third_party/ghidra/decompiler" "$BUILD/decompiler"
cp "$ROOT/native/ventris_linkage.hh" "$ROOT/native/ventris_patterns.hh" \
   "$ROOT/native/ventris_flow.hh" "$ROOT/native/ventris_constant_state.hh" \
   "$ROOT/native/ventris_constants.hh" "$BUILD/decompiler/"

cp "$PATCH" "$BUILD/apply.patch"
git -C "$BUILD" init -q
git -C "$BUILD" add -A
git -C "$BUILD" apply --whitespace=nowarn --ignore-space-change "$BUILD/apply.patch"

cd "$BUILD/decompiler"
make ghidra_opt -j"$JOBS" > /tmp/ghidra-opt-build.log 2>&1
mkdir -p "$OUT"
cp ghidra_opt "$OUT/ghidra_opt"
echo "built: $OUT/ghidra_opt"
echo "runtime: VENTRIS_SLA=/path/to/x86-64.sla $OUT/ghidra_opt"
