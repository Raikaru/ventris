#!/usr/bin/env bash
# Acceptance test for m1-006: multi-architecture corpus generation
# Target architectures: x86-64, x86-32, AArch64, PPC32-BE (plus MSVC via Windows CI / skipped local)
# Variants: plain_o0, plain_o2, plain_pie, cpp_o2, many_o2
# Requirements:
# 1. Committed sources in tests/corpus-src/
# 2. Committed lock in tests/corpus.lock.json
# 3. Unstripped twin for each entry with oracle symbols
# 4. Successful native import across all generated architecture binaries
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$ROOT/target/debug/lre-cli"
CORPUS_SRC="$ROOT/tests/corpus-src"
CORPUS_LOCK="$ROOT/tests/corpus.lock.json"
GEN_SCRIPT="$ROOT/scripts/gen_corpus.py"

echo "=== m1-006: multi-architecture corpus generation acceptance test ==="

# 1. Check committed sources exist
if [ ! -d "$CORPUS_SRC" ]; then
    echo "FAIL: corpus source directory $CORPUS_SRC does not exist"
    exit 1
fi

for src in plain.c src.cpp many.c; do
    if [ ! -f "$CORPUS_SRC/$src" ]; then
        echo "FAIL: expected committed source $CORPUS_SRC/$src missing"
        exit 1
    fi
done

# 2. Check committed lock file exists
if [ ! -f "$CORPUS_LOCK" ]; then
    echo "FAIL: corpus lock file $CORPUS_LOCK does not exist"
    exit 1
fi

# 3. Check generator script exists
if [ ! -f "$GEN_SCRIPT" ]; then
    echo "FAIL: generator script $GEN_SCRIPT does not exist"
    exit 1
fi

# 4. Run generator into a temporary output directory
OUT_DIR="$(mktemp -d /tmp/m1-006-corpus.XXXXXX)"
trap 'rm -rf "$OUT_DIR"' EXIT

python3 "$GEN_SCRIPT" --out-dir "$OUT_DIR" --lock "$CORPUS_LOCK"

# 5. Verify generated architecture binaries and unstripped twins
ARCHS="x86_64 i386 aarch64 powerpc"
VARIANTS="plain_o0 plain_o2 plain_pie cpp_o2 many_o2"

for arch in $ARCHS; do
    for var in $VARIANTS; do
        bin="$OUT_DIR/${arch}_${var}.bin"
        twin="$OUT_DIR/${arch}_${var}.unstripped"
        
        if [ ! -f "$bin" ]; then
            echo "FAIL: missing generated binary $bin"
            exit 1
        fi
        if [ ! -f "$twin" ]; then
            echo "FAIL: missing unstripped twin $twin"
            exit 1
        fi
        
        # Verify unstripped twin has symbols
        sym_count=$(readelf -s "$twin" 2>/dev/null | grep -c " FUNC " || true)
        if [ "$sym_count" -eq 0 ]; then
            echo "FAIL: unstripped twin $twin has no function symbols in symbol table"
            exit 1
        fi
        
        # Verify native import succeeds
        out=$("$CLI" import-native "$bin" 2>&1)
        echo "Imported $bin: $out"
    done
done

# 6. Verify MSVC entry handled (checked on Windows, skipped with message on Linux)
if [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "cygwin"* || "$OSTYPE" == "win32"* ]]; then
    for var in $VARIANTS; do
        bin="$OUT_DIR/msvc_${var}.exe"
        if [ ! -f "$bin" ]; then
            echo "FAIL: Windows host missing MSVC binary $bin"
            exit 1
        fi
    done
else
    echo "MSVC entries: skipped on non-Windows host (verified via Windows CI)"
fi

echo "m1-006: PASS"
