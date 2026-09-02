#!/bin/sh
# Build the Java service jar against a local Ghidra 12.1.3 install.
# Usage: service/build.sh [GHIDRA_INSTALL_DIR]
# The install dir defaults to $VENTRIS_GHIDRA, then ~/ghidra_12.1.3_PUBLIC.
set -e

GHIDRA="${1:-${VENTRIS_GHIDRA:-$HOME/ghidra_12.1.3_PUBLIC}}"
if [ ! -d "$GHIDRA/Ghidra" ]; then
    echo "Ghidra install not found at: $GHIDRA" >&2
    echo "Set VENTRIS_GHIDRA or pass the install dir as \$1." >&2
    exit 1
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CP=$(find "$GHIDRA/Ghidra" -name '*.jar' | grep -vE 'src\.zip|Extension' | tr '\n' ':')
CP="$CP:$GHIDRA/Ghidra/Framework/Generic/lib/gson-2.13.2.jar"

mkdir -p "$ROOT/service/build"
javac -cp "$CP" -d "$ROOT/service/build" "$ROOT"/service/src/main/java/net/ventris/*.java
jar cf "$ROOT/service/build/ventris-service.jar" -C "$ROOT/service/build" net
echo "built $ROOT/service/build/ventris-service.jar"
