#!/usr/bin/env bash
# Prepare a POSIX machine to work on Ventris.
#
# The gate needs four things beyond the checkout: the pinned Rust toolchain, a
# Ghidra installation with this project's loader extensions, the corpus images,
# and three environment variables telling the tools where the last two live.
# This script asserts each one and reports what is missing, rather than failing
# somewhere deep inside a build.
#
# It is deliberately not a package installer. Fetching a JDK or a 900 MB Ghidra
# is the operator's call; what this owns is the toolchain pin, the environment,
# and a verdict.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${VENTRIS_IMAGE_DIR:=$HOME/ventris-corpus}"
: "${VENTRIS_GHIDRA:=$HOME/ghidra_12.1.3_PUBLIC}"
: "${VENTRIS_CENSUS_OUT:=$HOME/.cache/ventris-census}"

fail=0
note() { printf '  %-22s %s\n' "$1" "$2"; }
bad() { printf '  %-22s %s\n' "$1" "$2"; fail=1; }

echo "repo: $REPO"
echo
echo "toolchain:"

pinned="$(sed -n 's/^channel = "\(.*\)"/\1/p' "$REPO/rust-toolchain.toml")"
if command -v rustup >/dev/null 2>&1; then
  if rustup toolchain list | grep -q "^${pinned}"; then
    note "rust $pinned" "present"
  else
    echo "  installing rust $pinned via rustup..."
    rustup toolchain install "$pinned" --profile minimal --component rustfmt \
      && note "rust $pinned" "installed" \
      || bad "rust $pinned" "rustup install failed"
  fi
elif command -v cargo >/dev/null 2>&1; then
  have="$(cargo --version | awk '{print $2}')"
  # rust-toolchain.toml is honoured only by rustup. A distro cargo ignores the
  # pin silently, so a mismatch here is a real hazard, not a nit.
  if [ "$have" = "$pinned" ]; then
    note "rust $pinned" "present (distro cargo, pin not enforced)"
  else
    bad "rust $pinned" "distro cargo is $have and ignores rust-toolchain.toml; install rustup"
  fi
else
  bad "rust $pinned" "no cargo or rustup on PATH"
fi

for tool in python3 java git; do
  if command -v "$tool" >/dev/null 2>&1; then
    note "$tool" "$($tool --version 2>&1 | head -1)"
  else
    bad "$tool" "missing"
  fi
done

echo
echo "data:"
if [ -d "$VENTRIS_GHIDRA" ] && [ -x "$VENTRIS_GHIDRA/support/analyzeHeadless" ]; then
  note "ghidra" "$VENTRIS_GHIDRA"
  for ext in GameCubeLoader GhidraSPU ghidra-emotionengine-reloaded; do
    if [ -d "$VENTRIS_GHIDRA/Ghidra/Extensions/$ext" ]; then
      note "  extension" "$ext"
    else
      bad "  extension" "$ext missing; the census cannot import that target"
    fi
  done
else
  bad "ghidra" "$VENTRIS_GHIDRA has no support/analyzeHeadless"
fi

if [ -d "$VENTRIS_IMAGE_DIR" ]; then
  count="$(find "$VENTRIS_IMAGE_DIR" -maxdepth 1 -type f | wc -l)"
  note "corpus" "$VENTRIS_IMAGE_DIR ($count files)"
else
  bad "corpus" "$VENTRIS_IMAGE_DIR does not exist"
fi

echo
echo "environment: add these to your shell profile"
echo "  export VENTRIS_IMAGE_DIR=$VENTRIS_IMAGE_DIR"
echo "  export VENTRIS_GHIDRA=$VENTRIS_GHIDRA"
echo "  export VENTRIS_CENSUS_OUT=$VENTRIS_CENSUS_OUT"
mkdir -p "$VENTRIS_CENSUS_OUT"

echo
if [ "$fail" -eq 0 ]; then
  echo "ready. next: cargo build --release && python3 tools/gate.py"
else
  echo "not ready: resolve the items above."
fi
exit "$fail"
