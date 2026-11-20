#!/usr/bin/env bash
# Phase 8c: build llama.cpp's llama-server (CPU only) into tools/llama.cpp at a pinned release tag.
# Uses the system cmake if present, else the PyPI cmake wheel (aarch64 build) in tools/cmake-venv; no sudo.
#
#   bash scripts/fetch_llama.sh
set -euo pipefail

TAG=b11758
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="$ROOT/tools/llama.cpp"
mkdir -p "$ROOT/tools"

if [ ! -d "$DIR" ]; then
  echo "fetch llama.cpp @ $TAG"
  git clone -q --depth 1 --branch "$TAG" https://github.com/ggml-org/llama.cpp.git "$DIR"
fi

CMAKE=$(command -v cmake || true)
if [ -z "$CMAKE" ]; then
  python3 -m venv "$ROOT/tools/cmake-venv"
  "$ROOT/tools/cmake-venv/bin/pip" install -q cmake
  CMAKE="$ROOT/tools/cmake-venv/bin/cmake"
fi

# Two compile jobs on a 1 GB machine (a Pi 3), all cores otherwise.
MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
JOBS=$([ "$MEM_MB" -lt 2048 ] && echo 2 || nproc)

"$CMAKE" -S "$DIR" -B "$DIR/build" -DCMAKE_BUILD_TYPE=Release -DGGML_NATIVE=ON -DLLAMA_CURL=OFF \
  -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF > /dev/null
"$CMAKE" --build "$DIR/build" --target llama-server -j "$JOBS"
echo "built $DIR/build/bin/llama-server ($TAG)"
