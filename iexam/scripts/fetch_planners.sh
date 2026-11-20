#!/usr/bin/env bash
# Fetch the third-party planners into Backend/ at the exact commits this
# project was tested with. They are not stored in this repo (see README).
#
#   ./scripts/fetch_planners.sh           # fetch sources only (enough for Docker / HF)
#   ./scripts/fetch_planners.sh --build   # also compile natively (local dev)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/Backend"

fetch() {  # fetch <dir> <repo-url> <commit>
  local dir=$1 url=$2 sha=$3
  if [ -d "$dir" ]; then
    echo "skip  $dir (already exists; delete it to re-fetch)"
    return
  fi
  echo "fetch $dir @ ${sha:0:9}"
  git init -q "$dir"
  git -C "$dir" fetch -q --depth 1 "$url" "$sha"
  git -C "$dir" checkout -q FETCH_HEAD
  rm -rf "$dir/.git"
}

fetch downward        https://github.com/aibasel/downward.git      1ad981d8a671267b51f8df3b19c396a64c608ea5
fetch forbiditerative https://github.com/IBM/forbiditerative.git   67d2e84bc2da67472e7139f2f585edf5ad5011bd
fetch VAL             https://github.com/KCL-Planning/VAL.git      3c7a1f330bdab0ba28a4762bb45c3f06c27fb6d4

# VAL ships doc/sample PDFs and PNGs. They are not needed, and Hugging Face
# rejects binary files pushed over plain git.
find VAL \( -name '*.pdf' -o -name '*.png' \) -delete

# ForbidIterative's driver looks for its builds one level down.
[ -L forbiditerative/forbiditerative/builds ] || ln -s ../builds forbiditerative/forbiditerative/builds

if [ "${1:-}" = "--build" ]; then
  # EdgePlanner (ARM / new toolchains):
  # - CMake 4 refuses projects declaring cmake_minimum_required < 3.5 (ForbidIterative, VAL).
  # - GCC 14+ rejects ForbidIterative's bundled tl::optional (-Wtemplate-body); the code path is unused.
  # - Low-memory boards (Pi 3: 1 GB) cannot compile with 4 parallel jobs.
  export CMAKE_POLICY_VERSION_MINIMUM=3.5
  if echo 'int x;' | ${CXX:-c++} -Wno-template-body -x c++ -fsyntax-only - 2>/dev/null; then
    export CXXFLAGS="${CXXFLAGS:-} -Wno-template-body"
  fi
  export CMAKE_BUILD_PARALLEL_LEVEL="${CMAKE_BUILD_PARALLEL_LEVEL:-2}"
  (cd downward && ./build.py release -j"$CMAKE_BUILD_PARALLEL_LEVEL")
  (cd forbiditerative && ./build.py release -j"$CMAKE_BUILD_PARALLEL_LEVEL")
  arch=$([ "$(uname -s)" = Linux ] && echo linux64 || echo macos64)
  cmake -S VAL -B "VAL/build/$arch/Release" -DCMAKE_BUILD_TYPE=Release
  cmake --build "VAL/build/$arch/Release" -j"$CMAKE_BUILD_PARALLEL_LEVEL" --target Validate
fi
