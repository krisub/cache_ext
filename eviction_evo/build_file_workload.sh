#!/bin/bash
set -eu -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$SCRIPT_DIR/file_workload.cpp"
OUT="$SCRIPT_DIR/build/file_workload"

mkdir -p "$SCRIPT_DIR/build"

echo "Building file_workload..."
g++ -O2 -std=c++17 -Wall -pthread \
    -o "$OUT" "$SRC" \
    -lyaml-cpp -lm

echo "Built: $OUT"
