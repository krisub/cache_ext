#!/bin/bash
set -eu -o pipefail

# Populate test files for the file_workload benchmark.
# Creates two directories:
#   /mydata/file_workload_data/small/  - 20,000 files x 4 KB  = ~80 MB
#   /mydata/file_workload_data/large/  - 5,000  files x 256 KB = ~1.25 GB
# Total ~1.33 GB, exceeding the 512 MiB cgroup limit to force eviction.

DATA_DIR="/mydata/file_workload_data"
SMALL_DIR="$DATA_DIR/small"
LARGE_DIR="$DATA_DIR/large"

SMALL_COUNT=20000
SMALL_SIZE=4096         # 4 KB
LARGE_COUNT=5000
LARGE_SIZE=262144       # 256 KB

echo "Populating file workload data at $DATA_DIR ..."

mkdir -p "$SMALL_DIR" "$LARGE_DIR"

echo "Creating $SMALL_COUNT small files (${SMALL_SIZE} bytes each)..."
for i in $(seq 0 $((SMALL_COUNT - 1))); do
    fname=$(printf "data_%06d" "$i")
    if [ ! -f "$SMALL_DIR/$fname" ]; then
        dd if=/dev/urandom of="$SMALL_DIR/$fname" bs="$SMALL_SIZE" count=1 status=none
    fi
done
echo "  Done: $SMALL_DIR"

echo "Creating $LARGE_COUNT large files (${LARGE_SIZE} bytes each)..."
for i in $(seq 0 $((LARGE_COUNT - 1))); do
    fname=$(printf "data_%06d" "$i")
    if [ ! -f "$LARGE_DIR/$fname" ]; then
        dd if=/dev/urandom of="$LARGE_DIR/$fname" bs="$LARGE_SIZE" count=1 status=none
    fi
done
echo "  Done: $LARGE_DIR"

echo ""
echo "File workload data ready:"
du -sh "$SMALL_DIR" "$LARGE_DIR" "$DATA_DIR"
