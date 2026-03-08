#!/bin/bash
# Build the networked LevelDB components for cache_ext page cache testing.
#
# This builds:
#   net_leveldb_server  — LevelDB TCP server (block_cache=NULL, page-cache-only)
#   run_net_leveldb     — My-YCSB client that talks to net_leveldb_server
#   init_net_leveldb    — Populates net_leveldb_server over TCP
#
#   - LevelDB installed (libleveldb, snappy)
#   - yaml-cpp installed
#   - My-YCSB dependencies

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Building net_leveldb_server ==="
LEVELDB_INCLUDE="$SCRIPT_DIR/leveldb/include"
LEVELDB_BUILD="$SCRIPT_DIR/leveldb/build"

g++ net_leveldb_server.cc -o net_leveldb_server \
    -I"$LEVELDB_INCLUDE" \
    -L"$LEVELDB_BUILD" \
    -lleveldb -lsnappy -lpthread -O2
echo "  -> Built: $SCRIPT_DIR/net_leveldb_server"

echo ""
echo "=== Building My-YCSB (including net_leveldb backend) ==="
cd "$SCRIPT_DIR/My-YCSB"
mkdir -p build
cd build
cmake ..
make -j"$(nproc)" run_net_leveldb init_net_leveldb
echo "  -> Built: run_net_leveldb, init_net_leveldb"

echo ""
echo "=== Build complete ==="
echo ""
echo "To run a networked page cache benchmark:"
echo "  cd $SCRIPT_DIR/bench"
echo "  python bench_net_leveldb.py \\"
echo "    --leveldb-db /mydata/leveldb_db \\"
echo "    --bench-binary-dir $SCRIPT_DIR/My-YCSB/build \\"
echo "    --server-binary $SCRIPT_DIR/net_leveldb_server \\"
echo "    --policy-loader $SCRIPT_DIR/policies/build/cache_ext_lru.out \\"
echo "    --benchmark ycsb_c \\"
echo "    --cgroup-size-gib 10"
