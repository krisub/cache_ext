#!/bin/bash
set -e

echo "=== Testing best Policy ==="

# Step 0: Drop page cache FIRST (before compilation)
echo "Dropping caches..."
sync
echo 3 > /proc/sys/vm/drop_caches
echo "Page cache dropped."

# Reset database (skip if already synced)
if [ ! -f /mydata/leveldb_temp/CURRENT ]; then
    echo "Database not synced, copying from source..."
    rsync -a --delete /mydata/leveldb/ /mydata/leveldb_temp/
else
    echo "Database already present, skipping rsync"
fi

# Copy best to build directory (same approach as evaluate.py)
echo "Preparing build directory..."
mkdir -p build_best
cp results/eviction_evo/best/main.c build_best/best.bpf.c

# Symlink headers if not already present
for header in cache_ext_lib.bpf.h dir_watcher.bpf.h dir_watcher.h vmlinux.h; do
    if [ ! -e "build_best/$header" ]; then
        if [ -f "build/$header" ]; then
            ln -sf "../build/$header" "build_best/$header"
        elif [ -f "../policies/$header" ]; then
            ln -sf "../../policies/$header" "build_best/$header"
        fi
    fi
done

# Compile best's BPF policy
echo "Compiling best BPF policy..."
cd build_best
clang-14 -O2 -target bpf \
    -D__TARGET_ARCH_x86 \
    -c -g -Wall \
    $(clang-14 -v -E - </dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }') \
    best.bpf.c -o best.bpf.o
cd ..

# Generate skeleton
echo "Generating skeleton..."
/usr/local/sbin/bpftool gen skeleton build_best/best.bpf.o name cache_ext_evolved_bpf > build_best/best.skel.h

# Compile loader (using best skeleton) — flags match evaluate.py exactly
echo "Building loader..."
cp cache_ext_evolved.c build_best/best_loader.c
# Update include to use best.skel.h
sed -i 's/#include "cache_ext_evolved.skel.h"/#include "best.skel.h"/' build_best/best_loader.c

clang-14 -O2 -g -Wall \
    -Ibuild_best \
    -I/mydata/cache_ext/policies \
    build_best/best_loader.c \
    -o build_best/best_loader \
    -L/usr/local/lib64 -lbpf

# Kill any leftover server/loader from previous runs
echo "Killing any leftover processes..."
sudo pkill -9 -f "net_leveldb_server" 2>/dev/null || true
sudo pkill -9 -f "best_loader\|cache_ext_evolved" 2>/dev/null || true
sleep 2

# Disable MGLRU so BPF evict_folios hook is the sole eviction decision maker.
# Without this, the kernel uses MGLRU directly and never calls our BPF hook.
MGLRU_PATH=/sys/kernel/mm/lru_gen/enabled
MGLRU_DISABLED=0
MGLRU_ORIGINAL=0x0007
if [ -f "$MGLRU_PATH" ]; then
    MGLRU_ORIGINAL=$(cat $MGLRU_PATH)
    echo "Disabling MGLRU (was: $MGLRU_ORIGINAL)..."
    echo 0 | sudo tee $MGLRU_PATH > /dev/null
    echo "  New state: $(cat $MGLRU_PATH)"
    MGLRU_DISABLED=1
fi

# Create cgroup
CGROUP_PATH=/sys/fs/cgroup/cache_ext_test
if [ -d "$CGROUP_PATH" ]; then
    echo "Cleaning up existing cgroup..."
    sudo cgdelete memory:cache_ext_test 2>/dev/null || true
fi

echo "Creating cgroup with 512 MiB limit..."
sudo cgcreate -g memory:cache_ext_test
echo $((512 * 1024 * 1024)) > $CGROUP_PATH/memory.max

# Load BPF policy (run OUTSIDE cgroup, same as evaluate.py)
echo "Loading BPF policy (waiting 10s for stabilization)..."
sudo ./build_best/best_loader \
    --cgroup_path $CGROUP_PATH \
    --watch_dir /mydata/leveldb_temp \
    > /mydata/cache_ext/eviction_evo/loader_output.log 2>&1 &
LOADER_PID=$!
sleep 10

# Check loader actually attached successfully
if ! kill -0 $LOADER_PID 2>/dev/null; then
    echo "ERROR: Loader exited early!"
    cat /mydata/cache_ext/eviction_evo/loader_output.log
    exit 1
fi
if ! grep -q "Evolved policy loaded" /mydata/cache_ext/eviction_evo/loader_output.log; then
    echo "ERROR: Loader did not confirm policy attachment!"
    cat /mydata/cache_ext/eviction_evo/loader_output.log
    exit 1
fi
echo "Policy attached: $(cat /mydata/cache_ext/eviction_evo/loader_output.log | head -1)"

# Start server (using absolute path, no cd needed)
echo "Starting net_leveldb_server..."
sudo cgexec -g memory:cache_ext_test \
    /mydata/cache_ext/net_leveldb_server 9100 /mydata/leveldb_temp &
SERVER_PID=$!

# Wait for server to be ready (TCP polling)
echo "Waiting for server to accept connections..."
timeout=120
elapsed=0
while ! nc -z localhost 9100 2>/dev/null; do
    sleep 1
    elapsed=$((elapsed + 1))
    if [ $elapsed -ge $timeout ]; then
        echo "ERROR: Server failed to start within ${timeout}s"
        sudo kill -9 $SERVER_PID $LOADER_PID 2>/dev/null
        exit 1
    fi
done
echo "Server ready after ${elapsed}s"

# Run benchmark
echo "Running benchmark (30s warmup + 120s measurement)..."
/mydata/cache_ext/My-YCSB/build/run_net_leveldb \
    /mydata/cache_ext/eviction_evo/build/bench_config.yaml 2>&1 | tee /mydata/cache_ext/eviction_evo/best_benchmark.log

# Parse results
echo ""
echo "=== Results ==="
python3 << 'EOF'
import re

with open('/mydata/cache_ext/eviction_evo/best_benchmark.log', 'r') as f:
    content = f.read()

# Parse metrics using actual My-YCSB output format
total_tp = None
read_avg_ns = None
read_p99_ns = None

for line in content.splitlines():
    if "overall:" in line:
        # Parse throughput: "total throughput 171.75 ops/sec"
        match = re.search(r'total throughput ([\d.]+) ops/sec', line)
        if match:
            total_tp = float(match.group(1))
        
        # Parse latency in nanoseconds: "READ average latency 46550418.61 ns"
        match = re.search(r'READ average latency ([\d.]+) ns', line)
        if match:
            read_avg_ns = float(match.group(1))
        
        match = re.search(r'READ p99 latency ([\d.]+) ns', line)
        if match:
            read_p99_ns = float(match.group(1))

if total_tp is None or read_p99_ns is None:
    print("ERROR: Could not parse benchmark output")
    print(f"Found: total_tp={total_tp}, read_p99_ns={read_p99_ns}")
    exit(1)

# Calculate combined score
latency_bonus = min(1.0, 1_000_000.0 / max(read_p99_ns, 1.0))
combined_score = total_tp + total_tp * 0.1 * latency_bonus

# Convert to ms for display
read_avg_ms = read_avg_ns / 1_000_000 if read_avg_ns else 0
read_p99_ms = read_p99_ns / 1_000_000

print(f"Combined score:       {combined_score:.4f}")
print(f"Total throughput:     {total_tp:.2f} ops/sec")
print(f"Read  avg latency:    {read_avg_ms:.1f} ms")
print(f"Read  p99 latency:    {read_p99_ms:.1f} ms")
print(f"\nExpected best score: 729.14")
print(f"Actual vs Expected:   {combined_score:.2f} vs 729.14")
if abs(combined_score - 729.14) < 20:
    print("Status: ✓ Matches (within tolerance)")
elif abs(combined_score - 729.14) < 50:
    print("Status: ~ Close (small variance expected)")
else:
    print("Status: ✗ Does not match (significant difference)")
EOF

# Cleanup
echo ""
echo "Cleaning up..."
sudo kill -9 $SERVER_PID $LOADER_PID 2>/dev/null || true
sudo cgdelete memory:cache_ext_test 2>/dev/null || true
rm -rf build_best

# Re-enable MGLRU
if [ "$MGLRU_DISABLED" = "1" ] && [ -f "$MGLRU_PATH" ]; then
    echo "Restoring MGLRU to $MGLRU_ORIGINAL..."
    echo "$MGLRU_ORIGINAL" | sudo tee $MGLRU_PATH > /dev/null
    echo "  State: $(cat $MGLRU_PATH)"
fi

echo ""
echo "Test complete!"
echo "  Benchmark log: /mydata/cache_ext/eviction_evo/best_benchmark.log"
echo "  Loader log:    /mydata/cache_ext/eviction_evo/loader_output.log"
