#!/bin/bash
set -e

echo "=== Testing best Policy (${#TRACE_NAMES[@]} traces, harmonic mean) ==="

TRACES_DIR=/mydata/cache_ext/eviction_evo/traces
BENCH=/mydata/cache_ext/My-YCSB/build/run_net_leveldb
DUAL_RUNNER="python3 /mydata/cache_ext/eviction_evo/run_dual_trace.py"
# Single-client traces (commented out — dual-client only mode)
#TRACE_NAMES=(ycsb_a ycsb_b ycsb_c ycsb_d ycsb_e ycsb_f uniform uniform_rw dual_small_vs_large dual_congested)
#TRACE_FILES=(ycsb_a.yaml ycsb_b.yaml ycsb_c.yaml ycsb_d.yaml ycsb_e.yaml ycsb_f.yaml uniform.yaml uniform_read_write.yaml dual_small_vs_large.yaml dual_congested.yaml)
# Dual-client traces only
TRACE_NAMES=(dual_small_vs_large dual_congested)
TRACE_FILES=(dual_small_vs_large.yaml dual_congested.yaml)

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

# Run all trace benchmarks
echo "Running ${#TRACE_NAMES[@]} trace benchmarks (30s warmup + 120s measurement each)..."
declare -a THROUGHPUTS

for idx in "${!TRACE_NAMES[@]}"; do
    trace_name="${TRACE_NAMES[$idx]}"
    trace_file="${TRACE_FILES[$idx]}"
    trace_config="$TRACES_DIR/$trace_file"
    trace_log="/mydata/cache_ext/eviction_evo/best_${trace_name}.log"

    echo ""
    echo "--- Trace $((idx+1))/${#TRACE_NAMES[@]}: $trace_name ---"

    # Drop page cache between traces
    if [ "$idx" -gt 0 ]; then
        sync
        echo 3 > /proc/sys/vm/drop_caches
        sleep 2
    fi

    # Detect dual-client traces (YAML has 'type: dual_client')
    if python3 -c "import yaml,sys; c=yaml.safe_load(open(sys.argv[1])); exit(0 if c.get('type')=='dual_client' else 1)" "$trace_config" 2>/dev/null; then
        # Dual-client: use run_dual_trace.py (server already running)
        $DUAL_RUNNER "$trace_config" > "$trace_log" 2>&1
        TP=$(grep "^total_throughput" "$trace_log" | awk '{print $2}')
        [ -z "$TP" ] && TP=0
    else
        "$BENCH" "$trace_config" 2>&1 | tee "$trace_log"
        TP=$(grep "overall:.*total throughput" "$trace_log" | tail -1 | grep -oP 'total throughput \K[0-9.]+' || echo "0")
    fi
    THROUGHPUTS[$idx]="$TP"
    echo "  $trace_name throughput: $TP ops/sec"
done

# Parse results using dynamic throughputs array
echo ""
echo "=== Results ==="
TP_LIST=$(IFS=,; echo "${THROUGHPUTS[*]}")
python3 -c "
import re

trace_names = '${TRACE_NAMES[*]}'.split()
throughputs = [$TP_LIST]

for name, tp in zip(trace_names, throughputs):
    print(f'  {name:24s}  {tp:.2f} ops/sec')

nonzero = [t for t in throughputs if t > 0]
if len(nonzero) == len(throughputs) and len(throughputs) > 0:
    hm = len(throughputs) / sum(1.0 / t for t in throughputs)
elif len(nonzero) > 0:
    hm_partial = len(nonzero) / sum(1.0 / t for t in nonzero)
    hm = hm_partial * (len(nonzero) / len(throughputs))
else:
    hm = 0.0

print(f'\nCombined score (harmonic mean): {hm:.4f} ops/sec')
print(f'Traces passed: {len(nonzero)}/{len(throughputs)}')
"

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
echo "  Trace logs: /mydata/cache_ext/eviction_evo/best_*.log"
echo "  Loader log: /mydata/cache_ext/eviction_evo/loader_output.log"
