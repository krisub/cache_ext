#!/usr/bin/env bash
# Measure MGLRU baseline: server inside 2GiB cgroup, no BPF policy.
set -e

BENCH=/mydata/cache_ext/My-YCSB/build/run_net_leveldb
SERVER=/mydata/cache_ext/net_leveldb_server
DB=/mydata/leveldb_temp
CONFIG=/mydata/cache_ext/eviction_evo/build/bench_config.yaml
CGROUP=cache_ext_test
MEM_LIMIT=536870912    # 512 MiB — matches evaluate.py cgroup limit
RESULTS_DIR=/mydata/cache_ext/eviction_evo/baseline_results
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULT_FILE="$RESULTS_DIR/baseline_${TIMESTAMP}.log"

mkdir -p "$RESULTS_DIR"

echo "=== MGLRU Baseline ($TIMESTAMP) ==="
echo "Results will be saved to: $RESULT_FILE"

# Clean up any leftovers
sudo pkill -9 -f "net_leveldb_server" 2>/dev/null || true
sleep 1

sudo sh -c "echo 1 > /proc/sys/vm/drop_caches"
sudo cgdelete "memory:$CGROUP" 2>/dev/null || true
sudo cgcreate -g "memory:$CGROUP"
sudo sh -c "echo $MEM_LIMIT > /sys/fs/cgroup/$CGROUP/memory.max"

# Start server inside cgroup (no BPF)
sudo cgexec -g "memory:$CGROUP" "$SERVER" 9100 "$DB" &
SERVER_PID=$!

# Wait for it to accept connections
for i in $(seq 1 60); do
    (echo >/dev/tcp/127.0.0.1/9100) 2>/dev/null && break || sleep 1
done
echo "Server ready (PID $SERVER_PID)"

# Run benchmark — output goes to screen AND result file
"$BENCH" "$CONFIG" 2>&1 | tee "$RESULT_FILE"

# Cleanup
sudo kill $SERVER_PID 2>/dev/null || true
sudo cgdelete "memory:$CGROUP" 2>/dev/null || true

# Parse and display summary
THROUGHPUT=$(grep "overall:.*total throughput" "$RESULT_FILE" | tail -1 | grep -oP 'total throughput \K[0-9.]+')
READ_TP=$(grep "overall:.*total throughput" "$RESULT_FILE" | tail -1 | grep -oP 'READ throughput \K[0-9.]+')
READ_AVG=$(grep "overall:.*average latency" "$RESULT_FILE" | tail -1 | grep -oP 'READ average latency \K[0-9.]+')
READ_P99=$(grep "overall:.*p99 latency" "$RESULT_FILE" | tail -1 | grep -oP 'READ p99 latency \K[0-9.]+')

# Same formula as evaluate.py:
#   latency_bonus = min(1.0, 1_000_000 / max(p99_ns, 1))
#   combined_score = total_throughput + total_throughput * 0.1 * latency_bonus
COMBINED_SCORE=$(awk "BEGIN{
    p99   = $READ_P99
    tp    = $THROUGHPUT
    bonus = 1000000 / (p99 > 1 ? p99 : 1)
    if (bonus > 1.0) bonus = 1.0
    printf \"%.4f\", tp + tp * 0.1 * bonus
}")

echo ""
echo "========================================"
echo "  MGLRU BASELINE RESULTS ($TIMESTAMP)"
echo "========================================"
printf "  Combined score:       %s\n"         "$COMBINED_SCORE"
printf "  Total throughput:     %s ops/sec\n" "$THROUGHPUT"
printf "  Read  throughput:     %s ops/sec\n" "$READ_TP"
printf "  Read  avg latency:    %s ms\n"      "$(awk "BEGIN{printf \"%.1f\", $READ_AVG/1e6}")"
printf "  Read  p99 latency:    %s ms\n"      "$(awk "BEGIN{printf \"%.1f\", $READ_P99/1e6}")"
echo "========================================"
echo "  Full log: $RESULT_FILE"
echo "========================================"

# Append a one-line summary to a persistent summary file
SUMMARY_FILE="$RESULTS_DIR/summary.txt"
if [ ! -f "$SUMMARY_FILE" ]; then
    printf "timestamp\tcombined_score\tthroughput_ops_sec\tread_throughput\tread_avg_ms\tread_p99_ms\n" > "$SUMMARY_FILE"
fi
printf "%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$TIMESTAMP" "$COMBINED_SCORE" "$THROUGHPUT" "$READ_TP" \
    "$(awk "BEGIN{printf \"%.1f\", $READ_AVG/1e6}")" \
    "$(awk "BEGIN{printf \"%.1f\", $READ_P99/1e6}")" \
    >> "$SUMMARY_FILE"
echo ""
echo "Appended to summary: $SUMMARY_FILE"

