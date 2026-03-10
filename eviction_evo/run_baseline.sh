#!/usr/bin/env bash
# Measure MGLRU baseline: server inside 512 MiB cgroup, no BPF policy.
# Runs all traces (single + dual-client) and computes harmonic mean of throughputs.
# If --reuse <dir> is given, skips benchmarking and recalculates from existing logs.
set -e

BENCH=/mydata/cache_ext/My-YCSB/build/run_net_leveldb
SERVER=/mydata/cache_ext/net_leveldb_server
DB=/mydata/leveldb_temp
TRACES_DIR=/mydata/cache_ext/eviction_evo/traces
DUAL_RUNNER="python3 /mydata/cache_ext/eviction_evo/run_dual_trace.py"
CGROUP=cache_ext_test
MEM_LIMIT=536870912    # 512 MiB — matches evaluate.py cgroup limit
RESULTS_DIR=/mydata/cache_ext/eviction_evo/baseline_results

# Trace configs: name filename (must match TRACE_CONFIGS in evaluate.py)
# Single-client traces (commented out — dual-client only mode)
#TRACE_NAMES=(ycsb_a ycsb_b ycsb_c ycsb_d ycsb_e ycsb_f uniform uniform_rw dual_small_vs_large dual_congested)
#TRACE_FILES=(ycsb_a.yaml ycsb_b.yaml ycsb_c.yaml ycsb_d.yaml ycsb_e.yaml ycsb_f.yaml uniform.yaml uniform_read_write.yaml dual_small_vs_large.yaml dual_congested.yaml)
# Dual-client traces only
TRACE_NAMES=(dual_small_vs_large dual_congested)
TRACE_FILES=(dual_small_vs_large.yaml dual_congested.yaml)

# ── Check for --reuse mode ──
REUSE_DIR=""
if [ "$1" = "--reuse" ] && [ -n "$2" ]; then
    REUSE_DIR="$2"
    # Allow bare directory name (resolve relative to RESULTS_DIR)
    if [ ! -d "$REUSE_DIR" ] && [ -d "$RESULTS_DIR/$REUSE_DIR" ]; then
        REUSE_DIR="$RESULTS_DIR/$REUSE_DIR"
    fi
    if [ ! -d "$REUSE_DIR" ]; then
        echo "ERROR: --reuse directory does not exist: $REUSE_DIR"
        exit 1
    fi
fi

if [ -n "$REUSE_DIR" ]; then
    # ── Reuse mode: parse existing logs ──
    echo "=== Reusing existing logs from: $REUSE_DIR ==="
    RESULT_DIR="$REUSE_DIR"
else
    # ── Normal mode: run benchmarks ──
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    RESULT_DIR="$RESULTS_DIR/baseline_${TIMESTAMP}"
    mkdir -p "$RESULT_DIR"

    echo "=== MGLRU Baseline ($TIMESTAMP) ==="
    echo "Running ${#TRACE_NAMES[@]} traces"
    echo "Results will be saved to: $RESULT_DIR/"

    # Clean up any leftovers
    sudo pkill -9 -f "net_leveldb_server" 2>/dev/null || true
    sleep 1

    sudo sh -c "echo 3 > /proc/sys/vm/drop_caches"
    sudo cgdelete "memory:$CGROUP" 2>/dev/null || true
    sudo cgcreate -g "memory:$CGROUP"
    sudo sh -c "echo $MEM_LIMIT > /sys/fs/cgroup/$CGROUP/memory.max"

    # Start server inside cgroup (no BPF)
    sudo cgexec -g "memory:$CGROUP" "$SERVER" 9100 "$DB" &
    SERVER_PID=$!

    # Wait for it to accept connections
    for i in $(seq 1 120); do
        (echo >/dev/tcp/127.0.0.1/9100) 2>/dev/null && break || sleep 1
    done
    echo "Server ready (PID $SERVER_PID)"

    # Run each trace benchmark
    for idx in "${!TRACE_NAMES[@]}"; do
        trace_name="${TRACE_NAMES[$idx]}"
        trace_file="${TRACE_FILES[$idx]}"
        trace_config="$TRACES_DIR/$trace_file"
        trace_log="$RESULT_DIR/${trace_name}.log"

        echo ""
        echo "--- Trace $((idx+1))/${#TRACE_NAMES[@]}: $trace_name ---"

        # Drop page cache between traces
        if [ "$idx" -gt 0 ]; then
            sudo sh -c "echo 3 > /proc/sys/vm/drop_caches"
            sleep 2
        fi

        # Detect dual-client traces (YAML has 'type: dual_client')
        if python3 -c "import yaml,sys; c=yaml.safe_load(open(sys.argv[1])); exit(0 if c.get('type')=='dual_client' else 1)" "$trace_config" 2>/dev/null; then
            # Dual-client: use run_dual_trace.py (server already running)
            $DUAL_RUNNER "$trace_config" > "$trace_log" 2>&1
            # Extract throughput from the structured output
            TP=$(grep "^total_throughput" "$trace_log" | awk '{print $2}')
            [ -z "$TP" ] && TP=0
        else
            "$BENCH" "$trace_config" 2>&1 | tee "$trace_log"
            TP=$(grep "overall:.*total throughput" "$trace_log" | tail -1 | grep -oP 'total throughput \K[0-9.]+' || echo "0")
        fi
        THROUGHPUTS[$idx]="$TP"
        echo "  $trace_name throughput: $TP ops/sec"
    done

    # Cleanup server/cgroup
    sudo kill $SERVER_PID 2>/dev/null || true
    sudo cgdelete "memory:$CGROUP" 2>/dev/null || true
fi

# ── Parse throughputs from logs (both modes) ──
declare -a THROUGHPUTS
for idx in "${!TRACE_NAMES[@]}"; do
    trace_name="${TRACE_NAMES[$idx]}"
    trace_log="$RESULT_DIR/${trace_name}.log"
    # Try dual-client format first, then standard format
    TP=$(grep "^total_throughput" "$trace_log" 2>/dev/null | awk '{print $2}')
    if [ -z "$TP" ] || [ "$TP" = "0" ]; then
        TP=$(grep "overall:.*total throughput" "$trace_log" 2>/dev/null | tail -1 | grep -oP 'total throughput \K[0-9.]+' || echo "0")
    fi
    THROUGHPUTS[$idx]="$TP"
done

# Compute harmonic mean of throughputs (same formula as evaluate.py)
TP_LIST=$(IFS=,; echo "${THROUGHPUTS[*]}")
COMBINED_SCORE=$(python3 -c "
tps = [$TP_LIST]
nonzero = [t for t in tps if t > 0]
if len(nonzero) == len(tps) and len(tps) > 0:
    hm = len(tps) / sum(1.0 / t for t in tps)
elif len(nonzero) > 0:
    hm_partial = len(nonzero) / sum(1.0 / t for t in nonzero)
    hm = hm_partial * (len(nonzero) / len(tps))
else:
    hm = 0.0
print(f'{hm:.4f}')
")

echo ""
echo "========================================================"
echo "  MGLRU BASELINE RESULTS ($TIMESTAMP)"
echo "========================================================"
printf "  Combined score (harmonic mean): %s ops/sec\n" "$COMBINED_SCORE"
echo "  ------------------------------------------------"
for idx in "${!TRACE_NAMES[@]}"; do
    printf "  %-12s  %s ops/sec\n" "${TRACE_NAMES[$idx]}" "${THROUGHPUTS[$idx]}"
done
echo "========================================================"
echo "  Traces passed: $(python3 -c "tps=[$TP_LIST]; print(sum(1 for t in tps if t>0))")/${#TRACE_NAMES[@]}"
echo "  Full logs: $RESULT_DIR/"
echo "========================================================"

# Append a one-line summary to a persistent summary file
SUMMARY_FILE="$RESULTS_DIR/summary.txt"
if [ ! -f "$SUMMARY_FILE" ]; then
    printf "timestamp\tcombined_score" > "$SUMMARY_FILE"
    for name in "${TRACE_NAMES[@]}"; do
        printf "\t%s" "$name" >> "$SUMMARY_FILE"
    done
    printf "\n" >> "$SUMMARY_FILE"
fi
printf "%s\t%s" "$TIMESTAMP" "$COMBINED_SCORE" >> "$SUMMARY_FILE"
for idx in "${!TRACE_NAMES[@]}"; do
    printf "\t%s" "${THROUGHPUTS[$idx]}" >> "$SUMMARY_FILE"
done
printf "\n" >> "$SUMMARY_FILE"
echo ""
echo "Appended to summary: $SUMMARY_FILE"

