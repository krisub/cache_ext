#!/usr/bin/env bash
# Run baseline and/or best evolved policy multiple times to measure variance.
#
# Usage:
#   sudo bash run_variance_test.sh              # run both baseline and best, 5 times each
#   sudo bash run_variance_test.sh baseline 5   # run only baseline, 5 times
#   sudo bash run_variance_test.sh best 3       # run only best policy, 3 times
#   sudo bash run_variance_test.sh both 5       # run both, 5 times each
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VARIANCE_DIR="$SCRIPT_DIR/variance_results"

MODE="${1:-both}"
NUM_RUNS="${2:-5}"

mkdir -p "$VARIANCE_DIR"

run_baseline() {
    local run_idx=$1
    echo ""
    echo "================================================================"
    echo "  BASELINE run $run_idx/$NUM_RUNS"
    echo "================================================================"

    local dest="$VARIANCE_DIR/baseline/run_${run_idx}"
    mkdir -p "$dest"

    bash "$SCRIPT_DIR/run_baseline.sh" 2>&1 | tee "$dest/stdout.log"

    LATEST=$(ls -td "$SCRIPT_DIR/baseline_results/baseline_"* 2>/dev/null | head -1)
    if [ -n "$LATEST" ] && [ -d "$LATEST" ]; then
        cp "$LATEST"/*.log "$dest/" 2>/dev/null || true
    fi

    # Build a metrics.json from the logs so the summary script can parse uniformly
    python3 - "$dest" <<'PYEOF'
import sys, os, json
d = sys.argv[1]
svl = cong = 0
svl_p99 = cong_p99 = 0
for name in ["dual_small_vs_large", "dual_congested"]:
    lf = os.path.join(d, f"{name}.log")
    if not os.path.exists(lf):
        continue
    for line in open(lf):
        if line.startswith("total_throughput"):
            val = float(line.split()[1])
            if name == "dual_small_vs_large": svl = val
            else: cong = val
        if line.startswith("read_latency_p99_ns"):
            val = float(line.split()[1])
            if name == "dual_small_vs_large": svl_p99 = val
            else: cong_p99 = val

if svl > 0 and cong > 0:
    hm = 2.0 / (1.0/svl + 1.0/cong)
elif svl > 0 or cong > 0:
    hm = max(svl, cong) * 0.5
else:
    hm = 0

metrics = {
    "combined_score": hm,
    "public": {
        "dual_small_vs_large_throughput": svl,
        "dual_small_vs_large_read_p99_ns": svl_p99,
        "dual_congested_throughput": cong,
        "dual_congested_read_p99_ns": cong_p99,
        "combined_score_harmonic_mean": hm,
        "traces_passed": (1 if svl > 0 else 0) + (1 if cong > 0 else 0),
        "traces_total": 2,
    },
    "private": {
        "dual_small_vs_large": {"total_throughput": svl, "read_latency_p99_ns": svl_p99},
        "dual_congested": {"total_throughput": cong, "read_latency_p99_ns": cong_p99},
    },
}
with open(os.path.join(d, "metrics.json"), "w") as f:
    json.dump(metrics, f, indent=2)
print(f"  => combined={hm:.1f}  svl={svl:.1f}  cong={cong:.1f}")
PYEOF

    echo "  Saved to $dest/"
}

run_best() {
    local run_idx=$1
    echo ""
    echo "================================================================"
    echo "  BEST POLICY run $run_idx/$NUM_RUNS"
    echo "================================================================"

    local dest="$VARIANCE_DIR/best/run_${run_idx}"
    mkdir -p "$dest"

    python3 "$SCRIPT_DIR/evaluate.py" \
        --program_path "$SCRIPT_DIR/results/eviction_evo/best/main.c" \
        --results_dir "$dest" 2>&1 | tee "$dest/stdout.log"

    if [ -f "$dest/metrics.json" ]; then
        python3 -c "
import json
m = json.load(open('$dest/metrics.json'))
print(f'  => combined={m[\"combined_score\"]:.1f}  svl={m[\"public\"][\"dual_small_vs_large_throughput\"]:.1f}  cong={m[\"public\"][\"dual_congested_throughput\"]:.1f}')
"
    else
        echo "  WARNING: no metrics.json produced"
    fi

    echo "  Saved to $dest/"
}

# Main loop
if [ "$MODE" = "baseline" ] || [ "$MODE" = "both" ]; then
    echo "Running $NUM_RUNS baseline iterations..."
    for i in $(seq 1 "$NUM_RUNS"); do
        run_baseline "$i"
        sleep 5
    done
fi

if [ "$MODE" = "best" ] || [ "$MODE" = "both" ]; then
    echo "Running $NUM_RUNS best-policy iterations..."
    for i in $(seq 1 "$NUM_RUNS"); do
        run_best "$i"
        sleep 5
    done
fi

echo ""
echo "================================================================"
echo "  ALL RUNS COMPLETE — run the summary script next:"
echo "  python3 $SCRIPT_DIR/summarize_variance.py"
echo "================================================================"
