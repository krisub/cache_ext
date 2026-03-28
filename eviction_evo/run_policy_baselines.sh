#!/usr/bin/env bash
# Run all cache_ext policy baselines and collect metrics.json for each.
#
# Policies: fifo, lhd, mglru, mru, s3fifo, sampling (cache_ext LRU/sampling)
# Each run uses evaluate.py with --policy_name, producing metrics.json in the
# same format as evolution (combined_score, public, private, 5 runs per trace).
#
# Usage:
#   ./run_policy_baselines.sh              # Run all policies
#   ./run_policy_baselines.sh fifo sampling  # Run only specified policies
#
# Output: baseline_results/policy_baselines/<policy>/metrics.json

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICIES_DIR="$SCRIPT_DIR/../policies"
RESULTS_BASE="$SCRIPT_DIR/baseline_results/policy_baselines"
EVALUATE_PY="$SCRIPT_DIR/evaluate.py"

# Policies to run (short names matching cache_ext_<name>.out)
DEFAULT_POLICIES=(fifo lhd mglru mru sampling)

# Parse policy list from args, or use defaults
if [ $# -gt 0 ]; then
    POLICIES=("$@")
else
    POLICIES=("${DEFAULT_POLICIES[@]}")
fi

echo "========================================"
echo "  Cache_ext Policy Baselines"
echo "  Policies: ${POLICIES[*]}"
echo "  Results: $RESULTS_BASE/<policy>/metrics.json"
echo "========================================"

# Build policies first
echo ""
echo "=== Building policies in $POLICIES_DIR ==="
make -C "$POLICIES_DIR" -j"$(nproc)" || {
    echo "ERROR: Policy build failed. Fix and rerun."
    exit 1
}

# Run each policy
for policy in "${POLICIES[@]}"; do
    loader="$POLICIES_DIR/cache_ext_${policy}.out"
    if [ ! -f "$loader" ]; then
        echo "WARNING: $loader not found, skipping $policy"
        continue
    fi

    results_dir="$RESULTS_BASE/$policy"
    mkdir -p "$results_dir"

    echo ""
    echo "========================================"
    echo "  Running policy: $policy"
    echo "  Results dir: $results_dir"
    echo "========================================"

    if python3 "$EVALUATE_PY" --policy_name "$policy" --results_dir "$results_dir"; then
        echo "  OK: $policy -> $results_dir/metrics.json"
    else
        echo "  FAILED: $policy (exit code $?)"
    fi
done

echo ""
echo "========================================"
echo "  Summary: metrics.json locations"
echo "========================================"
for policy in "${POLICIES[@]}"; do
    m="$RESULTS_BASE/$policy/metrics.json"
    if [ -f "$m" ]; then
        score=$(python3 -c "import json; d=json.load(open('$m')); print(d.get('combined_score', 'N/A'))" 2>/dev/null || echo "?")
        echo "  $policy: $m (score: $score)"
    else
        echo "  $policy: (no metrics.json)"
    fi
done
echo "========================================"
