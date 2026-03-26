#!/bin/bash
# Debug the vulcan eviction timeout.
# Run from eviction_evo directory. Saves timeout capture to results/.../client_timeout_debug.txt

set -e
cd "$(dirname "$0")"

PROGRAM="${1:-results/vulcan_evo/gen_0/main.c}"
RESULTS="${2:-results/vulcan_evo/gen_0/results}"

echo "=== Debug run: program=$PROGRAM results=$RESULTS ==="
echo "Using --debug: 1 trace, 1 run, shorter warmup (10s) + runtime (30s)"
echo "On timeout, partial client output saved to: $RESULTS/client_timeout_debug.txt"
echo ""

python evaluate.py --program_path "$PROGRAM" --results_dir "$RESULTS" --debug 2>&1 | tee /tmp/eval_debug.log

if [[ -f "$RESULTS/client_timeout_debug.txt" ]]; then
    echo ""
    echo "=== TIMEOUT DEBUG OUTPUT (saved) ==="
    cat "$RESULTS/client_timeout_debug.txt"
fi
