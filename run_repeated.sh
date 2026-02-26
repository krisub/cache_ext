#!/bin/bash
# Run setup_netbench.sh + client.py N times for reproducibility testing.
#
# Usage: ./run_repeated.sh [output_prefix] [num_runs]
#   output_prefix: base name for output files (default: net)
#   num_runs: number of runs (default: 5)
#
# Output: data/<prefix>_1.csv, data/<prefix>_2.csv, ...
#
# Full workflow:
#   1. Terminal 1: sudo python3 bench/load_policy.py policies/cache_ext_mglru.out
#      (or policies/cache_ext_net.out for network heuristic)
#   2. Terminal 2: ./run_repeated.sh mglru 5    # for MGLRU
#      Then load net policy and: ./run_repeated.sh net_heuristic 5
#   3. Analyze: python3 analyze_repeated.py --mglru data/mglru_*.csv --net data/net_heuristic_*.csv --plot

set -e
cd "$(dirname "$0")"

PREFIX="${1:-net}"
NUM_RUNS="${2:-5}"

echo "=== Repeated benchmark: $NUM_RUNS runs, output prefix: $PREFIX ==="
echo "Ensure policy is loaded in another terminal (load_policy.py)"
echo ""

mkdir -p data

for i in $(seq 1 "$NUM_RUNS"); do
    echo ""
    echo "========== Run $i / $NUM_RUNS =========="
    ./setup_netbench.sh
    sleep 2  # allow servers to bind
    python3 ./client.py -o "data/${PREFIX}_${i}.csv"
    echo "Saved data/${PREFIX}_${i}.csv"
done

echo ""
echo "=== Done. Output files: ==="
ls -la data/${PREFIX}_*.csv
