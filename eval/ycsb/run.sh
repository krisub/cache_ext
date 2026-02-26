#!/bin/bash
# YCSB run script (Figure 9 and Table 5)
set -eu -o pipefail

if ! uname -r | grep -q "cache-ext"; then
	echo "This script is intended to be run on a cache_ext kernel."
	echo "Please switch to the cache_ext kernel and try again."
	exit 1
fi

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(realpath "$(dirname $SCRIPT_PATH)/../../")
BENCH_PATH="$BASE_DIR/bench"
POLICY_PATH="$BASE_DIR/policies"
YCSB_PATH="$BASE_DIR/My-YCSB"
DB_PATH=$(realpath "$BASE_DIR/../leveldb")
RESULTS_PATH="$BASE_DIR/results"

ITERATIONS="${ITERATIONS:-3}"
CPU="${CPU:-8}"
RUNTIME_SECONDS="${RUNTIME_SECONDS:-240}"
WARMUP_SECONDS="${WARMUP_SECONDS:-45}"
CGROUP_SIZES_GIB="${CGROUP_SIZES_GIB:-10}"
WORKLOADS="${WORKLOADS:-ycsb_a,ycsb_b,ycsb_c,ycsb_d,ycsb_e,ycsb_f,uniform,uniform_read_write}"
MIN_SIZE_EXCLUDED_WORKLOADS="${MIN_SIZE_EXCLUDED_WORKLOADS:-}"
RESULTS_FILE="${RESULTS_FILE:-$RESULTS_PATH/ycsb_results.json}"
MGLRU_RESULTS_FILE="${MGLRU_RESULTS_FILE:-$RESULTS_PATH/ycsb_results_mglru.json}"
INCLUDE_BASELINE_MGLRU="${INCLUDE_BASELINE_MGLRU:-1}"

POLICIES=(
	"cache_ext_lhd"
	"cache_ext_s3fifo"
	"cache_ext_sampling"
	"cache_ext_fifo"
	"cache_ext_mru"
	"cache_ext_mglru"
)

mkdir -p "$RESULTS_PATH"

NUM_POLICIES=${#POLICIES[@]}
NUM_SIZES=$(echo "$CGROUP_SIZES_GIB" | tr ',' '\n' | grep -c . || true)
NUM_BENCHES=$(echo "$WORKLOADS" | tr ',' '\n' | grep -c . || true)
EST_SECONDS=$((NUM_POLICIES * NUM_SIZES * NUM_BENCHES * (RUNTIME_SECONDS + WARMUP_SECONDS + 15) * ITERATIONS))
EST_HOURS=$(awk "BEGIN { printf \"%.2f\", $EST_SECONDS/3600 }")
MIN_SIZE_GIB=$(echo "$CGROUP_SIZES_GIB" | tr ',' '\n' | awk 'NF{print $1}' | sort -n | head -n1)
echo "Estimated runtime: ~${EST_HOURS} hours"
echo "  policies=$NUM_POLICIES sizes=$NUM_SIZES workloads=$NUM_BENCHES iterations=$ITERATIONS"
echo "  runtime=${RUNTIME_SECONDS}s warmup=${WARMUP_SECONDS}s"
if [ -n "$MIN_SIZE_EXCLUDED_WORKLOADS" ]; then
	echo "  min-size exclusion: size=${MIN_SIZE_GIB}GiB skip=[$MIN_SIZE_EXCLUDED_WORKLOADS]"
fi

join_by_comma() {
	local first=1
	local out=""
	for item in "$@"; do
		if [ $first -eq 1 ]; then
			out="$item"
			first=0
		else
			out="$out,$item"
		fi
	done
	echo "$out"
}

filter_workloads_for_size() {
	local size_gib="$1"
	local workloads_csv="$2"
	local exclude_csv="$3"
	if [ -z "$exclude_csv" ] || [ "$size_gib" != "$MIN_SIZE_GIB" ]; then
		echo "$workloads_csv"
		return
	fi
	local workloads_arr=()
	local exclude_arr=()
	local filtered_arr=()
	IFS=',' read -r -a workloads_arr <<< "$workloads_csv"
	IFS=',' read -r -a exclude_arr <<< "$exclude_csv"
	for w in "${workloads_arr[@]}"; do
		local skip=0
		for ex in "${exclude_arr[@]}"; do
			if [ "$w" = "$ex" ]; then
				skip=1
				break
			fi
		done
		if [ $skip -eq 0 ]; then
			filtered_arr+=("$w")
		fi
	done
	join_by_comma "${filtered_arr[@]}"
}

# Build correct My-YCSB version
cd "$YCSB_PATH/build"
git checkout master
make clean
make -j run_leveldb

cd -

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

# Baseline and cache_ext
for POLICY in "${POLICIES[@]}"; do
	echo "Running policy: ${POLICY}"
	for SIZE_GIB in $(echo "$CGROUP_SIZES_GIB" | tr ',' ' '); do
		SIZE_WORKLOADS=$(filter_workloads_for_size "$SIZE_GIB" "$WORKLOADS" "$MIN_SIZE_EXCLUDED_WORKLOADS")
		if [ -z "$SIZE_WORKLOADS" ]; then
			echo "Skipping size ${SIZE_GIB}GiB for ${POLICY}: no workloads left after filtering"
			continue
		fi
		echo "  size=${SIZE_GIB}GiB workloads=${SIZE_WORKLOADS}"
		python3 "$BENCH_PATH/bench_leveldb.py" \
			--cpu "$CPU" \
			--policy-loader "$POLICY_PATH/${POLICY}.out" \
			--results-file "$RESULTS_FILE" \
			--leveldb-db "$DB_PATH" \
			--fadvise-hints "" \
			--iterations "$ITERATIONS" \
			--runtime-seconds "$RUNTIME_SECONDS" \
			--warmup-runtime-seconds "$WARMUP_SECONDS" \
			--cgroup-size-gib "$SIZE_GIB" \
			--bench-binary-dir "$YCSB_PATH/build" \
			--benchmark "$SIZE_WORKLOADS"
	done
done

if [ "$INCLUDE_BASELINE_MGLRU" = "1" ]; then
	# Enable MGLRU
	if ! "$BASE_DIR/utils/enable-mglru.sh"; then
		echo "Failed to enable MGLRU. Please check the script."
		exit 1
	fi

	# MGLRU
	# TODO: Remove --policy-loader requirement when using --default-only
	echo "Running baseline MGLRU"
	for SIZE_GIB in $(echo "$CGROUP_SIZES_GIB" | tr ',' ' '); do
		SIZE_WORKLOADS=$(filter_workloads_for_size "$SIZE_GIB" "$WORKLOADS" "$MIN_SIZE_EXCLUDED_WORKLOADS")
		if [ -z "$SIZE_WORKLOADS" ]; then
			echo "Skipping size ${SIZE_GIB}GiB for baseline MGLRU: no workloads left after filtering"
			continue
		fi
		echo "  size=${SIZE_GIB}GiB workloads=${SIZE_WORKLOADS}"
		python3 "$BENCH_PATH/bench_leveldb.py" \
			--cpu "$CPU" \
			--policy-loader "$POLICY_PATH/${POLICIES[0]}.out" \
			--results-file "$MGLRU_RESULTS_FILE" \
			--leveldb-db "$DB_PATH" \
			--fadvise-hints "" \
			--iterations "$ITERATIONS" \
			--runtime-seconds "$RUNTIME_SECONDS" \
			--warmup-runtime-seconds "$WARMUP_SECONDS" \
			--cgroup-size-gib "$SIZE_GIB" \
			--bench-binary-dir "$YCSB_PATH/build" \
			--benchmark "$SIZE_WORKLOADS" \
			--default-only
	done

	# Disable MGLRU
	if ! "$BASE_DIR/utils/disable-mglru.sh"; then
		echo "Failed to disable MGLRU. Please check the script."
		exit 1
	fi
fi

echo "YCSB benchmark completed. Results saved to $RESULTS_PATH."
