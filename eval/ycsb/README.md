# YCSB benchmark

This script benchmarks YCSB performance with LevelDB using 8 different policies:

- Baseline
- Baseline MGLRU
- cache_ext LHD
- cache_ext S3-FIFO
- cache_ext LFU
- cache_ext FIFO
- cache_ext MRU
- cache_ext MGLRU

It also runs Uniform and Uniform R/W workloads with the above policies.

It corresponds to Figure 9 and Table 5 in the paper.

Outputs:

- `results/ycsb_results.json` (for baseline and cache_ext)
- `results/ycsb_results_mglru.json` (for MGLRU)

## Instance-optimality style heatmap (Vulcan-style)

Use the same `run.sh` script, but sweep cache sizes and shorten runtime so the
full run stays within ~4-5 hours.

Example (6 policies x 3 sizes x 8 traces x 1 iteration):

```bash
cd /mydata/cache_ext
ITERATIONS=1 \
RUNTIME_SECONDS=60 \
WARMUP_SECONDS=10 \
CGROUP_SIZES_GIB=1,2,4 \
INCLUDE_BASELINE_MGLRU=0 \
RESULTS_FILE=results/ycsb_instance_optimality_results.json \
eval/ycsb/run.sh
```

If you are hitting OOM kills at tiny size, use this safer profile (does all 3):

- uses larger "tiny" (`2,4,8` GiB),
- reduces pressure (`CPU=4`),
- excludes `ycsb_d` only at the smallest size.

```bash
cd /mydata/cache_ext
CPU=4 \
ITERATIONS=1 \
RUNTIME_SECONDS=60 \
WARMUP_SECONDS=10 \
CGROUP_SIZES_GIB=2,4,8 \
MIN_SIZE_EXCLUDED_WORKLOADS=ycsb_d \
INCLUDE_BASELINE_MGLRU=0 \
RESULTS_FILE=results/ycsb_instance_optimality_results.json \
eval/ycsb/run.sh
```

Then generate the heatmap:

```bash
cd /mydata/cache_ext
python3 eval/ycsb/plot_instance_optimality.py \
  --results-file results/ycsb_instance_optimality_results.json \
  --output results/ycsb_instance_optimality_heatmap.png \
  --summary-csv results/ycsb_instance_optimality_winners.csv
```

Notes:

- `CGROUP_SIZES_GIB` controls the rows in the heatmap.
- `WORKLOADS` can override which traces are used.
- `MIN_SIZE_EXCLUDED_WORKLOADS` excludes workload(s) only for the smallest size
  in `CGROUP_SIZES_GIB` (e.g., skip `ycsb_d` only at tiny size).
- If you also run baseline Linux MGLRU (`INCLUDE_BASELINE_MGLRU=1`), add
  `--include-linux-mglru` to the plotting command.
