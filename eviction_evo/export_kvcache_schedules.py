#!/usr/bin/env python3
"""
Build two rate-schedule CSV files (one aggregate-ops/s per experiment second) from a
Meta-style kvcache CSV, using the same compression windows as plot_kvcache_compress.py.

Output format: one column per line, target aggregate ops/s for experiment seconds 0..N-1.
Referenced from net_leveldb YAML as workload.rate_schedule_file.

Example:
  python3 export_kvcache_schedules.py /mydata/kvcache_traces_1.csv \\
    --out-a /mydata/cache_ext/eviction_evo/schedules/window_10000_40000.csv \\
    --out-b /mydata/cache_ext/eviction_evo/schedules/window_40000_70000.csv
"""
from __future__ import annotations

import argparse
import sys

import numpy as np
import pandas as pd

N_EXP = 120
CHUNK = 3_000_000


def build_histogram(path: str) -> tuple[np.ndarray, int]:
    t_min, t_max = None, None
    for chunk in pd.read_csv(path, usecols=["op_time"], chunksize=CHUNK):
        lo, hi = int(chunk["op_time"].min()), int(chunk["op_time"].max())
        t_min = lo if t_min is None else min(t_min, lo)
        t_max = hi if t_max is None else max(t_max, hi)
    span = t_max - t_min + 1
    bins = np.zeros(span, dtype=np.int64)
    for chunk in pd.read_csv(path, usecols=["op_time"], chunksize=CHUNK):
        idx = chunk["op_time"].to_numpy(dtype=np.int64, copy=False) - t_min
        np.add.at(bins, idx, 1)
    return bins, t_min


def compress_window(bins: np.ndarray, start_off: int, end_off: int) -> np.ndarray:
    lo_s, hi_s = start_off, end_off
    L = hi_s - lo_s
    if L <= 0:
        raise ValueError("empty window")
    if hi_s > len(bins):
        raise ValueError(f"window end {hi_s} past histogram length {len(bins)}")
    out = np.zeros(N_EXP, dtype=np.float64)
    for u in range(N_EXP):
        t0 = lo_s + (u / N_EXP) * L
        t1 = lo_s + ((u + 1) / N_EXP) * L
        i0 = int(np.floor(t0))
        i1 = int(np.ceil(t1))
        i0 = max(i0, lo_s)
        i1 = min(i1, hi_s)
        if i1 <= i0:
            out[u] = float(bins[i0])
        else:
            out[u] = float(bins[i0:i1].mean())
    return out


def write_schedule_csv(path: str, qps: np.ndarray) -> None:
    with open(path, "w") as f:
        f.write("# target_aggregate_ops_per_sec (one row per experiment second)\n")
        for v in qps:
            f.write(f"{v:.6f}\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("kvcache_csv", type=str, help="Source kvcache trace CSV")
    ap.add_argument("--out-a", type=str, required=True, help="Output CSV for window A")
    ap.add_argument("--out-b", type=str, required=True, help="Output CSV for window B")
    ap.add_argument("--w1", type=str, default="10000,40000", help="Window A start,end (trace seconds from t_min)")
    ap.add_argument("--w2", type=str, default="40000,70000", help="Window B start,end")
    args = ap.parse_args()

    a0, a1 = map(int, args.w1.split(","))
    b0, b1 = map(int, args.w2.split(","))

    print("Building histogram (two passes)...", file=sys.stderr)
    bins, t_min = build_histogram(args.kvcache_csv)
    print(f"t_min={t_min}, bins={len(bins)}", file=sys.stderr)

    y1 = compress_window(bins, a0, a1)
    y2 = compress_window(bins, b0, b1)

    write_schedule_csv(args.out_a, y1)
    write_schedule_csv(args.out_b, y2)
    print(f"Wrote {args.out_a} and {args.out_b} ({N_EXP} lines each)", file=sys.stderr)


if __name__ == "__main__":
    main()
