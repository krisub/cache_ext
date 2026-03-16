#!/usr/bin/env python3
"""
Summarize variance test results from run_variance_test.sh.

Usage:
    python3 summarize_variance.py
    python3 summarize_variance.py /path/to/variance_results
"""
import json
import os
import statistics
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VARIANCE_DIR = sys.argv[1] if len(sys.argv) > 1 else os.path.join(SCRIPT_DIR, "variance_results")

METRICS = [
    ("combined_score", "Combined Score"),
    ("dual_small_vs_large_throughput", "SVL Throughput"),
    ("dual_small_vs_large_read_p99_ns", "SVL p99 (ns)"),
    ("dual_congested_throughput", "Congested Throughput"),
    ("dual_congested_read_p99_ns", "Congested p99 (ns)"),
]


def load_runs(label_dir):
    runs = []
    if not os.path.isdir(label_dir):
        return runs
    for entry in sorted(os.listdir(label_dir)):
        mf = os.path.join(label_dir, entry, "metrics.json")
        if os.path.exists(mf):
            with open(mf) as f:
                runs.append((entry, json.load(f)))
    return runs


def extract(m, key):
    if key == "combined_score":
        return m.get("combined_score", 0)
    return m.get("public", {}).get(key, 0)


def print_section(title, runs):
    if not runs:
        print(f"\n{'=' * 70}")
        print(f"  {title}: no data found")
        print(f"{'=' * 70}")
        return

    print(f"\n{'=' * 70}")
    print(f"  {title}  ({len(runs)} runs)")
    print(f"{'=' * 70}")

    header = f"  {'Run':<8}"
    for _, label in METRICS:
        header += f"  {label:>18}"
    print(header)
    print("  " + "-" * (len(header) - 2))

    for name, m in runs:
        row = f"  {name:<8}"
        for key, _ in METRICS:
            val = extract(m, key)
            row += f"  {val:>18.1f}"
        print(row)

    print("  " + "-" * (len(header) - 2))

    for key, label in METRICS:
        values = [extract(m, key) for _, m in runs]
        values = [v for v in values if v > 0]
        if len(values) < 2:
            print(f"  {label}: insufficient data")
            continue
        mean = statistics.mean(values)
        sd = statistics.stdev(values)
        cv = (sd / mean * 100) if mean > 0 else 0
        print(f"  {label:<26}  mean={mean:>10.1f}  stdev={sd:>8.1f}  "
              f"min={min(values):>10.1f}  max={max(values):>10.1f}  CV={cv:.1f}%")


baseline_runs = load_runs(os.path.join(VARIANCE_DIR, "baseline"))
best_runs = load_runs(os.path.join(VARIANCE_DIR, "best"))

print_section("BASELINE (MGLRU, no BPF)", baseline_runs)
print_section("BEST EVOLVED POLICY", best_runs)

if baseline_runs and best_runs:
    print(f"\n{'=' * 70}")
    print("  COMPARISON")
    print(f"{'=' * 70}")
    for key, label in METRICS:
        b_vals = [extract(m, key) for _, m in baseline_runs if extract(m, key) > 0]
        e_vals = [extract(m, key) for _, m in best_runs if extract(m, key) > 0]
        if b_vals and e_vals:
            b_mean = statistics.mean(b_vals)
            e_mean = statistics.mean(e_vals)
            if b_mean > 0:
                pct = (e_mean - b_mean) / b_mean * 100
                direction = "+" if pct >= 0 else ""
                print(f"  {label:<26}  baseline={b_mean:>10.1f}  "
                      f"best={e_mean:>10.1f}  {direction}{pct:.1f}%")

print()
