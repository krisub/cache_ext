#!/usr/bin/env python3
import argparse
import json
import math
import os
from collections import defaultdict

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch

GIB = 2**30

DEFAULT_BENCHMARKS = [
    "ycsb_a",
    "ycsb_b",
    "ycsb_c",
    "ycsb_d",
    "ycsb_e",
    "ycsb_f",
    "uniform",
    "uniform_read_write",
]

DEFAULT_POLICIES = [
    "cache_ext_lhd",
    "cache_ext_s3fifo",
    "cache_ext_sampling",
    "cache_ext_fifo",
    "cache_ext_mru",
    "cache_ext_mglru",
]

POLICY_LABELS = {
    "cache_ext_lhd": "LHD",
    "cache_ext_s3fifo": "S3FIFO",
    "cache_ext_sampling": "SAMPLING",
    "cache_ext_fifo": "FIFO",
    "cache_ext_mru": "MRU",
    "cache_ext_mglru": "MGLRU",
    "linux_mglru": "Linux-MGLRU",
}


def parse_list(value: str):
    return [x.strip() for x in value.split(",") if x.strip()]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Plot policy winner counts per cache size (Vulcan-style heatmap)"
    )
    parser.add_argument(
        "--results-file",
        default="results/ycsb_results.json",
        help="JSON file from eval/ycsb/run.sh (cache_ext policies)",
    )
    parser.add_argument(
        "--mglru-results-file",
        default="results/ycsb_results_mglru.json",
        help="Optional JSON file from eval/ycsb/run.sh for Linux MGLRU baseline",
    )
    parser.add_argument(
        "--include-linux-mglru",
        action="store_true",
        help="Add Linux MGLRU as an extra policy column if mglru results are available",
    )
    parser.add_argument(
        "--benchmarks",
        default=",".join(DEFAULT_BENCHMARKS),
        help="Comma-separated benchmarks to treat as traces",
    )
    parser.add_argument(
        "--policies",
        default=",".join(DEFAULT_POLICIES),
        help="Comma-separated policy ids from policy_loader names",
    )
    parser.add_argument(
        "--output",
        default="results/ycsb_instance_optimality_heatmap.png",
        help="Output heatmap path",
    )
    parser.add_argument(
        "--summary-csv",
        default="results/ycsb_instance_optimality_winners.csv",
        help="CSV with per-(size,trace) winner details",
    )
    parser.add_argument(
        "--title",
        default="Best Policy by Cache Size Across YCSB Workloads",
        help="Plot title",
    )
    parser.add_argument(
        "--subtitle",
        default="Cell value = number of workloads where this policy has the highest mean throughput",
        help="Subtitle under the main title",
    )
    parser.add_argument(
        "--show-legend",
        action="store_true",
        help="Show legend explaining cell values and tie handling",
    )
    parser.add_argument(
        "--tie-epsilon",
        type=float,
        default=1e-9,
        help="Absolute epsilon for tie handling",
    )
    return parser.parse_args()


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def parse_policy(cfg):
    policy_loader = cfg.get("policy_loader", "")
    if not policy_loader:
        return None
    base = os.path.basename(policy_loader)
    if base.endswith(".out"):
        return base[:-4]
    return base


def collect_scores(raw_runs, benchmark_set, policy_set):
    scores = defaultdict(list)
    for run in raw_runs:
        cfg = run.get("config", {})
        bench = cfg.get("benchmark")
        if bench not in benchmark_set:
            continue
        policy = parse_policy(cfg)
        if policy not in policy_set:
            continue
        cgroup_size = cfg.get("cgroup_size")
        if not cgroup_size:
            continue
        size_gib = int(round(float(cgroup_size) / GIB))
        metric = run.get("results", {}).get("throughput_avg")
        if metric is None:
            continue
        scores[(size_gib, bench, policy)].append(float(metric))
    return {k: float(np.mean(v)) for k, v in scores.items()}


def collect_linux_mglru_scores(raw_runs, benchmark_set):
    scores = defaultdict(list)
    for run in raw_runs:
        cfg = run.get("config", {})
        if cfg.get("cgroup_name") != "baseline_test":
            continue
        bench = cfg.get("benchmark")
        if bench not in benchmark_set:
            continue
        cgroup_size = cfg.get("cgroup_size")
        if not cgroup_size:
            continue
        size_gib = int(round(float(cgroup_size) / GIB))
        metric = run.get("results", {}).get("throughput_avg")
        if metric is None:
            continue
        scores[(size_gib, bench, "linux_mglru")].append(float(metric))
    return {k: float(np.mean(v)) for k, v in scores.items()}


def size_labels(sizes):
    if len(sizes) == 3:
        return ["Tiny", "Small", "Large"]
    return [f"{size} GiB" for size in sizes]


def write_summary_csv(path, rows):
    with open(path, "w") as f:
        f.write("size_gib,benchmark,winner_policies,max_throughput_ops\n")
        for row in rows:
            f.write(
                f"{row['size_gib']},{row['benchmark']},{'|'.join(row['winners'])},{row['max_value']:.2f}\n"
            )


def main():
    args = parse_args()
    benchmarks = parse_list(args.benchmarks)
    policies = parse_list(args.policies)

    raw_runs = load_json(args.results_file)
    score_map = collect_scores(raw_runs, set(benchmarks), set(policies))

    if args.include_linux_mglru and os.path.exists(args.mglru_results_file):
        mglru_runs = load_json(args.mglru_results_file)
        score_map.update(collect_linux_mglru_scores(mglru_runs, set(benchmarks)))
        policies = policies + ["linux_mglru"]

    sizes = sorted({k[0] for k in score_map.keys()})
    if not sizes:
        raise ValueError("No matching scores found. Check input files and filters.")

    counts = np.zeros((len(sizes), len(policies)))
    detail_rows = []

    for size_idx, size in enumerate(sizes):
        for bench in benchmarks:
            vals = []
            for policy in policies:
                key = (size, bench, policy)
                if key in score_map:
                    vals.append((policy, score_map[key]))
            if not vals:
                continue
            max_value = max(v for _, v in vals)
            winners = [
                p for p, v in vals if math.isclose(v, max_value, abs_tol=args.tie_epsilon)
            ]
            for winner in winners:
                counts[size_idx, policies.index(winner)] += 1.0 / len(winners)
            detail_rows.append(
                {
                    "size_gib": size,
                    "benchmark": bench,
                    "winners": winners,
                    "max_value": max_value,
                }
            )

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(args.summary_csv) or ".", exist_ok=True)
    write_summary_csv(args.summary_csv, detail_rows)

    fig, ax = plt.subplots(figsize=(11, 5))
    im = ax.imshow(counts, cmap="YlGnBu")
    ax.set_xticks(np.arange(len(policies)))
    ax.set_xticklabels([POLICY_LABELS.get(p, p) for p in policies], rotation=35, ha="right")
    ax.set_yticks(np.arange(len(sizes)))
    ax.set_yticklabels(size_labels(sizes))
    ax.set_xlabel("Policy (higher value = wins more workloads)")
    ax.set_ylabel("Cache Size")
    ax.set_title(args.title, fontsize=14, pad=16)
    if args.subtitle:
        ax.text(
            0.5,
            1.02,
            args.subtitle,
            transform=ax.transAxes,
            ha="center",
            va="bottom",
            fontsize=10,
        )

    for i in range(counts.shape[0]):
        for j in range(counts.shape[1]):
            value = counts[i, j]
            text = f"{int(round(value))}" if abs(value - round(value)) < 1e-6 else f"{value:.1f}"
            color = "white" if value >= (counts.max() * 0.45 if counts.max() > 0 else 0) else "black"
            ax.text(j, i, text, ha="center", va="center", color=color, fontsize=12)

    cbar = fig.colorbar(im, ax=ax)
    cbar.set_label("Winner Count (Number of Workloads)")
    if args.show_legend:
        legend_items = [
            # Patch(facecolor="none", edgecolor="none", label="Integer values: clear winner"),
            # Patch(
            #     facecolor="none",
            #     edgecolor="none",
            #     label="Fractional values (e.g., 0.5): tie split evenly",
            # ),
        ]
        ax.legend(
            handles=legend_items,
            loc="upper center",
            bbox_to_anchor=(0.5, -0.14),
            frameon=False,
            fontsize=9,
            ncol=1,
        )
    fig.tight_layout()
    fig.savefig(args.output, dpi=220, bbox_inches="tight")
    print(f"Saved heatmap to {args.output}")
    print(f"Saved winner summary to {args.summary_csv}")


if __name__ == "__main__":
    main()
