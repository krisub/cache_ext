#!/usr/bin/env python3
"""
Plot baseline policy comparison from baseline_results/policy_baselines/*/metrics.json.

- Throughput: grouped bars = mean throughput per trace; error bars = stdev across runs (per bar).
- P99 latency: grouped bars = mean read p99 (ns); error bars = stdev of p99 across runs (per bar).

Usage:
  python3 plot_policy_baselines.py
  python3 plot_policy_baselines.py --results-dir /path/to/policy_baselines --out baselines_plots.png
"""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path


TRACE_KEYS = ("dual_small_vs_large", "dual_congested")
TRACE_LABELS = ("small_vs_large", "congested")


def load_metrics(path: Path) -> dict | None:
    with open(path) as f:
        return json.load(f)


def p99_std_from_runs(private_trace: dict) -> float:
    runs = private_trace.get("runs") or []
    vals = [r["read_latency_p99_ns"] for r in runs if "read_latency_p99_ns" in r]
    if len(vals) < 2:
        return 0.0
    return statistics.stdev(vals)


def collect_policies(results_dir: Path) -> list[tuple[str, dict]]:
    rows: list[tuple[str, dict]] = []
    for sub in sorted(results_dir.iterdir()):
        if not sub.is_dir():
            continue
        mpath = sub / "metrics.json"
        if not mpath.exists():
            continue
        data = load_metrics(mpath)
        if not data:
            continue
        pub = data.get("public") or {}
        if "error" in pub and pub.get("error"):
            print(f"skip {pub.get('error')!r}: {mpath}")
            continue
        priv = data.get("private") or {}
        if not all(k in priv for k in TRACE_KEYS):
            print(f"skip missing traces: {mpath}")
            continue
        rows.append((sub.name, data))
    return rows


def plot_figure(
    policies: list[str],
    bar_means: list[list[float]],
    bar_stds: list[list[float]],
    y_label: str,
    title: str,
    out_path: Path,
) -> None:
    import matplotlib.pyplot as plt
    import numpy as np

    n_pol = len(policies)
    n_trace = len(TRACE_KEYS)
    x = np.arange(n_pol)
    width = 0.36
    colors_bar = ("#3b82f6", "#f97316")

    fig, ax = plt.subplots(figsize=(max(8, n_pol * 1.2), 5.5))

    for j in range(n_trace):
        offset = (j - (n_trace - 1) / 2) * width
        means = [bar_means[i][j] for i in range(n_pol)]
        stds = [bar_stds[i][j] for i in range(n_pol)]
        ax.bar(
            x + offset,
            means,
            width,
            yerr=stds,
            capsize=4,
            label=TRACE_LABELS[j],
            color=colors_bar[j],
            alpha=0.85,
            zorder=2,
            error_kw={
                "elinewidth": 1.6,
                "capthick": 1.6,
                "ecolor": "#334155",
            },
        )

    ax.set_xticks(x)
    ax.set_xticklabels(policies, rotation=25, ha="right")
    ax.set_ylabel(y_label)
    ax.set_title(title)

    ax.legend(
        loc="upper right",
        fontsize=9,
        title="Trace (error bar = stdev)",
    )
    ax.grid(True, axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"Wrote {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Plot policy baseline throughput and p99 charts.")
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "baseline_results" / "policy_baselines",
        help="Directory containing <policy>/metrics.json",
    )
    parser.add_argument(
        "--out-prefix",
        type=Path,
        default=None,
        help="Output path prefix (default: <results-dir>/plots/baselines)",
    )
    args = parser.parse_args()

    results_dir = args.results_dir.resolve()
    if not results_dir.is_dir():
        raise SystemExit(f"Not a directory: {results_dir}")

    rows = collect_policies(results_dir)
    if not rows:
        raise SystemExit(f"No valid metrics under {results_dir}")

    policies = [name for name, _ in rows]

    tp_means: list[list[float]] = []
    tp_stds: list[list[float]] = []
    p99_means: list[list[float]] = []
    p99_stds: list[list[float]] = []

    for _, data in rows:
        priv = data["private"]
        tpm, tps, pm, ps = [], [], [], []
        for key in TRACE_KEYS:
            block = priv[key]
            tpm.append(float(block["throughput_mean"]))
            tps.append(float(block["throughput_std"]))
            pm.append(float(block["read_p99_ns_mean"]))
            ps.append(p99_std_from_runs(block))
        tp_means.append(tpm)
        tp_stds.append(tps)
        p99_means.append(pm)
        p99_stds.append(ps)

    out_prefix = args.out_prefix
    if out_prefix is None:
        out_dir = results_dir / "plots"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_prefix = out_dir / "baselines"

    out_prefix.parent.mkdir(parents=True, exist_ok=True)

    plot_figure(
        policies,
        tp_means,
        tp_stds,
        y_label="Throughput (mean; error bar = stdev over runs)",
        title="Caching policies: throughput by trace",
        out_path=out_prefix.with_name(out_prefix.name + "_throughput.png"),
    )

    plot_figure(
        policies,
        p99_means,
        p99_stds,
        y_label="Read p99 latency (mean ns; error bar = stdev over runs)",
        title="Caching policies: read p99 latency by trace",
        out_path=out_prefix.with_name(out_prefix.name + "_p99_latency.png"),
    )


if __name__ == "__main__":
    main()
