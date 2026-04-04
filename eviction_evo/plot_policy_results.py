#!/usr/bin/env python3
"""
Plot baseline policy comparison from baseline_results/policy_baselines/*/metrics.json.

- Throughput: grouped bars = by default mean of per-epoch throughput series with the first N
  seconds dropped (avoids My-YCSB monitor startup inflation); error bars stay stdev across runs.
  Use --drop-first-epoch 0 to use evaluate's throughput_mean instead.
- P99 latency: grouped bars = mean read p99 (ns); error bars = stdev of p99 across runs (per bar).

Usage:
  python3 plot_policy_results.py
  python3 plot_policy_results.py --results-dir baseline_results/policy_baselines
  python3 plot_policy_results.py --results-dir baseline_results/old_sched_1_2

  Policies can be flat (<name>/metrics.json) or nested (<name>/results/metrics.json).
"""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path


PREFERRED_TRACE_ORDERS = [
    # Current synthetic-step suite
    (
        "ycsb_a_d_sched_2_a",
        "ycsb_a_d_sched_2_a_flipped",
        "ycsb_a_d_sched_2_b",
        "ycsb_a_d_sched_2_c",
    ),
    # schedule_1 + schedule_2 dual-trace runs (older baselines)
    ("ycsb_a_d_sched_1", "ycsb_a_d_sched_2"),
    # Legacy suite
    ("ycsb_c_a", "ycsb_c_f", "ycsb_b_a", "ycsb_a_d"),
]


def find_metrics_json(policy_dir: Path) -> Path | None:
    """Shinka/evaluate usually writes <policy>/metrics.json; some trees use <policy>/results/metrics.json."""
    direct = policy_dir / "metrics.json"
    if direct.is_file():
        return direct
    nested = policy_dir / "results" / "metrics.json"
    if nested.is_file():
        return nested
    return None


def load_metrics(path: Path) -> dict | None:
    with open(path) as f:
        return json.load(f)


def p99_std_from_runs(private_trace: dict) -> float:
    runs = private_trace.get("runs") or []
    vals = [r["read_latency_p99_ns"] for r in runs if "read_latency_p99_ns" in r]
    if len(vals) < 2:
        return 0.0
    return statistics.stdev(vals)


def throughput_mean_for_bar(block: dict, drop_first_epoch: int) -> float:
    """
    Bar chart throughput: prefer mean of per-epoch series with first N seconds dropped
    (My-YCSB epoch 0 uses a too-short window and inflates ops/s). Fallback to evaluate's
    throughput_mean (mean of per-run totals).
    """
    s = block.get("throughput_series_total_ops_per_sec_mean")
    if (
        drop_first_epoch > 0
        and isinstance(s, list)
        and len(s) > drop_first_epoch
    ):
        return statistics.mean(float(x) for x in s[drop_first_epoch:])
    return float(block["throughput_mean"])


def choose_trace_keys(rows: list[tuple[str, dict]]) -> tuple[str, ...]:
    """Pick a trace-key set that exists in all policy metrics."""
    if not rows:
        return tuple()
    private_blocks = [data.get("private") or {} for _, data in rows]

    # Prefer known orders first for stable plots.
    for keys in PREFERRED_TRACE_ORDERS:
        if all(all(k in priv for k in keys) for priv in private_blocks):
            return keys

    # Fallback: intersection of trace keys across policies.
    common = set(private_blocks[0].keys())
    for priv in private_blocks[1:]:
        common &= set(priv.keys())
    # Keep deterministic ordering.
    return tuple(sorted(k for k in common if isinstance(k, str)))


def trace_label(key: str) -> str:
    if key.startswith("ycsb_"):
        return key.replace("ycsb_", "").upper()
    return key


def collect_policies(results_dir: Path) -> list[tuple[str, dict]]:
    rows: list[tuple[str, dict]] = []
    for sub in sorted(results_dir.iterdir()):
        if not sub.is_dir():
            continue
        mpath = find_metrics_json(sub)
        if not mpath:
            continue
        data = load_metrics(mpath)
        if not data:
            continue
        pub = data.get("public") or {}
        if "error" in pub and pub.get("error"):
            print(f"skip {pub.get('error')!r}: {mpath}")
            continue
        rows.append((sub.name, data))
    return rows


def plot_figure(
    policies: list[str],
    bar_means: list[list[float]],
    bar_stds: list[list[float]],
    trace_keys: tuple[str, ...],
    y_label: str,
    title: str,
    out_path: Path,
) -> None:
    import matplotlib.pyplot as plt
    import numpy as np

    n_pol = len(policies)
    n_trace = len(trace_keys)
    x = np.arange(n_pol)
    # Keep all trace bars within a single policy group width.
    group_width = 0.84
    width = group_width / max(n_trace, 1)
    # Ensure we always have one color per trace.
    cmap = plt.get_cmap("tab10")
    colors_bar = [cmap(i % cmap.N) for i in range(n_trace)]

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
            label=trace_label(trace_keys[j]),
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
    parser.add_argument(
        "--drop-first-epoch",
        type=int,
        default=1,
        help="When >0 and per-epoch series exists in private trace block, throughput bar uses "
        "mean(series[drop:]) instead of throughput_mean (avoids inflated first epoch). 0 = old behavior.",
    )
    args = parser.parse_args()

    results_dir = args.results_dir.resolve()
    if not results_dir.is_dir():
        raise SystemExit(f"Not a directory: {results_dir}")

    rows = collect_policies(results_dir)
    if not rows:
        raise SystemExit(f"No valid metrics under {results_dir}")

    trace_keys = choose_trace_keys(rows)
    if not trace_keys:
        raise SystemExit("No common trace keys found across policy metrics.")

    policies = [name for name, _ in rows]

    tp_means: list[list[float]] = []
    tp_stds: list[list[float]] = []
    p99_means: list[list[float]] = []
    p99_stds: list[list[float]] = []

    for _, data in rows:
        priv = data["private"]
        tpm, tps, pm, ps = [], [], [], []
        for key in trace_keys:
            block = priv[key]
            tpm.append(
                throughput_mean_for_bar(block, args.drop_first_epoch)
            )
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
        trace_keys,
        y_label="Throughput (mean; error bar = stdev over runs)",
        title="Caching policies: throughput by trace"
        + (
            f" (epoch mean, drop first {args.drop_first_epoch})"
            if args.drop_first_epoch > 0
            else ""
        ),
        out_path=out_prefix.with_name(out_prefix.name + "_throughput.png"),
    )

    plot_figure(
        policies,
        p99_means,
        p99_stds,
        trace_keys,
        y_label="Read p99 latency (mean ns; error bar = stdev over runs)",
        title="Caching policies: read p99 latency by trace",
        out_path=out_prefix.with_name(out_prefix.name + "_p99_latency.png"),
    )


if __name__ == "__main__":
    main()
