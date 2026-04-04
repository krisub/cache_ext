#!/usr/bin/env python3
"""
Plot throughput over time (1 Hz, post-warmup) from evaluate.py metrics.json.

Uses public_metrics keys:
  {trace}_throughput_series_mean
  {trace}_{client}_throughput_series_mean   (dual-client)

Example:
  python3 plot_throughput_timeseries.py --metrics baseline_results/policy_baselines/evolved/metrics.json --out-dir baseline_results/policy_baselines/evolved/plots_timeseries
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def load_metrics(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def discover_traces(pub: dict) -> list[str]:
    """Trace names from keys like ycsb_*_throughput_series_mean (not per-client)."""
    traces: set[str] = set()
    for k in pub:
        if not k.endswith("_throughput_series_mean"):
            continue
        if "_client_" in k:
            continue
        trace = k[: -len("_throughput_series_mean")]
        if trace:
            traces.add(trace)
    return sorted(traces)


def client_series_keys(pub: dict, trace: str) -> list[tuple[str, str]]:
    """Return [(suffix_label, full_key), ...] for client series for this trace."""
    prefix = f"{trace}_client_"
    out: list[tuple[str, str]] = []
    for k in pub:
        if not k.endswith("_throughput_series_mean"):
            continue
        if not k.startswith(prefix):
            continue
        mid = k[len(prefix) : -len("_throughput_series_mean")]
        if mid:
            out.append((mid, k))
    return sorted(out, key=lambda x: x[0])


def trim_series(seq: list, drop_first: int) -> list[float]:
    if drop_first <= 0:
        return [float(x) for x in seq]
    return [float(x) for x in seq[drop_first:]]


def plot_one_trace(
    trace: str,
    pub: dict,
    seconds_offset: int,
    drop_first: int,
    out_path: Path,
) -> None:
    import matplotlib.pyplot as plt

    combined_key = f"{trace}_throughput_series_mean"
    series = pub.get(combined_key)
    if not series:
        return

    series = trim_series(series, drop_first)
    if not series:
        return

    t = [seconds_offset + i for i in range(len(series))]

    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(t, series, label="combined (total)", color="#0f172a", linewidth=1.4)

    combined_len = len(series)
    for label, key in client_series_keys(pub, trace):
        cs = pub.get(key)
        if not cs:
            continue
        cs = trim_series(cs, drop_first)
        if len(cs) != combined_len:
            continue
        ax.plot(t, cs, label=label, alpha=0.85, linewidth=1.1)

    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Throughput (ops/s)")
    ax.set_title(f"{trace}: throughput over time (mean across runs)")
    ax.legend(loc="upper right", fontsize=8)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"Wrote {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Plot per-trace throughput time series from metrics.json"
    )
    parser.add_argument(
        "--metrics",
        type=Path,
        required=True,
        help="Path to metrics.json (combined_score + public + private)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory (default: <metrics_dir>/plots_timeseries)",
    )
    parser.add_argument(
        "--second-offset",
        type=int,
        default=1,
        help="X-axis starts at this second (first plotted point is this second)",
    )
    parser.add_argument(
        "--drop-first",
        type=int,
        default=1,
        help="Drop first N per-epoch samples (My-YCSB epoch 0 is a short-window artifact); 0 keeps all",
    )
    args = parser.parse_args()

    metrics_path = args.metrics.resolve()
    data = load_metrics(metrics_path)
    pub = data.get("public") or {}
    if "error" in pub and pub.get("error"):
        raise SystemExit(f"metrics has error: {pub.get('error')!r}")

    traces = discover_traces(pub)
    if not traces:
        raise SystemExit(
            "No *_throughput_series_mean keys in public. "
            "Re-run evaluate with throughput series export enabled."
        )

    out_dir = args.out_dir
    if out_dir is None:
        out_dir = metrics_path.parent / "plots_timeseries"
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    stem = metrics_path.parent.name
    safe_stem = re.sub(r"[^\w.\-]+", "_", stem)

    for trace in traces:
        out_png = out_dir / f"{safe_stem}_{trace}_throughput_time.png"
        plot_one_trace(trace, pub, args.second_offset, args.drop_first, out_png)

    # Optional overview: all traces in one figure
    try:
        import matplotlib.pyplot as plt

        n = len(traces)
        fig, axes = plt.subplots(n, 1, figsize=(10, 2.8 * n), sharex=False)
        if n == 1:
            axes = [axes]
        for ax, trace in zip(axes, traces):
            combined_key = f"{trace}_throughput_series_mean"
            raw = pub.get(combined_key) or []
            series = trim_series(raw, args.drop_first)
            if not series:
                continue
            t = [args.second_offset + i for i in range(len(series))]
            ax.plot(t, series, color="#1d4ed8", linewidth=1.2)
            ax.set_ylabel("ops/s")
            ax.set_title(trace)
            ax.grid(True, alpha=0.3)
        axes[-1].set_xlabel("Time (s)")
        fig.suptitle(f"{stem}: combined throughput over time", fontsize=11)
        fig.tight_layout()
        overview = out_dir / f"{safe_stem}_all_traces_throughput.png"
        fig.savefig(overview, dpi=150)
        plt.close(fig)
        print(f"Wrote {overview}")
    except Exception as e:
        print(f"Overview plot skipped: {e}")


if __name__ == "__main__":
    main()
