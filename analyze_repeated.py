#!/usr/bin/env python3
"""
Analyze reproducibility of repeated benchmark runs.
Computes mean, std, and optionally plots time series with running average.

Usage:
  # Reproducibility stats for one policy (5 MGLRU runs):
  python3 analyze_repeated.py data/mglru_1.csv data/mglru_2.csv data/mglru_3.csv data/mglru_4.csv data/mglru_5.csv
  python3 analyze_repeated.py data/net_1.csv data/net_2.csv data/net_3.csv data/net_4.csv data/net_5.csv

  # Compare two policies with time series + running avg:
  python3 analyze_repeated.py --mglru 'data/mglru_*.csv' --net 'data/net_*.csv' --plot
"""
import argparse
import csv
import glob
import statistics
from pathlib import Path


def load_csv(path: str) -> list[dict]:
    rows = []
    with open(path, newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            if not row.get("Time_Sec"):
                continue
            for k in ["Time_Sec", "Throughput_MBps", "OpsPerSec", "LatencyAvg_ms", "LatencyP99_ms"]:
                try:
                    row[k] = float(row[k])
                except (ValueError, KeyError):
                    pass
            rows.append(row)
    return rows


def running_avg(xs, window: int = 10) -> list[float]:
    """Exponential smoothing / running average."""
    out = []
    alpha = 2.0 / (window + 1)
    ema = xs[0] if xs else 0
    for x in xs:
        ema = alpha * x + (1 - alpha) * ema
        out.append(ema)
    return out


def main():
    parser = argparse.ArgumentParser(
        description="Analyze reproducibility and plot time series with running avg"
    )
    parser.add_argument("files", nargs="*", help="CSV files to analyze (one policy)")
    parser.add_argument(
        "--mglru", metavar="GLOB",
        help="Glob for MGLRU run CSVs (e.g. data/mglru_*.csv)",
    )
    parser.add_argument(
        "--net", metavar="GLOB",
        help="Glob for network heuristic run CSVs (e.g. data/net_heuristic_*.csv)",
    )
    parser.add_argument(
        "--plot", action="store_true",
        help="Generate time series plot with running avg (requires matplotlib)",
    )
    parser.add_argument(
        "--output", "-o", default="data/reproducibility_plot.png",
        help="Output plot path",
    )
    parser.add_argument(
        "--window", type=int, default=10,
        help="Running average window for smoothing (default: 10)",
    )
    args = parser.parse_args()

    def expand_globs(pat: str) -> list[str]:
        return sorted(glob.glob(pat))

    # Single-policy reproducibility mode
    if args.files and not args.mglru and not args.net:
        files = args.files
        all_runs = []
        for f in files:
            rows = load_csv(f)
            mb = [r["Throughput_MBps"] for r in rows if "Throughput_MBps" in r]
            avg = statistics.mean(mb) if mb else float("nan")
            all_runs.append((Path(f).name, avg, mb))
        avgs = [a for _, a, _ in all_runs if not (a != a)]
        print("=== Reproducibility ===")
        for name, avg, _ in all_runs:
            print(f"  {name}: avg throughput {avg:.1f} MB/s")
        if len(avgs) >= 2:
            print(f"  Mean across runs: {statistics.mean(avgs):.1f} MB/s")
            print(f"  Std dev:          {statistics.stdev(avgs):.1f} MB/s")
            print(f"  CoV:              {100 * statistics.stdev(avgs) / statistics.mean(avgs):.1f}%")
        return

    # Two-policy comparison mode
    if not args.mglru or not args.net:
        parser.error("For comparison, provide both --mglru and --net globs (or pass files for single-policy)")

    mglru_files = expand_globs(args.mglru)
    net_files = expand_globs(args.net)
    if not mglru_files or not net_files:
        raise SystemExit("No files matched. Check your globs.")

    mglru_runs = [load_csv(f) for f in mglru_files]
    net_runs = [load_csv(f) for f in net_files]

    # Per-policy reproducibility
    def policy_stats(runs: list, label: str):
        avgs = []
        for rows in runs:
            mb = [r["Throughput_MBps"] for r in rows if "Throughput_MBps" in r]
            avgs.append(statistics.mean(mb) if mb else 0)
        print(f"\n{label}:")
        print(f"  Mean throughput: {statistics.mean(avgs):.1f} MB/s")
        if len(avgs) >= 2:
            print(f"  Std dev:         {statistics.stdev(avgs):.1f} MB/s")
            print(f"  CoV:             {100 * statistics.stdev(avgs) / statistics.mean(avgs):.1f}%")
        return runs, avgs

    print("=== Reproducibility ===")
    mglru_runs, mglru_avgs = policy_stats(mglru_runs, "MGLRU")
    net_runs, net_avgs = policy_stats(net_runs, "Network heuristic")

    if not args.plot:
        return

    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed; skipping plot. Install with: pip install matplotlib numpy")
        return

    fig, axes = plt.subplots(2, 1, figsize=(12, 8), sharex=True)

    def plot_runs(runs, color, label, ax_raw, ax_smooth):
        for i, rows in enumerate(runs):
            t = [r["Time_Sec"] for r in rows]
            mb = [r["Throughput_MBps"] for r in rows]
            alpha = 0.4 if len(runs) > 1 else 0.8
            ax_raw.plot(t, mb, color=color, alpha=alpha, label=label if i == 0 else None)
        # Align by row index (all runs have same 0.5s interval structure)
        n = min(len(r) for r in runs)
        t0 = [r["Time_Sec"] for r in runs[0]][:n]
        mb_mean = [
            statistics.mean(r["Throughput_MBps"] for r in [rows[i] for rows in runs])
            for i in range(n)
        ]
        ra = running_avg(mb_mean, args.window)
        ax_smooth.plot(t0, mb_mean, color=color, alpha=0.6, linestyle="--", label=f"{label} (mean)")
        ax_smooth.plot(t0, ra, color=color, linewidth=2, label=f"{label} (running avg)")

    ax_raw, ax_smooth = axes[0], axes[1]
    ax_raw.set_ylabel("Throughput (MB/s)")
    ax_raw.set_title("Per-run throughput over time (all repeated runs)")
    ax_smooth.set_ylabel("Throughput (MB/s)")
    ax_smooth.set_xlabel("Time (s)")
    ax_smooth.set_title(f"Across-run mean and smoothed trend (EMA window={args.window})")

    plot_runs(mglru_runs, "C0", "MGLRU", ax_raw, ax_smooth)
    plot_runs(net_runs, "C1", "Network heuristic", ax_raw, ax_smooth)

    # Build legends after plotting so handles exist.
    ax_raw.legend(
        title="Policy",
        loc="upper right",
    )
    ax_smooth.legend(
        title="Line type",
        loc="upper right",
    )

    fig.suptitle(
        "Reproducibility Comparison: MGLRU vs Network Heuristic",
        fontsize=14,
    )

    plt.tight_layout(rect=[0, 0, 1, 0.97])
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(args.output, dpi=150)
    print(f"\nPlot saved to {args.output}")

if __name__ == "__main__":
    main()
