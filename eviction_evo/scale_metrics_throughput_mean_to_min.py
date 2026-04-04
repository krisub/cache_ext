#!/usr/bin/env python3
"""
Scale all throughput-related numbers in a Shinka evaluate.py metrics.json so that
for each trace, new_throughput_mean == old_throughput_min (per-trace scale s = min/mean).

Leaves read p99 / latency metrics unchanged; recomputes combined_score harmonic means and
per-trace latency_adjusted_score from new throughput + existing p99.

Usage:
  python3 scale_metrics_throughput_mean_to_min.py metrics.json
  python3 scale_metrics_throughput_mean_to_min.py metrics.json --dry-run
  python3 scale_metrics_throughput_mean_to_min.py metrics.json -o out.json
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any


def latency_adjusted_trace_score(
    tp_mean: float, p99_ns_mean: float, lat_ref_ms: float
) -> float:
    if tp_mean <= 0:
        return 0.0
    if p99_ns_mean <= 0 or lat_ref_ms <= 0:
        return tp_mean
    p99_ms = p99_ns_mean / 1e6
    return tp_mean / (1.0 + (p99_ms / lat_ref_ms))


def harmonic_mean_throughput_like(mean_throughputs: list[float]) -> float:
    """Match evaluate.py Step 7 harmonic mean of per-trace means."""
    nonzero_tps = [t for t in mean_throughputs if t > 0]
    if len(nonzero_tps) == len(mean_throughputs) and len(mean_throughputs) > 0:
        return len(mean_throughputs) / sum(1.0 / t for t in mean_throughputs)
    if len(nonzero_tps) > 0:
        hm_partial = len(nonzero_tps) / sum(1.0 / t for t in nonzero_tps)
        return hm_partial * (len(nonzero_tps) / len(mean_throughputs))
    return 0.0


def scale_float_list(xs: list, s: float) -> list:
    return [round(float(v) * s, 6) if isinstance(v, (int, float)) else v for v in xs]


def scale_run_dict(run: dict, s: float) -> None:
    if "total_throughput" in run:
        run["total_throughput"] = round(float(run["total_throughput"]) * s, 6)
    if "throughput_series_total_ops_per_sec" in run:
        run["throughput_series_total_ops_per_sec"] = scale_float_list(
            run["throughput_series_total_ops_per_sec"], s
        )
    pcs = run.get("per_client_throughput_series_total_ops_per_sec")
    if isinstance(pcs, dict):
        for ck, ser in list(pcs.items()):
            if isinstance(ser, list):
                pcs[ck] = scale_float_list(ser, s)


def scale_trace_private(block: dict, s: float, lat_ref_ms: float) -> None:
    m = float(block["throughput_mean"])
    block["throughput_mean"] = round(m * s, 6)
    block["throughput_std"] = round(float(block["throughput_std"]) * s, 6)
    block["throughput_min"] = round(float(block["throughput_min"]) * s, 6)
    block["throughput_max"] = round(float(block["throughput_max"]) * s, 6)
    if "throughput_cv" in block:
        new_m = float(block["throughput_mean"])
        if new_m > 0:
            block["throughput_cv"] = float(block["throughput_std"]) / new_m * 100.0
        else:
            block["throughput_cv"] = 0.0

    sm = block.get("throughput_series_total_ops_per_sec_mean")
    if isinstance(sm, list):
        block["throughput_series_total_ops_per_sec_mean"] = scale_float_list(sm, s)
    pcm = block.get("per_client_throughput_series_total_ops_per_sec_mean")
    if isinstance(pcm, dict):
        for k, ser in list(pcm.items()):
            if isinstance(ser, list):
                pcm[k] = scale_float_list(ser, s)

    p99 = float(block.get("read_p99_ns_mean", 0.0))
    block["latency_adjusted_score"] = latency_adjusted_trace_score(
        float(block["throughput_mean"]), p99, lat_ref_ms
    )

    for run in block.get("runs") or []:
        if isinstance(run, dict):
            scale_run_dict(run, s)


def scale_public_for_trace(pub: dict, trace: str, s: float) -> None:
    for suffix in (
        "_throughput_mean",
        "_throughput_std",
        "_throughput_min",
        "_throughput_max",
    ):
        k = f"{trace}{suffix}"
        if k in pub:
            pub[k] = round(float(pub[k]) * s, 6)

    k_series = f"{trace}_throughput_series_mean"
    if k_series in pub and isinstance(pub[k_series], list):
        pub[k_series] = scale_float_list(pub[k_series], s)

    k_pr = f"{trace}_per_run_throughput"
    if k_pr in pub and isinstance(pub[k_pr], list):
        pub[k_pr] = scale_float_list(pub[k_pr], s)

    prefix = f"{trace}_client_"
    for k in list(pub.keys()):
        if k.startswith(prefix) and k.endswith("_throughput_series_mean"):
            if isinstance(pub[k], list):
                pub[k] = scale_float_list(pub[k], s)


def transform_metrics(data: dict) -> dict:
    out = copy.deepcopy(data)
    priv = out.get("private") or {}
    pub = out.get("public") or {}

    lat_ref_ms = float(pub.get("lat_ref_ms", 400.0))

    trace_names = sorted(
        k
        for k, v in priv.items()
        if isinstance(v, dict) and "throughput_mean" in v and "throughput_min" in v
    )

    for trace in trace_names:
        block = priv[trace]
        mean = float(block["throughput_mean"])
        min_v = float(block["throughput_min"])
        if mean <= 0:
            continue
        if min_v == 0.0:
            # Failed run recorded as 0 — use lowest non-zero run throughput instead
            run_tps = [
                float(r["total_throughput"])
                for r in (block.get("runs") or [])
                if isinstance(r, dict) and float(r.get("total_throughput", 0)) > 0
            ]
            if run_tps:
                min_v = min(run_tps)
                print(
                    f"info: {trace} has throughput_min=0 (failed run); "
                    f"using lowest non-zero run throughput {min_v} instead.",
                    file=sys.stderr,
                )
            else:
                print(
                    f"warning: {trace} has throughput_min=0 and no non-zero runs; skipping.",
                    file=sys.stderr,
                )
                continue
        s = min_v / mean
        scale_public_for_trace(pub, trace, s)
        scale_trace_private(block, s, lat_ref_ms)

    # Recompute combined scores from new per-trace means
    new_means = [float(priv[t]["throughput_mean"]) for t in trace_names if priv[t].get("throughput_mean")]
    new_lat = [
        float(priv[t]["latency_adjusted_score"])
        for t in trace_names
        if priv[t].get("latency_adjusted_score") is not None
    ]

    if new_means:
        out["combined_score"] = harmonic_mean_throughput_like(new_means)
        pub["combined_score_harmonic_mean_throughput_only"] = out["combined_score"]
    if new_lat:
        pub["combined_score_harmonic_mean_latency_adjusted"] = harmonic_mean_throughput_like(
            new_lat
        )

    out["public"] = pub
    out["private"] = priv
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("metrics_json", type=Path)
    ap.add_argument("-o", "--output", type=Path, default=None)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    path = args.metrics_json.resolve()
    data = json.loads(path.read_text())
    new_data = transform_metrics(data)

    if args.dry_run:
        old = data["combined_score"]
        new = new_data["combined_score"]
        print(f"combined_score: {old} -> {new}")
        for t in sorted((data.get("private") or {}).keys()):
            if t not in (new_data.get("private") or {}):
                continue
            om = (data["private"][t]).get("throughput_mean")
            nm = (new_data["private"][t]).get("throughput_mean")
            omi = (data["private"][t]).get("throughput_min")
            print(f"  {t}: mean {om} -> {nm} (target old min {omi})")
        return

    out_path = args.output or path
    if args.output is None:
        bak = path.with_suffix(path.suffix + ".bak")
        bak.write_text(path.read_text())
        print(f"Backup: {bak}")

    out_path.write_text(json.dumps(new_data, indent=2))
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
