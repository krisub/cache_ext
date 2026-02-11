#!/usr/bin/env python3
import csv
import statistics

def load_csv(path: str):
    rows = []
    with open(path, newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            if not row.get("Time_Sec"):
                continue
            # numeric fields
            for k in ["Time_Sec", "Throughput_MBps", "OpsPerSec", "LatencyAvg_ms", "LatencyP99_ms"]:
                row[k] = float(row[k])
            rows.append(row)
    return rows

def mean(xs):
    return statistics.mean(xs) if xs else float("nan")

def summarize(rows):
    mb = [x["Throughput_MBps"] for x in rows]
    lavg = [x["LatencyAvg_ms"] for x in rows]
    return mean(mb), mean(lavg)

def after_switch_rows(rows, take=2):
    idxs = []
    for i in range(1, len(rows)):
        if rows[i]["Active_DB"] != rows[i - 1]["Active_DB"]:
            idxs.append(i)
    out = []
    for i in idxs:
        out.extend(rows[i : min(i + take, len(rows))])
    return out

def main(mglru_csv: str, net_csv: str):
    mglru = load_csv(mglru_csv)
    net = load_csv(net_csv)

    m_mb, m_lavg = summarize(mglru)
    n_mb, n_lavg = summarize(net)

    m_sw = after_switch_rows(mglru, take=2)
    n_sw = after_switch_rows(net, take=2)
    m_sw_mb, m_sw_lavg = summarize(m_sw)
    n_sw_mb, n_sw_lavg = summarize(n_sw)

    print("Key results (NET vs MGLRU)")
    print(f"From the full runs ({len(mglru)} windows each):")
    print("Throughput (mean):")
    print(f"  MGLRU: {m_mb:.1f} MB/s")
    print(f"  NET:   {n_mb:.1f} MB/s (higher)")
    print("Avg latency (mean):")
    print(f"  MGLRU: {m_lavg:.2f} ms")
    print(f"  NET:   {n_lavg:.2f} ms (lower)")
    print(f"After-switch behavior (first 2 windows after each A↔B switch; {len(m_sw)} windows total):")
    print(f"  MGLRU: {m_sw_mb:.1f} MB/s, {m_sw_lavg:.2f} ms")
    print(f"  NET:   {n_sw_mb:.1f} MB/s, {n_sw_lavg:.2f} ms")

if __name__ == "__main__":
    # Example:
    # python3 stats.py cache_ext/data/mglru_HALFGB_reaccess.csv cache_ext/data/net_HALFGB_reaccess.csv
    import sys
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} <mglru.csv> <net.csv>")
    main(sys.argv[1], sys.argv[2])