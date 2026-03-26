#!/usr/bin/env python3
"""run_dual_trace.py - Run any trace config (single or dual-client).

Used by bash scripts (run_baseline.sh, test_best.sh) to handle dual-client
traces transparently. Assumes the server is ALREADY running on port 9100.

Usage:
    python3 run_dual_trace.py <trace_config.yaml>

Output (parseable, one metric per line):
    total_throughput 123.45
    read_p99_ns 456789.0
    client_name_throughput 80.00
    ...

For single-client traces, runs run_net_leveldb directly.
For dual-client traces, starts proxies, runs clients in parallel, combines results.
"""

import os
import re
import shlex
import subprocess
import sys
import tempfile
import time

CACHE_EXT_DIR = "/mydata/cache_ext"
BENCH_BINARY = os.path.join(CACHE_EXT_DIR, "My-YCSB", "build", "run_net_leveldb")
PROXY_SCRIPT = os.path.join(CACHE_EXT_DIR, "eviction_evo", "tcp_delay_proxy.py")
SERVER_PORT = 9100
SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
           "-i", "/users/krisub/.ssh/id_ed25519"]
REMOTE_CLIENT_CGROUP = "cache_ext_remote_clients"


def parse_benchmark_output(stdout):
    """Parse My-YCSB output into results dict."""
    results = {}
    for line in stdout.splitlines():
        line = line.strip()
        if "Warm-Up" in line:
            continue
        if "overall:" in line:
            for match in re.finditer(r"(\w+) throughput ([\d.]+) ops/sec", line):
                label, value = match.group(1), float(match.group(2))
                if label == "total":
                    results["total_throughput"] = value
                else:
                    results[f"{label.lower()}_throughput"] = value
            for match in re.finditer(r"(\w+) (average|p99) latency ([\d.]+) ns", line):
                op, kind, value = match.group(1), match.group(2), float(match.group(3))
                results[f"{op.lower()}_{kind}_ns"] = value
    return results


def wait_for_port(port, timeout=30):
    import socket
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=1)
            s.close()
            return True
        except OSError:
            time.sleep(0.5)
    return False


def run_single(config_path):
    """Run a single-client benchmark. Returns (results_dict, raw_stdout)."""
    import yaml as pyyaml
    with open(config_path) as f:
        config = pyyaml.safe_load(f)
    warmup = config.get("workload", {}).get("warmup_runtime_seconds", 30)
    runtime = config.get("workload", {}).get("runtime_seconds", 120)

    result = subprocess.run(
        [BENCH_BINARY, config_path],
        capture_output=True, text=True,
        timeout=warmup + runtime + 120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Benchmark failed (rc={result.returncode}): {result.stderr[:500]}")
    return parse_benchmark_output(result.stdout), result.stdout


def scp_to_remote(local_path, remote_host, remote_path, timeout=30):
    """Copy a file to a remote host via scp."""
    subprocess.run(
        ["scp"] + SSH_OPTS + [local_path, f"{remote_host}:{remote_path}"],
        check=True, timeout=timeout, capture_output=True, text=True,
    )


def ssh_rm(remote_host, remote_path):
    """Remove a file on a remote host."""
    subprocess.run(
        ["ssh"] + SSH_OPTS + [remote_host, "rm", "-f", remote_path],
        check=False, timeout=10, capture_output=True,
    )


def ssh_shell_cmd(remote_host, shell_command):
    """Build ssh argv that runs a command through remote sh -lc."""
    return ["ssh"] + SSH_OPTS + [remote_host, f"sh -lc {shlex.quote(shell_command)}"]


def ensure_remote_client_cgroup(remote_host):
    """Best-effort create shared remote cgroup for benchmark client processes."""
    setup_cmd = (
        f"sudo -n cgcreate -g memory:{REMOTE_CLIENT_CGROUP} >/dev/null 2>&1 || true"
    )
    subprocess.run(
        ssh_shell_cmd(remote_host, setup_cmd),
        check=False, timeout=15, capture_output=True, text=True,
    )


def remote_bench_command(remote_path):
    """Run benchmark in shared remote cgroup when available."""
    return (
        f"if command -v cgexec >/dev/null 2>&1; then "
        f"cgexec -g memory:{REMOTE_CLIENT_CGROUP} "
        f"{BENCH_BINARY} {remote_path} && exit 0; "
        f"fi; "
        f"exec {BENCH_BINARY} {remote_path}"
    )


def run_dual(trace_config):
    """Run a dual-client benchmark. Returns (combined_results, raw_output).

    Clients with a 'host' field are launched on that host via SSH.
    Clients without 'host' (or with proxy settings) run locally as before.
    """
    import yaml as pyyaml

    clients = trace_config["clients"]
    proxy_procs = []
    # Each entry: (local_path, remote_host_or_None, remote_path_or_None)
    temp_files = []

    try:
        # Start proxies for local clients that need them
        for client in clients:
            if client.get("host"):
                continue
            proxy_port = client.get("proxy_port", 0)
            delay_ms = client.get("proxy_delay_ms", 0)
            bw_kbps = client.get("proxy_bandwidth_kbps", 0)

            if proxy_port > 0 and (delay_ms > 0 or bw_kbps > 0):
                cmd = [
                    sys.executable, PROXY_SCRIPT,
                    "--listen-port", str(proxy_port),
                    "--target-port", str(SERVER_PORT),
                    "--delay-ms", str(delay_ms),
                    "--bandwidth-kbps", str(bw_kbps),
                ]
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True)
                proxy_procs.append(proc)
                if not wait_for_port(proxy_port, timeout=10):
                    raise RuntimeError(f"Proxy on port {proxy_port} failed to start")

        # Ensure a shared client cgroup exists on each remote host.
        for host in {c.get("host") for c in clients if c.get("host")}:
            ensure_remote_client_cgroup(host)

        # Write temp configs and start clients
        client_procs = []
        for client in clients:
            config = client["config"]
            remote_host = client.get("host")

            fd, local_path = tempfile.mkstemp(suffix=".yaml",
                                              prefix=f"dual_{client['name']}_")
            with os.fdopen(fd, 'w') as f:
                pyyaml.dump(config, f)

            if remote_host:
                remote_path = f"/tmp/{os.path.basename(local_path)}"
                scp_to_remote(local_path, remote_host, remote_path)
                temp_files.append((local_path, remote_host, remote_path))

                remote_cmd = remote_bench_command(remote_path)
                proc = subprocess.Popen(
                    ssh_shell_cmd(remote_host, remote_cmd),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
            else:
                temp_files.append((local_path, None, None))
                proc = subprocess.Popen(
                    [BENCH_BINARY, local_path],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )

            client_procs.append((client["name"], proc))

        # Wait for all clients
        max_timeout = max(
            c["config"]["workload"].get("warmup_runtime_seconds", 30) +
            c["config"]["workload"].get("runtime_seconds", 120)
            for c in clients
        ) + 120

        results_per_client = {}
        raw_outputs = []
        for name, proc in client_procs:
            try:
                stdout, stderr = proc.communicate(timeout=max_timeout)
                if proc.returncode != 0:
                    results_per_client[name] = {"total_throughput": 0.0}
                    raw_outputs.append(f"--- {name} ERROR ---\n{stderr[:500]}")
                else:
                    results_per_client[name] = parse_benchmark_output(stdout)
                    raw_outputs.append(f"--- {name} ---\n{stdout}")
            except subprocess.TimeoutExpired:
                proc.kill()
                results_per_client[name] = {"total_throughput": 0.0}
                raw_outputs.append(f"--- {name} TIMEOUT ---")

        # Combine: sum throughputs
        total_tp = sum(r.get("total_throughput", 0.0)
                       for r in results_per_client.values())
        combined = {
            "total_throughput": total_tp,
            "per_client": results_per_client,
        }
        # Aggregate p99: max across clients
        p99s = [r.get("read_p99_ns", 0) for r in results_per_client.values()
                if "read_p99_ns" in r]
        if p99s:
            combined["read_latency_p99_ns"] = max(p99s)

        return combined, "\n".join(raw_outputs)

    finally:
        for proc in proxy_procs:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except Exception:
                pass
        for local_path, remote_host, remote_path in temp_files:
            try:
                os.unlink(local_path)
            except Exception:
                pass
            if remote_host and remote_path:
                try:
                    ssh_rm(remote_host, remote_path)
                except Exception:
                    pass


def run_trace(config_path):
    """Run any trace (single or dual-client). Returns (results_dict, raw_stdout)."""
    import yaml as pyyaml
    with open(config_path) as f:
        trace_config = pyyaml.safe_load(f)

    if trace_config.get("type") == "dual_client":
        return run_dual(trace_config)
    else:
        return run_single(config_path)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <trace_config.yaml>", file=sys.stderr)
        sys.exit(1)

    config_path = sys.argv[1]
    try:
        results, raw_output = run_trace(config_path)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        print("total_throughput 0")
        sys.exit(1)

    # Output in parseable format
    tp = results.get("total_throughput", 0.0)
    print(f"total_throughput {tp}")
    if "read_latency_p99_ns" in results:
        print(f"read_p99_ns {results['read_latency_p99_ns']}")
    if "per_client" in results:
        for name, r in results["per_client"].items():
            print(f"{name}_throughput {r.get('total_throughput', 0.0)}")
    # Also write raw output to stderr for tee/logging
    print(raw_output, file=sys.stderr)


if __name__ == "__main__":
    main()
