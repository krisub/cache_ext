"""
bench_net_leveldb.py — Benchmarking framework for networked LevelDB.

This runs:
  1. net_leveldb_server (LevelDB TCP server, block_cache=NULL) running inside
     a memory cgroup → all reads go through the OS page cache
  2. run_net_leveldb (My-YCSB client) sending workload over TCP from outside
     the cgroup
  3. optionally, cache_ext eBPF policy attached to the server's cgroup

Architecture:
  [run_net_leveldb client] --TCP--> [net_leveldb_server in cgroup] --page cache--> [disk]

Why this works for testing page cache policies:
  - Redis stores data in app memory (heap), NOT the page cache → useless
  - LevelDB with block_cache=NULL stores nothing in app memory; every read goes
    through the OS page cache (file-backed pages)
  - The server runs in a memory cgroup → page cache for its .ldb files is constrained
  - cache_ext eBPF policies manage eviction within that cgroup
  - The client runs outside the cgroup, generating YCSB workload over TCP

Usage:
  python bench_net_leveldb.py \\
    --leveldb-db /mydata/leveldb_db \\
    --bench-binary-dir /mydata/cache_ext/My-YCSB/build \\
    --server-binary /mydata/cache_ext/net_leveldb_server \\
    --policy-loader /mydata/cache_ext/policies/build/cache_ext_lru.out \\
    --benchmark ycsb_c \\
    --cgroup-size-gib 10 \\
    --server-port 9100
"""

import argparse
import logging
import os
import re
import signal
import subprocess
from time import sleep
from typing import Dict, List

from bench_lib import *

log = logging.getLogger(__name__)
GiB = 2**30
CLEANUP_TASKS = []

# Default port for net_leveldb_server
DEFAULT_SERVER_PORT = 9100


def reset_database(db_dir: str, temp_db_dir: str):
    if not db_dir.endswith("/"):
        db_dir += "/"
    run(["rsync", "-avpl", "--delete", db_dir, temp_db_dir])


def parse_net_leveldb_bench_results(stdout: str) -> Dict:
    """Parse My-YCSB output format (same as LevelDB bench results)."""
    results = {}
    for line in stdout.splitlines():
        line = line.strip()
        if "Warm-Up" in line:
            continue
        elif "overall: UPDATE throughput" in line:
            pattern = r"(\w+ throughput) (\d+\.\d+) ops/sec"
            matches = re.findall(pattern, line)
            assert len(matches) == 6, "Unexpected line pattern: %s" % line
            assert "total throughput" in matches[-1][0]
            for match in matches:
                if "READ throughput" in match[0]:
                    results["read_throughput_avg"] = float(match[1])
                elif "INSERT throughput" in match[0]:
                    results["insert_throughput_avg"] = float(match[1])
                elif "UPDATE throughput" in match[0]:
                    results["update_throughput_avg"] = float(match[1])
                elif "SCAN throughput" in match[0]:
                    results["scan_throughput_avg"] = float(match[1])
                elif "READ_MODIFY_WRITE throughput" in match[0]:
                    results["read_modify_write_throughput_avg"] = float(match[1])
                elif "total throughput" in match[0]:
                    results["throughput_avg"] = float(match[1])
                else:
                    raise Exception("Unknown throughput type: " + match[0])
            results["throughput_avg"] = float(matches[-1][1])
        elif "overall: UPDATE average latency" in line:
            pattern = r"(\w+ \w+ latency) (\d+\.\d+) ns"
            matches = re.findall(pattern, line)
            for match in matches:
                if "READ average latency" in match[0]:
                    results["read_latency_avg"] = float(match[1])
                    results["latency_avg"] = float(match[1])
                elif "INSERT average latency" in match[0]:
                    results["insert_latency_avg"] = float(match[1])
                elif "UPDATE average latency" in match[0]:
                    results["update_latency_avg"] = float(match[1])
                elif "SCAN average latency" in match[0]:
                    results["scan_latency_avg"] = float(match[1])
                elif "READ_MODIFY_WRITE average latency" in match[0]:
                    results["read_modify_write_latency_avg"] = float(match[1])
                elif "READ p99 latency" in match[0]:
                    results["read_latency_p99"] = float(match[1])
                    results["latency_p99"] = float(match[1])
                elif "INSERT p99 latency" in match[0]:
                    results["insert_latency_p99"] = float(match[1])
                elif "UPDATE p99 latency" in match[0]:
                    results["update_latency_p99"] = float(match[1])
                elif "SCAN p99 latency" in match[0]:
                    results["scan_latency_p99"] = float(match[1])
                elif "READ_MODIFY_WRITE p99 latency" in match[0]:
                    results["read_modify_write_latency_p99"] = float(match[1])
                else:
                    raise Exception("Unknown latency metric: " + match[0])
    if not all(
        key in results for key in ["throughput_avg", "latency_avg", "latency_p99"]
    ):
        raise Exception("Could not parse results from stdout: \n" + stdout)
    return results


class NetLevelDBServer:
    """Manages a net_leveldb_server process running inside a cgroup."""

    def __init__(self, binary_path: str, db_path: str, port: int):
        self.binary_path = binary_path
        self.db_path = db_path
        self.port = port
        self._process = None

    def start(self, cgroup_name: str):
        """Start the server inside the given cgroup."""
        cmd = [
            "sudo", "cgexec", "-g", "memory:%s" % cgroup_name,
            self.binary_path,
            str(self.port),
            self.db_path,
        ]
        log.info("Starting net_leveldb_server: %s", cmd)
        self._process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        # Wait for server to be ready
        sleep(3)
        if self._process.poll() is not None:
            stderr = self._process.stderr.read().decode("utf-8")
            raise Exception(
                "net_leveldb_server exited unexpectedly: %s" % stderr
            )
        log.info("net_leveldb_server started on port %d (PID %d)", self.port, self._process.pid)

    def stop(self):
        """Stop the server."""
        if self._process is not None and self._process.poll() is None:
            log.info("Stopping net_leveldb_server (PID %d)", self._process.pid)
            try:
                run(["sudo", "kill", str(self._process.pid)])
                self._process.wait(timeout=10)
            except Exception as e:
                log.warning("Failed to stop server gracefully: %s", e)
                try:
                    run(["sudo", "kill", "-9", str(self._process.pid)])
                except Exception:
                    pass
            self._process = None

    @property
    def is_running(self):
        return self._process is not None and self._process.poll() is None


class NetLevelDBBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("net_leveldb_benchmark", benchresults_cls, cli_args)
        if self.args.leveldb_temp_db is None:
            self.args.leveldb_temp_db = self.args.leveldb_db + "_temp"

        self.server = NetLevelDBServer(
            self.args.server_binary,
            self.args.leveldb_temp_db,
            self.args.server_port,
        )
        self.cache_ext_policy = CacheExtPolicy(
            DEFAULT_CACHE_EXT_CGROUP,
            self.args.policy_loader,
            self.args.leveldb_temp_db,
        )
        CLEANUP_TASKS.append(lambda: self.server.stop())
        CLEANUP_TASKS.append(lambda: self.cache_ext_policy.stop())

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--leveldb-db",
            type=str,
            required=True,
            help="Source LevelDB database directory (will be rsync'd to temp dir)",
        )
        parser.add_argument(
            "--leveldb-temp-db",
            type=str,
            default=None,
            help="Temporary directory for LevelDB benchmarking. Default: <leveldb-db>_temp",
        )
        parser.add_argument(
            "--server-binary",
            type=str,
            required=True,
            help="Path to net_leveldb_server binary",
        )
        parser.add_argument(
            "--server-port",
            type=int,
            default=DEFAULT_SERVER_PORT,
            help="TCP port for net_leveldb_server",
        )
        parser.add_argument(
            "--policy-loader",
            type=str,
            required=True,
            help="Path to the cache_ext policy loader binary",
        )
        parser.add_argument(
            "--bench-binary-dir",
            type=str,
            required=True,
            help="Directory containing My-YCSB binaries (run_net_leveldb, etc.)",
        )
        parser.add_argument(
            "--benchmark",
            type=str,
            required=True,
            help="Comma-separated benchmark names, e.g., 'ycsb_a,ycsb_c,mixed_get_scan'",
        )
        parser.add_argument(
            "--runtime-seconds",
            type=int,
            default=240,
            help="Benchmark runtime in seconds per workload",
        )
        parser.add_argument(
            "--warmup-runtime-seconds",
            type=int,
            default=45,
            help="Warmup runtime in seconds per workload",
        )
        parser.add_argument(
            "--cgroup-size-gib",
            type=str,
            default="10",
            help="Comma-separated cgroup size(s) in GiB, e.g., '1,2,4'",
        )

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        if self.args.runtime_seconds <= 0:
            raise ValueError("--runtime-seconds must be > 0")
        if self.args.warmup_runtime_seconds < 0:
            raise ValueError("--warmup-runtime-seconds must be >= 0")

        cgroup_sizes_gib = parse_numbers_string(self.args.cgroup_size_gib)
        if not cgroup_sizes_gib:
            raise ValueError("--cgroup-size-gib must contain at least one value")
        if any(v <= 0 for v in cgroup_sizes_gib):
            raise ValueError("--cgroup-size-gib values must be > 0")

        configs = add_config_option(
            "runtime_seconds", [self.args.runtime_seconds], configs
        )
        configs = add_config_option(
            "warmup_runtime_seconds", [self.args.warmup_runtime_seconds], configs
        )
        configs = add_config_option(
            "benchmark", parse_strings_string(self.args.benchmark), configs
        )
        configs = add_config_option(
            "cgroup_size", [v * GiB for v in cgroup_sizes_gib], configs
        )

        if self.args.default_only:
            configs = add_config_option(
                "cgroup_name", [DEFAULT_BASELINE_CGROUP], configs
            )
        else:
            configs = add_config_option(
                "cgroup_name",
                [DEFAULT_BASELINE_CGROUP, DEFAULT_CACHE_EXT_CGROUP],
                configs,
            )

        # Tag cache_ext configs with policy loader name
        for config in configs:
            if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
                policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
                config["policy_loader"] = policy_loader_name

        configs = add_config_option(
            "iteration", list(range(1, self.args.iterations + 1)), configs
        )
        return configs

    def benchmark_prepare(self, config):
        # Stop any running server from previous iteration
        self.server.stop()
        if self.cache_ext_policy.has_started:
            self.cache_ext_policy.stop()

        # Reset database and clear page cache
        reset_database(self.args.leveldb_db, self.args.leveldb_temp_db)
        drop_page_cache()
        disable_swap()
        disable_smt()

        cgroup_name = config["cgroup_name"]
        cgroup_size = config["cgroup_size"]

        # Create the cgroup for the SERVER (this is where page cache is constrained)
        if cgroup_name == DEFAULT_CACHE_EXT_CGROUP:
            recreate_cache_ext_cgroup(limit_in_bytes=cgroup_size)
            # Start cache_ext policy
            policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
            if policy_loader_name == "cache_ext_s3fifo.out":
                self.cache_ext_policy.start(cgroup_size=cgroup_size)
            else:
                self.cache_ext_policy.start()
        else:
            recreate_baseline_cgroup(limit_in_bytes=cgroup_size)

        # Start net_leveldb_server INSIDE the cgroup
        self.server.start(cgroup_name)
        log.info(
            "Server started in cgroup %s (limit=%s) on port %d",
            cgroup_name,
            format_bytes_str(cgroup_size),
            self.args.server_port,
        )

    def benchmark_cmd(self, config):
        """Return the My-YCSB client command (runs OUTSIDE the cgroup)."""
        bench_binary_dir = self.args.bench_binary_dir
        bench_binary = os.path.join(bench_binary_dir, "run_net_leveldb")
        if not os.path.exists(bench_binary):
            raise Exception("run_net_leveldb not found: %s" % bench_binary)

        bench_file = "../net_leveldb/config/%s.yaml" % config["benchmark"]
        bench_file = os.path.abspath(os.path.join(bench_binary_dir, bench_file))
        if not os.path.exists(bench_file):
            raise Exception("Benchmark config file not found: %s" % bench_file)

        # Apply runtime overrides to the YAML config
        with edit_yaml_file(bench_file) as bench_config:
            bench_config["workload"]["runtime_seconds"] = config["runtime_seconds"]
            bench_config["workload"]["warmup_runtime_seconds"] = config[
                "warmup_runtime_seconds"
            ]
            bench_config["net_leveldb"]["port"] = self.args.server_port

        cmd = [bench_binary, bench_file]
        return cmd

    def cmd_extra_envs(self, config):
        return {}

    def after_benchmark(self, config):
        # Stop the server
        self.server.stop()
        # Stop cache_ext policy
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            self.cache_ext_policy.stop()
        sleep(2)
        enable_smt()

    def parse_results(self, stdout: str) -> BenchResults:
        results = parse_net_leveldb_bench_results(stdout)
        return BenchResults(results)


def main():
    global log
    bench = NetLevelDBBenchmark()
    set_sysctl("vm.dirty_background_ratio", 1)
    set_sysctl("vm.dirty_ratio", 30)
    CLEANUP_TASKS.append(lambda: set_sysctl("vm.dirty_background_ratio", 10))
    CLEANUP_TASKS.append(lambda: set_sysctl("vm.dirty_ratio", 20))

    if not os.path.exists(bench.args.leveldb_db):
        raise Exception(
            "LevelDB DB directory not found: %s" % bench.args.leveldb_db
        )
    if not os.path.exists(bench.args.bench_binary_dir):
        raise Exception(
            "Benchmark binary directory not found: %s" % bench.args.bench_binary_dir
        )
    if not os.path.exists(bench.args.server_binary):
        raise Exception(
            "net_leveldb_server binary not found: %s" % bench.args.server_binary
        )

    log.info("LevelDB DB directory: %s", bench.args.leveldb_db)
    log.info("LevelDB temp DB directory: %s", bench.args.leveldb_temp_db)
    log.info("Server binary: %s", bench.args.server_binary)
    log.info("Server port: %d", bench.args.server_port)

    bench.benchmark()

    set_sysctl("vm.dirty_background_ratio", 10)
    set_sysctl("vm.dirty_ratio", 20)


if __name__ == "__main__":
    try:
        logging.basicConfig(level=logging.INFO)
        main()
    except Exception as e:
        log.error("Error in main: %s", e)
        log.info("Cleaning up")
        for task in CLEANUP_TASKS:
            try:
                task()
            except Exception:
                pass
        log.error("Re-raising exception")
        raise e
