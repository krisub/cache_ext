import argparse
import logging
import os
import re
from typing import Dict, List

from bench_lib import *


log = logging.getLogger(__name__)


def parse_redis_bench_results(stdout: str) -> Dict:
    results = {}
    for line in stdout.splitlines():
        line = line.strip()
        if "Warm-Up" in line:
            continue
        if "overall: UPDATE throughput" in line:
            pattern = r"(\w+ throughput) (\d+\.\d+) ops/sec"
            matches = re.findall(pattern, line)
            if len(matches) != 6:
                raise Exception("Unexpected throughput line: %s" % line)
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
    required = ["throughput_avg", "latency_avg", "latency_p99"]
    if not all(k in results for k in required):
        raise Exception("Could not parse results from stdout:\n%s" % stdout)
    return results


class RedisBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("redis_benchmark", benchresults_cls, cli_args)

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--bench-binary-dir",
            type=str,
            required=True,
            help="Directory containing init_redis and run_redis",
        )
        parser.add_argument(
            "--benchmark",
            type=str,
            required=True,
            help="Comma-separated Redis YAML configs, e.g. 'uniform,zipfian'",
        )
        parser.add_argument(
            "--redis-config-dir",
            type=str,
            default=None,
            help="Directory containing Redis YAML configs; default <bench-binary-dir>/../redis/config",
        )
        parser.add_argument(
            "--redis-host",
            type=str,
            default=None,
            help="Override redis.addr in YAML",
        )
        parser.add_argument(
            "--redis-port",
            type=int,
            default=None,
            help="Override redis.port in YAML and pass as CLI arg",
        )
        parser.add_argument(
            "--nr-op",
            type=int,
            default=None,
            help="Override workload.nr_op in YAML",
        )
        parser.add_argument(
            "--nr-warmup-op",
            type=int,
            default=None,
            help="Override workload.nr_warmup_op in YAML",
        )
        parser.add_argument(
            "--nr-thread",
            type=int,
            default=None,
            help="Override workload.nr_thread in YAML",
        )
        parser.add_argument(
            "--nr-init-thread",
            type=int,
            default=None,
            help="Override workload.nr_init_thread in YAML",
        )
        parser.add_argument(
            "--init-before-run",
            action="store_true",
            default=False,
            help="Run init_redis before each benchmark run",
        )
        parser.add_argument(
            "--cgroup-name",
            type=str,
            default="",
            help="Optional cgroup name to run inside (requires existing memory cgroup)",
        )

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option(
            "benchmark", parse_strings_string(self.args.benchmark), configs
        )
        configs = add_config_option(
            "iteration", list(range(1, self.args.iterations + 1)), configs
        )
        return configs

    def _config_dir(self) -> str:
        if self.args.redis_config_dir:
            return os.path.abspath(self.args.redis_config_dir)
        return os.path.abspath(
            os.path.join(self.args.bench_binary_dir, "../redis/config")
        )

    def _config_path(self, benchmark: str) -> str:
        return os.path.join(self._config_dir(), "%s.yaml" % benchmark)

    def _apply_overrides(self, bench_file: str):
        with edit_yaml_file(bench_file) as bench_config:
            if self.args.redis_host is not None:
                bench_config["redis"]["addr"] = self.args.redis_host
            if self.args.redis_port is not None:
                bench_config["redis"]["port"] = self.args.redis_port
            if self.args.nr_op is not None:
                bench_config["workload"]["nr_op"] = self.args.nr_op
            if self.args.nr_warmup_op is not None:
                bench_config["workload"]["nr_warmup_op"] = self.args.nr_warmup_op
            if self.args.nr_thread is not None:
                bench_config["workload"]["nr_thread"] = self.args.nr_thread
            if self.args.nr_init_thread is not None:
                bench_config["workload"]["nr_init_thread"] = self.args.nr_init_thread

    def _redis_cmd(self, binary: str, bench_file: str) -> List[str]:
        cmd = []
        if self.args.cgroup_name:
            cmd += ["sudo", "cgexec", "-g", "memory:%s" % self.args.cgroup_name]
        cmd += [binary, bench_file]
        if self.args.redis_port is not None:
            cmd += [str(self.args.redis_port)]
        return cmd

    def benchmark_prepare(self, config):
        bench_file = self._config_path(config["benchmark"])
        if not os.path.exists(bench_file):
            raise Exception("Benchmark file not found: %s" % bench_file)
        self._apply_overrides(bench_file)

        if self.args.init_before_run:
            init_binary = os.path.join(self.args.bench_binary_dir, "init_redis")
            if not os.path.exists(init_binary):
                raise Exception("init_redis not found: %s" % init_binary)
            run(self._redis_cmd(init_binary, bench_file))

    def benchmark_cmd(self, config):
        bench_file = self._config_path(config["benchmark"])
        run_binary = os.path.join(self.args.bench_binary_dir, "run_redis")
        if not os.path.exists(run_binary):
            raise Exception("run_redis not found: %s" % run_binary)
        return self._redis_cmd(run_binary, bench_file)

    def parse_results(self, stdout: str) -> BenchResults:
        return BenchResults(parse_redis_bench_results(stdout))


def main():
    redis_bench = RedisBenchmark()
    if not os.path.exists(redis_bench.args.bench_binary_dir):
        raise Exception(
            "Benchmark binary directory not found: %s" % redis_bench.args.bench_binary_dir
        )
    redis_bench.benchmark()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
