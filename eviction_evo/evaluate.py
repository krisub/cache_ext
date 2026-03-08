#!/usr/bin/env python3
"""
evaluate.py — ShinkaEvolve evaluator for cache_ext eviction policies.

Called by ShinkaEvolve with:
    python evaluate.py --program_path <evolved.c> --results_dir <dir>

Flow:
  1. Copy the evolved .c file into the policies build directory
  2. Compile: clang → .bpf.o → bpftool skeleton → clang userspace loader
  3. Set up cgroup, start net_leveldb_server inside it
  4. Load the evolved BPF policy
  5. Run My-YCSB benchmark
  6. Parse throughput/latency, write metrics.json + correct.json
  7. Cleanup
"""

import argparse
import fcntl
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import traceback
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ─────────────────── Configuration ──────────────────────────────────
# Adjust these paths to match your environment
CACHE_EXT_DIR = "/mydata/cache_ext"
POLICIES_DIR = os.path.join(CACHE_EXT_DIR, "policies")
BUILD_DIR = os.path.join(CACHE_EXT_DIR, "eviction_evo", "build")
SERVER_BINARY = os.path.join(CACHE_EXT_DIR, "net_leveldb_server")
BENCH_BINARY_DIR = os.path.join(CACHE_EXT_DIR, "My-YCSB", "build")
LEVELDB_DB = "/mydata/leveldb"
LEVELDB_TEMP_DB = "/mydata/leveldb_temp"
BENCH_CONFIG = os.path.join(
    CACHE_EXT_DIR, "My-YCSB", "net_leveldb", "config", "ycsb_c.yaml"
)
SERVER_PORT = 9100
CGROUP_NAME = "cache_ext_test"
CGROUP_PATH = f"/sys/fs/cgroup/{CGROUP_NAME}"
CGROUP_SIZE_BYTES = 512 * (2**20)  # 512 MiB — hot working set ~600 MiB so this creates real eviction pressure

# Benchmark timing
WARMUP_SECONDS = 30
RUNTIME_SECONDS = 120
# Maximum time to wait for the full evaluation (compile + bench), seconds
EVAL_TIMEOUT_SECONDS = 1200

# Compiler settings (same as policies/Makefile)
CLANG = "clang-14"
BPFTOOL = "/usr/local/sbin/bpftool"
ARCH = (
    subprocess.check_output(
        "uname -m | sed 's/x86_64/x86/'", shell=True
    )
    .decode()
    .strip()
)
CLANG_BPF_SYS_INCLUDES = (
    subprocess.check_output(
        f"{CLANG} -v -E - </dev/null 2>&1 | "
        "sed -n '/<...> search starts here:/,/End of search list./{ s| \\(/.*\\)|-idirafter \\1|p }'",
        shell=True,
    )
    .decode()
    .strip()
)
GiB = 2**30


def run_cmd(cmd, timeout=60, check=True, **kwargs):
    """Run a command, return CompletedProcess. Raises on failure if check=True."""
    log.info("CMD: %s", " ".join(cmd) if isinstance(cmd, list) else cmd)
    return subprocess.run(
        cmd, timeout=timeout, check=check,
        capture_output=True, text=True, **kwargs
    )


def save_results(results_dir, metrics, correct, error_msg):
    """Write metrics.json and correct.json as ShinkaEvolve expects."""
    os.makedirs(results_dir, exist_ok=True)
    with open(os.path.join(results_dir, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)
    with open(os.path.join(results_dir, "correct.json"), "w") as f:
        json.dump({"correct": correct, "error": error_msg}, f, indent=2)


# ─────────────────── Compilation ────────────────────────────────────


def compile_bpf_policy(evolved_c_path: str, build_dir: str):
    """
    Compile the evolved .c into a loadable BPF policy + userspace loader.
    Returns the path to the compiled loader binary, or raises on failure.
    """
    os.makedirs(build_dir, exist_ok=True)

    bpf_src = os.path.join(build_dir, "cache_ext_evolved.bpf.c")
    bpf_obj = os.path.join(build_dir, "cache_ext_evolved.bpf.o")
    skel_h = os.path.join(build_dir, "cache_ext_evolved.skel.h")
    loader_src = os.path.join(
        CACHE_EXT_DIR, "eviction_evo", "cache_ext_evolved.c"
    )
    loader_out = os.path.join(build_dir, "cache_ext_evolved.out")

    # Fix ownership of any root-owned build artifacts (from prior sudo runs)
    run_cmd(["sudo", "chown", "-R", f"{os.environ.get('USER', 'krisub')}:", build_dir],
            check=False)

    # Copy evolved source
    shutil.copy2(evolved_c_path, bpf_src)

    # Symlink required headers into build dir
    for header in [
        "cache_ext_lib.bpf.h",
        "dir_watcher.bpf.h",
        "dir_watcher.h",
        "vmlinux.h",
    ]:
        dst = os.path.join(build_dir, header)
        src = os.path.join(POLICIES_DIR, header)
        if not os.path.exists(src):
            # vmlinux.h might be in the policies dir or needs generation
            if header == "vmlinux.h":
                src = os.path.join(CACHE_EXT_DIR, "vmlinux.h")
        if os.path.exists(dst):
            os.remove(dst)
        if os.path.exists(src):
            os.symlink(src, dst)
        else:
            raise FileNotFoundError(f"Required header {header} not found at {src}")

    # 1. Compile BPF object
    clang_cmd = [
        CLANG,
        "-O2",
        "-target", "bpf",
        f"-D__TARGET_ARCH_{ARCH}",
        "-c", "-g", "-Wall",
    ] + CLANG_BPF_SYS_INCLUDES.split() + [bpf_src, "-o", bpf_obj]
    result = run_cmd(clang_cmd, timeout=60, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"BPF compilation failed:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}")

    # 2. Generate skeleton header (name must match what cache_ext_evolved.c expects)
    skel_cmd = f"{BPFTOOL} gen skeleton {bpf_obj} name cache_ext_evolved_bpf"
    result = run_cmd(skel_cmd, timeout=30, shell=True)
    if result.returncode != 0:
        raise RuntimeError(f"Skeleton generation failed:\n{result.stderr}")
    with open(skel_h, "w") as f:
        f.write(result.stdout)

    # 3. Compile userspace loader
    loader_cmd = [
        CLANG,
        "-O2", "-g", "-Wall",
        f"-I{build_dir}",
        f"-I{POLICIES_DIR}",
        loader_src,
        "-o", loader_out,
        "-L/usr/local/lib64",
        "-lbpf",
    ]
    result = run_cmd(loader_cmd, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"Loader compilation failed:\n{result.stderr}")

    log.info("Compilation successful: %s", loader_out)
    return loader_out


# ─────────────────── Cgroup Management ──────────────────────────────


def delete_cgroup():
    """Delete the test cgroup if it exists."""
    try:
        run_cmd(["sudo", "cgdelete", f"memory:{CGROUP_NAME}"], check=False)
    except Exception:
        pass


def create_cgroup(limit_bytes):
    """Create the cgroup with the given memory limit."""
    delete_cgroup()
    run_cmd(["sudo", "cgcreate", "-g", f"memory:{CGROUP_NAME}"])
    run_cmd([
        "sudo", "sh", "-c",
        f"echo {limit_bytes} > /sys/fs/cgroup/{CGROUP_NAME}/memory.max",
    ])
    log.info("Created cgroup %s with limit %d bytes", CGROUP_NAME, limit_bytes)


MGLRU_ENABLED_PATH = "/sys/kernel/mm/lru_gen/enabled"
_mglru_original_value = None


def drop_page_cache():
    run_cmd(["sudo", "sync"])
    run_cmd(["sudo", "sh", "-c", "echo 3 > /proc/sys/vm/drop_caches"])
    log.info("Page cache dropped.")


def disable_mglru():
    """Disable MGLRU so the BPF evict_folios hook is the sole eviction decision maker."""
    global _mglru_original_value
    if os.path.exists(MGLRU_ENABLED_PATH):
        _mglru_original_value = open(MGLRU_ENABLED_PATH).read().strip()
        log.info("MGLRU current state: %s — disabling", _mglru_original_value)
        run_cmd(["sudo", "sh", "-c", f"echo 0 > {MGLRU_ENABLED_PATH}"])
        log.info("MGLRU disabled.")
    else:
        log.warning("MGLRU sysfs path not found: %s", MGLRU_ENABLED_PATH)


def enable_mglru():
    """Re-enable MGLRU after evaluation, restoring original value."""
    global _mglru_original_value
    if os.path.exists(MGLRU_ENABLED_PATH):
        restore = _mglru_original_value if _mglru_original_value else "0x0007"
        run_cmd(["sudo", "sh", "-c", f"echo {restore} > {MGLRU_ENABLED_PATH}"])
        log.info("MGLRU re-enabled (restored to %s).", restore)
    else:
        log.warning("MGLRU sysfs path not found: %s", MGLRU_ENABLED_PATH)


# ─────────────────── Server Management ──────────────────────────────


def wait_for_port(host, port, timeout=120):
    """Poll TCP port until it accepts connections or timeout (seconds)."""
    import socket as _socket
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = _socket.create_connection((host, port), timeout=1)
            s.close()
            return True
        except OSError:
            time.sleep(1)
    return False


def start_server(db_path, port, cgroup_name):
    """Start net_leveldb_server inside the cgroup. Returns Popen."""
    cmd = [
        "sudo", "cgexec", "-g", f"memory:{cgroup_name}",
        SERVER_BINARY, str(port), db_path,
    ]
    log.info("Starting server: %s", " ".join(cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Wait up to 120s for LevelDB to open the DB and start accepting connections
    log.info("Waiting for server on port %d ...", port)
    if not wait_for_port("127.0.0.1", port, timeout=120):
        if proc.poll() is not None:
            stderr = proc.stderr.read().decode()
            raise RuntimeError(f"Server exited before becoming ready: {stderr}")
        raise RuntimeError(f"Server did not start listening on port {port} within 120s")
    if proc.poll() is not None:
        stderr = proc.stderr.read().decode()
        raise RuntimeError(f"Server exited immediately: {stderr}")
    log.info("Server ready (PID %d) on port %d", proc.pid, port)
    return proc


def stop_process(proc, name="process"):
    """Gracefully stop a subprocess."""
    if proc is None or proc.poll() is not None:
        return
    log.info("Stopping %s (PID %d)", name, proc.pid)
    try:
        run_cmd(["sudo", "kill", str(proc.pid)], check=False)
        proc.wait(timeout=10)
    except Exception:
        try:
            run_cmd(["sudo", "kill", "-9", str(proc.pid)], check=False)
            proc.wait(timeout=5)
        except Exception:
            pass


# ─────────────────── Policy Management ──────────────────────────────


def start_policy(loader_path, watch_dir):
    """Load the evolved BPF policy. Returns Popen."""
    cmd = [
        "sudo", loader_path,
        "--watch_dir", watch_dir,
        "--cgroup_path", CGROUP_PATH,
    ]
    log.info("Loading policy: %s", " ".join(cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(10)  # BPF loading can take several seconds
    if proc.poll() is not None:
        stderr = proc.stderr.read().decode()
        raise RuntimeError(f"Policy loader exited immediately: {stderr}")
    log.info("Policy loaded (PID %d)", proc.pid)
    return proc


def stop_policy(proc):
    """Send SIGINT to cleanly unload the BPF policy."""
    if proc is None or proc.poll() is not None:
        return
    log.info("Unloading BPF policy (PID %d)", proc.pid)
    try:
        run_cmd(["sudo", "kill", "-2", str(proc.pid)], check=False)
        proc.wait(timeout=15)
    except Exception:
        try:
            run_cmd(["sudo", "kill", "-9", str(proc.pid)], check=False)
        except Exception:
            pass
    try:
        run_cmd(["sudo", "rm", "-f", "/sys/fs/bpf/cache_ext/scan_pids"], check=False)
    except Exception:
        pass


# ─────────────────── Benchmark ──────────────────────────────────────


def reset_database():
    """rsync the source DB to the temp location. Skips if temp DB already exists."""
    src = LEVELDB_DB
    if not src.endswith("/"):
        src += "/"
    # Check if temp DB already has essential LevelDB files (CURRENT, MANIFEST)
    # Skip expensive rsync for read-only workloads
    current_file = os.path.join(LEVELDB_TEMP_DB, "CURRENT")
    if os.path.isfile(current_file):
        log.info("Database already exists at %s (CURRENT file found), skipping rsync",
                 LEVELDB_TEMP_DB)
        return
    run_cmd(["rsync", "-apl", "--delete", src, LEVELDB_TEMP_DB], timeout=900)
    log.info("Database reset: %s → %s", LEVELDB_DB, LEVELDB_TEMP_DB)


def run_benchmark():
    """
    Run My-YCSB benchmark. Returns parsed throughput/latency results dict.
    Raises on failure.
    """
    bench_binary = os.path.join(BENCH_BINARY_DIR, "run_net_leveldb")
    if not os.path.exists(bench_binary):
        raise FileNotFoundError(f"run_net_leveldb not found: {bench_binary}")

    # Create a temporary copy of bench config with our timing settings
    import yaml as pyyaml

    with open(BENCH_CONFIG, "r") as f:
        config = pyyaml.safe_load(f)

    config["workload"]["runtime_seconds"] = RUNTIME_SECONDS
    config["workload"]["warmup_runtime_seconds"] = WARMUP_SECONDS
    config["net_leveldb"]["port"] = SERVER_PORT

    tmp_config = os.path.join(BUILD_DIR, "bench_config.yaml")
    with open(tmp_config, "w") as f:
        pyyaml.dump(config, f)

    cmd = [bench_binary, tmp_config]
    log.info("Running benchmark: %s", " ".join(cmd))
    result = run_cmd(cmd, timeout=WARMUP_SECONDS + RUNTIME_SECONDS + 120)
    stdout = result.stdout
    log.info("Benchmark stdout:\n%s", stdout[:2000])

    return parse_benchmark_results(stdout)


def parse_benchmark_results(stdout: str) -> dict:
    """Parse My-YCSB output into a results dict."""
    results = {}
    for line in stdout.splitlines():
        line = line.strip()
        if "Warm-Up" in line:
            continue
        elif "overall: UPDATE throughput" in line or "overall:" in line:
            # Parse throughput
            pattern = r"(\w+ throughput) (\d+\.?\d*) ops/sec"
            matches = re.findall(pattern, line)
            for label, value in matches:
                if "READ throughput" in label:
                    results["read_throughput"] = float(value)
                elif "INSERT throughput" in label:
                    results["insert_throughput"] = float(value)
                elif "UPDATE throughput" in label:
                    results["update_throughput"] = float(value)
                elif "SCAN throughput" in label:
                    results["scan_throughput"] = float(value)
                elif "READ_MODIFY_WRITE throughput" in label:
                    results["rmw_throughput"] = float(value)
                elif "total throughput" in label:
                    results["total_throughput"] = float(value)

            # Parse latency
            pattern = r"(\w+ \w+ latency) (\d+\.?\d*) ns"
            matches = re.findall(pattern, line)
            for label, value in matches:
                if "READ average latency" in label:
                    results["read_latency_avg_ns"] = float(value)
                elif "READ p99 latency" in label:
                    results["read_latency_p99_ns"] = float(value)
                elif "SCAN average latency" in label:
                    results["scan_latency_avg_ns"] = float(value)
                elif "SCAN p99 latency" in label:
                    results["scan_latency_p99_ns"] = float(value)

    if "total_throughput" not in results:
        raise RuntimeError(f"Could not parse throughput from output:\n{stdout[:2000]}")

    return results


# ─────────────────── Main Evaluation ────────────────────────────────


# Serialization lock — only one evaluate() may run at a time regardless of
# how many parallel evaluate.py processes ShinkaEvolve spawns.
EVAL_LOCK_PATH = "/tmp/cache_ext_evaluate.lock"


def evaluate(program_path: str, results_dir: str):
    """
    Full evaluation pipeline:
      drop cache → compile → disable MGLRU → setup cgroup → start server → load policy → benchmark → cleanup
    """
    # Acquire exclusive lock so concurrent evaluate.py instances don't fight
    # over the LevelDB LOCK file, cgroup, or port 9100.
    lock_fd = open(EVAL_LOCK_PATH, "w")
    log.info("Waiting for evaluation lock %s ...", EVAL_LOCK_PATH)
    fcntl.flock(lock_fd, fcntl.LOCK_EX)  # blocks until previous run finishes
    log.info("Acquired evaluation lock.")

    server_proc = None
    policy_proc = None
    mglru_disabled = False

    try:
        # 0. Drop page cache FIRST (before compilation) so even failed runs
        #    don't leave a warm cache that benefits the next generation.
        log.info("=== Step 0: Drop page cache ===")
        reset_database()
        drop_page_cache()

        # 1. Compile
        log.info("=== Step 1: Compile evolved policy ===")
        loader_path = compile_bpf_policy(program_path, BUILD_DIR)

        # 2. Disable MGLRU so BPF evict_folios is the sole eviction decision maker.
        #    Without this, the kernel routes cgroup reclaim through MGLRU directly,
        #    never calling our BPF hook, and evict_folios never fires.
        log.info("=== Step 2: Disable MGLRU ===")
        disable_mglru()
        mglru_disabled = True

        # 3. Create cgroup
        log.info("=== Step 3: Create cgroup ===")
        create_cgroup(CGROUP_SIZE_BYTES)

        # 4. Load BPF policy
        log.info("=== Step 4: Load BPF policy ===")
        policy_proc = start_policy(loader_path, LEVELDB_TEMP_DB)

        # 5. Start server in cgroup
        log.info("=== Step 5: Start server ===")
        server_proc = start_server(LEVELDB_TEMP_DB, SERVER_PORT, CGROUP_NAME)

        # 6. Run benchmark
        log.info("=== Step 6: Run benchmark ===")
        bench_results = run_benchmark()

        # 7. Compute metrics
        total_tp = bench_results.get("total_throughput", 0.0)
        read_tp = bench_results.get("read_throughput", 0.0)
        read_lat_avg = bench_results.get("read_latency_avg_ns", float("inf"))
        read_lat_p99 = bench_results.get("read_latency_p99_ns", float("inf"))

        # Combined score: higher is better.
        # Primary metric is throughput. We also reward lower latency.
        # Normalize latency contribution: latency_bonus = 1M / p99_latency
        # (caps at 1.0 for p99 >= 1ms, gives bonus for sub-ms p99)
        latency_bonus = min(1.0, 1_000_000.0 / max(read_lat_p99, 1.0))
        combined_score = total_tp + total_tp * 0.1 * latency_bonus

        metrics = {
            "combined_score": combined_score,
            "public": {
                "total_throughput_ops_sec": total_tp,
                "read_throughput_ops_sec": read_tp,
                "read_latency_avg_ns": read_lat_avg,
                "read_latency_p99_ns": read_lat_p99,
            },
            "private": bench_results,
        }

        save_results(results_dir, metrics, correct=True, error_msg=None)
        log.info("=== Evaluation complete ===")
        log.info("Combined score: %.2f  (throughput: %.0f ops/sec, p99: %.0f ns)",
                 combined_score, total_tp, read_lat_p99)

    except Exception as e:
        stderr_detail = ""
        if hasattr(e, "stderr") and e.stderr:
            stderr_detail = f"\nSTDERR: {e.stderr}"
        if hasattr(e, "stdout") and e.stdout:
            stderr_detail += f"\nSTDOUT: {e.stdout}"
        error_msg = f"{type(e).__name__}: {e}{stderr_detail}\n{traceback.format_exc()}"
        log.error("Evaluation failed: %s", error_msg)
        metrics = {
            "combined_score": 0.0,
            "public": {"error": str(e)},
            "private": {"traceback": traceback.format_exc()},
        }
        save_results(results_dir, metrics, correct=False, error_msg=str(e))

    finally:
        # Cleanup
        stop_process(server_proc, "net_leveldb_server")
        stop_policy(policy_proc)
        delete_cgroup()
        if mglru_disabled:
            enable_mglru()
        # Release the evaluation lock so the next queued evaluate.py can proceed
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()


def main():
    parser = argparse.ArgumentParser(
        description="ShinkaEvolve evaluator for cache_ext eviction policies"
    )
    parser.add_argument(
        "--program_path",
        type=str,
        required=True,
        help="Path to the evolved .c file",
    )
    parser.add_argument(
        "--results_dir",
        type=str,
        required=True,
        help="Directory to write metrics.json and correct.json",
    )
    args = parser.parse_args()
    evaluate(args.program_path, args.results_dir)


if __name__ == "__main__":
    main()
