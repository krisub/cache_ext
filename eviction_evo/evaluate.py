#!/usr/bin/env python3
"""
evaluate.py - ShinkaEvolve evaluator for cache_ext eviction policies.

Called by ShinkaEvolve with:
    python evaluate.py --program_path <evolved.c> --results_dir <dir>

Flow:
  1. Copy the evolved .c file into the policies build directory
  2. Compile: clang -> .bpf.o -> bpftool skeleton -> clang userspace loader
  3. (Default) Before each benchmark: reclone DB, cgroup, start server, load BPF
  4. Run My-YCSB benchmark(s)
  5. Parse throughput/latency, write metrics.json + correct.json
  6. Cleanup
"""

import argparse
import copy
import fcntl
import json
import platform
import random
import threading
import logging
import math
import os
import re
import shlex
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
import traceback
import yaml as pyyaml
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


# -- Emergency cleanup ---------------------------------------------------------
# MGLRU is a system-wide setting. If evaluate.py is killed (SIGKILL from
# ShinkaEvolve, Ctrl+C, timeout, etc.) while MGLRU is disabled, the entire
# system loses its page reclaim strategy and becomes unresponsive.
#
# We defend against this at three levels:
#   1. atexit -- runs on normal exit and most signal-induced exits
#   2. SIGTERM/SIGINT handlers -- convert to SystemExit so finally blocks run
#   3. Startup guard -- re-enable MGLRU at the very start of every evaluation
#      in case a previous run was killed without cleanup

def _emergency_restore_mglru():
    """Last-resort MGLRU restoration. Called via atexit."""
    try:
        path = "/sys/kernel/mm/lru_gen/enabled"
        if os.path.exists(path):
            current = open(path).read().strip()
            if current == "0x0000" or current == "0":
                subprocess.run(
                    ["sudo", "sh", "-c", f"echo 0x0007 > {path}"],
                    timeout=10, check=False, capture_output=True,
                )
    except Exception:
        pass

import atexit
atexit.register(_emergency_restore_mglru)


def _signal_handler(signum, frame):
    """Convert SIGTERM/SIGINT into SystemExit so try/finally blocks execute."""
    log.warning("Received signal %d, initiating cleanup...", signum)
    raise SystemExit(128 + signum)

signal.signal(signal.SIGTERM, _signal_handler)
signal.signal(signal.SIGINT, _signal_handler)


# -- Configuration -------------------------------------------------------------
# Adjust these paths to match your environment
CACHE_EXT_DIR = "/mydata/cache_ext"
POLICIES_DIR = os.path.join(CACHE_EXT_DIR, "policies")
BUILD_DIR = os.path.join(CACHE_EXT_DIR, "eviction_evo", "build")
SERVER_BINARY = os.path.join(CACHE_EXT_DIR, "net_leveldb_server")
BENCH_BINARY_DIR = os.path.join(CACHE_EXT_DIR, "My-YCSB", "build")
LEVELDB_DB = "/mydata/leveldb"
LEVELDB_TEMP_DB = "/mydata/leveldb_temp"
TRACES_DIR = os.path.join(CACHE_EXT_DIR, "eviction_evo")
PROXY_SCRIPT = os.path.join(CACHE_EXT_DIR, "eviction_evo", "tcp_delay_proxy.py")
SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
           "-i", "/users/krisub/.ssh/id_ed25519"]
REMOTE_CLIENT_CGROUP = "cache_ext_remote_clients"
# Ordered list of trace configs to run for each evaluation.
# Each trace is (short_name, yaml_filename).
#
# By default (RESET_ENV_EVERY_RUN, see below) each benchmark run stops the server,
# reclones leveldb_temp from LEVELDB_DB, drops page cache, recreates the cgroup, reloads
# BPF, and restarts the server — so traces do not mutate each other's DB and order
# does not matter. Set CACHE_EXT_RESET_EVERY_RUN=0 for one DB+server for the whole
# suite (faster; not comparable across trace order).
TRACE_CONFIGS = [
    # # Single-client traces (commented out - dual-client only mode)
    # ("ycsb_a", "ycsb_a.yaml"),           # 50% read, 50% update (zipfian)
    # ("ycsb_b", "ycsb_b.yaml"),           # 95% read, 5% update (zipfian)
    # ("ycsb_c", "ycsb_c.yaml"),           # 100% read (zipfian)
    # ("ycsb_d", "ycsb_d.yaml"),           # 95% read, 5% insert (latest)
    # ("ycsb_e", "ycsb_e.yaml"),           # 95% scan, 5% insert (zipfian)
    # ("ycsb_f", "ycsb_f.yaml"),           # 50% read, 50% RMW (zipfian)
    # ("uniform", "uniform.yaml"),          # 100% read (uniform)
    # ("uniform_rw", "uniform_read_write.yaml"),  # 50% read, 50% insert (uniform)
    # Dual-client traces in `dual_host_traces/` (already remote on node1)
    # ("dual_small_vs_large", "dual_host_traces/dual_small_vs_large.yaml"),  # fast reader + slow large writer
    # ("dual_congested", "dual_host_traces/dual_congested.yaml"),             # both clients WAN-delayed

    # dual-client traces in `traces/`: YCSB workload pairings vs same DB
    # ("ycsb_c_a", "traces/ycsb_c_a.yaml"),   # pure read hot-set vs read/update churn
    # ("ycsb_c_b", "traces/ycsb_c_b.yaml"),   # pure read hot-set vs mostly-read w/ low updates
    # ("ycsb_c_d", "traces/ycsb_c_d.yaml"),   # pure read hot-set vs RMW mix (50% read_modify_write)
    # ("ycsb_c_e", "traces/ycsb_c_e.yaml"),   # pure read hot-set vs mostly reads + latest inserts
    # ("ycsb_c_f", "traces/ycsb_c_f.yaml"),   # pure read hot-set vs scan-heavy client
    # ("ycsb_b_a", "traces/ycsb_b_a.yaml"),   # mostly-read vs aggressive updates (read/update mix)
    # ("ycsb_a_d", "traces/ycsb_a_d.yaml"),   # read/update mix vs RMW mix
    # ("ycsb_a_d_sched_1", "traces/ycsb_a_d_schedule_1.yaml"),  
    # ("ycsb_a_d_sched_2_a", "traces/ycsb_a_d_schedule_2_a.yaml"), 
    # ("ycsb_a_d_sched_2_a_flipped", "traces/ycsb_a_d_schedule_2_a_flipped.yaml"),  
    # ("ycsb_a_d_sched_2_b", "traces/ycsb_a_d_schedule_2_b.yaml"),  
    ("ycsb_a_d_sched_2_c", "traces/ycsb_a_d_schedule_2_c.yaml"),  
    # ("ycsb_b_f", "traces/ycsb_b_f.yaml"),   # mostly-read vs scan-heavy
    # ("ycsb_e_a", "traces/ycsb_e_a.yaml"),   # latest inserts vs read/update churn
    # ("ycsb_e_f", "traces/ycsb_e_f.yaml"),   # latest inserts vs scan-heavy
]
SERVER_PORT = 9100
CGROUP_NAME = "cache_ext_test"
CGROUP_PATH = f"/sys/fs/cgroup/{CGROUP_NAME}"
CGROUP_SIZE_BYTES = 512 * (2**20) # 512 mb

# Benchmark timing
WARMUP_SECONDS = 30
RUNTIME_SECONDS = 120
RUNS_PER_TRACE = 5
# When True (default): before each benchmark run, reclone DB, drop caches, reload BPF,
# restart server. Comparable across traces; slower. Disable with CACHE_EXT_RESET_EVERY_RUN=0.
RESET_ENV_EVERY_RUN = os.environ.get("CACHE_EXT_RESET_EVERY_RUN", "1") != "0"
# Optional: diagnostic latency-adjusted score (not used for combined_score).
# Per-trace diagnostic = throughput_mean / (1 + read_p99_ms / LAT_REF_MS).
LAT_REF_MS = float(os.environ.get("LAT_REF_MS", "400"))
# Copy bounded per-run throughput / read p99 into public_metrics so Shinka LLM prompts (perf_str) show them.
# Disable with CACHE_EXT_PUBLIC_PER_RUN_STATS=0. Cap list length with CACHE_EXT_PUBLIC_PER_RUN_MAX (default 20).
PUBLIC_PER_RUN_STATS = os.environ.get("CACHE_EXT_PUBLIC_PER_RUN_STATS", "1") != "0"
PUBLIC_PER_RUN_MAX = max(1, int(os.environ.get("CACHE_EXT_PUBLIC_PER_RUN_MAX", "20")))
# Maximum time to wait for the full evaluation, seconds
EVAL_TIMEOUT_SECONDS = 7200

# Compiler settings (same as policies/Makefile)
CLANG = "clang-14"
BPFTOOL = "/usr/local/sbin/bpftool"
def _get_arch():
    try:
        return subprocess.check_output(
            "uname -m | sed 's/x86_64/x86/'", shell=True
        ).decode().strip()
    except Exception:
        m = platform.machine()
        return "x86" if m == "x86_64" else m


ARCH = _get_arch()


def _get_clang_includes():
    try:
        out = subprocess.check_output(
            f"{CLANG} -v -E - </dev/null 2>&1 | "
            "sed -n '/<...> search starts here:/,/End of search list./{ s| \\(/.*\\)|-idirafter \\1|p }'",
            shell=True,
            timeout=10,
        ).decode().strip()
        if out:
            return out
    except Exception:
        pass
    # Fallback: common include paths for BPF (avoids clang/sed pipeline segfaults)
    return "-idirafter /usr/lib/llvm-14/lib/clang/14.0.0/include -idirafter /usr/local/include -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include"


CLANG_BPF_SYS_INCLUDES = _get_clang_includes()
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


# -- Compilation -------------------------------------------------------------


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
            if header == "vmlinux.h":
                src = os.path.join(CACHE_EXT_DIR, "vmlinux.h")
        if os.path.exists(dst):
            os.remove(dst)
        if os.path.exists(src):
            os.symlink(src, dst)
        else:
            raise FileNotFoundError(f"Required header {header} not found at {src}")

    # Symlink the vulcan_bpf library directory
    vulcan_dst = os.path.join(build_dir, "vulcan_bpf")
    vulcan_src = os.path.join(CACHE_EXT_DIR, "vulcan_bpf")
    if os.path.exists(vulcan_dst) or os.path.islink(vulcan_dst):
        os.remove(vulcan_dst)
    os.symlink(vulcan_src, vulcan_dst)

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


# -- Cgroup Management ---------------------------------------------------------


def delete_cgroup():
    """Delete the test cgroup if it exists."""
    for cmd, desc in [
        (["sudo", "cgdelete", f"memory:{CGROUP_NAME}"], "cgdelete"),
        (["sudo", "rmdir", f"/sys/fs/cgroup/{CGROUP_NAME}"], "rmdir v2"),
        (["sudo", "rmdir", f"/sys/fs/cgroup/memory/{CGROUP_NAME}"], "rmdir v1"),
    ]:
        try:
            subprocess.run(cmd, check=False, timeout=5, capture_output=True)
        except Exception:
            pass


def create_cgroup(limit_bytes):
    """Create the cgroup with the given memory limit.
    Uses cgcreate when available; falls back to cgroup v2 filesystem API
    when cgcreate segfaults (e.g. on some cgroup v2 setups)."""
    delete_cgroup()

    try:
        run_cmd(["sudo", "cgcreate", "-g", f"memory:{CGROUP_NAME}"], timeout=5)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        log.warning("cgcreate failed (%s), trying cgroup v2 fallback", e)
        run_cmd(["sudo", "mkdir", "-p", f"/sys/fs/cgroup/{CGROUP_NAME}"])

    # Set memory limit (v2: memory.max, v1: memory.limit_in_bytes)
    for path, fname in [
        (f"/sys/fs/cgroup/{CGROUP_NAME}", "memory.max"),
        (f"/sys/fs/cgroup/memory/{CGROUP_NAME}", "memory.limit_in_bytes"),
    ]:
        limit_file = f"{path}/{fname}"
        if os.path.exists(path):
            run_cmd(["sudo", "sh", "-c", f"echo {limit_bytes} > {limit_file}"])
            break
    log.info("Created cgroup %s with limit %d bytes", CGROUP_NAME, limit_bytes)


MGLRU_ENABLED_PATH = "/sys/kernel/mm/lru_gen/enabled"
_mglru_original_value = None
_mglru_watchdog_pid = None


def _start_mglru_watchdog(debug: bool):
    """Spawn a root process that will restore MGLRU after a timeout.
    The process runs as root from the start (via sudo); when it wakes from sleep,
    it writes directly to sysfs without invoking sudo again. So even when the
    system is thrashing and sudo would segfault, this restore can succeed."""
    global _mglru_watchdog_pid
    if not os.path.exists(MGLRU_ENABLED_PATH):
        return
    # Debug: ~5 min run; Full: EVAL_TIMEOUT_SECONDS (2h) + 10 min buffer
    seconds = 600 if debug else EVAL_TIMEOUT_SECONDS + 600
    cmd = [
        "sudo", "-n", "sh", "-c",
        f"sleep {seconds}; echo 0x0007 > {MGLRU_ENABLED_PATH}",
    ]
    try:
        proc = subprocess.Popen(
            cmd,
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _mglru_watchdog_pid = proc.pid
        log.info("MGLRU watchdog started (PID %d, will restore in %d s)", proc.pid, seconds)
    except Exception as e:
        log.warning("Failed to start MGLRU watchdog: %s (atexit/signal handlers still active)", e)
        _mglru_watchdog_pid = None


def _stop_mglru_watchdog():
    """Kill the MGLRU watchdog if we restored MGLRU ourselves."""
    global _mglru_watchdog_pid
    if _mglru_watchdog_pid is None:
        return
    try:
        # Kill the whole process group (sudo + its child shell) so the watchdog
        # does not run the echo after we've already restored MGLRU.
        os.killpg(_mglru_watchdog_pid, signal.SIGKILL)
        log.info("MGLRU watchdog stopped (PID %d)", _mglru_watchdog_pid)
    except ProcessLookupError:
        pass
    except OSError as e:
        # Process may have exited; try killing the main process
        try:
            os.kill(_mglru_watchdog_pid, signal.SIGKILL)
        except Exception:
            pass
    except Exception as e:
        log.warning("Could not stop MGLRU watchdog: %s", e)
    _mglru_watchdog_pid = None


def drop_page_cache():
    run_cmd(["sudo", "sync"])
    run_cmd(["sudo", "sh", "-c", "echo 3 > /proc/sys/vm/drop_caches"])
    log.info("Page cache dropped.")


def disable_mglru():
    """Disable MGLRU so the BPF evict_folios hook is the sole eviction decision maker."""
    global _mglru_original_value
    if os.path.exists(MGLRU_ENABLED_PATH):
        _mglru_original_value = open(MGLRU_ENABLED_PATH).read().strip()
        log.info("MGLRU current state: %s - disabling", _mglru_original_value)
        run_cmd(["sudo", "sh", "-c", f"echo 0 > {MGLRU_ENABLED_PATH}"])
        log.info("MGLRU disabled.")
    else:
        log.warning("MGLRU sysfs path not found: %s", MGLRU_ENABLED_PATH)


def enable_mglru():
    """Re-enable MGLRU after evaluation, restoring original value."""
    global _mglru_original_value
    if os.path.exists(MGLRU_ENABLED_PATH):
        restore = _mglru_original_value if _mglru_original_value else "0x0007"
        try:
            run_cmd(["sudo", "sh", "-c", f"echo {restore} > {MGLRU_ENABLED_PATH}"])
            log.info("MGLRU re-enabled (restored to %s).", restore)
        except Exception as e:
            log.warning("Failed to re-enable MGLRU: %s (try: echo %s > %s)", e, restore, MGLRU_ENABLED_PATH)


# -- Server Management ---------------------------------------------------------


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


# -- Policy Management ---------------------------------------------------------


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


def teardown_server_and_policy(server_proc, policy_proc):
    """Stop server and BPF policy. Server must stop before reset_database()."""
    stop_process(server_proc, "net_leveldb_server")
    stop_policy(policy_proc)


def prepare_fresh_benchmark_env(loader_path: str):
    """
    Recreate DB from LEVELDB_DB, drop page caches, cgroup, reload BPF, start server.
    Caller must have torn down any previous server/policy (teardown_server_and_policy).
    """
    reset_database()
    drop_page_cache()
    time.sleep(2)
    create_cgroup(CGROUP_SIZE_BYTES)
    policy_proc = start_policy(loader_path, LEVELDB_TEMP_DB)
    server_proc = start_server(LEVELDB_TEMP_DB, SERVER_PORT, CGROUP_NAME)
    return server_proc, policy_proc


# -- Benchmark -----------------------------------------------------------------


def reset_database():
    """
    Recreate temp DB from source via hardlinks (cp -al).

    Always rebuild from LEVELDB_DB so every evaluate() starts from the same
    on-disk snapshot. The previous behavior skipped copy when LEVELDB_TEMP_DB
    already existed, which reused a DB mutated by earlier benchmarks and made
    scores across reruns / evolution generations incomparable.
    """
    if os.path.lexists(LEVELDB_TEMP_DB):
        log.info("Removing %s for a fresh copy from %s", LEVELDB_TEMP_DB, LEVELDB_DB)
        shutil.rmtree(LEVELDB_TEMP_DB)
    # Use cp -al to hardlink all files - nearly instant even for large DBs.
    # Safe for LevelDB: it never modifies SST files in place, only creates/deletes.
    run_cmd(["cp", "-al", LEVELDB_DB, LEVELDB_TEMP_DB], timeout=120)
    log.info("Database hardlinked: %s -> %s", LEVELDB_DB, LEVELDB_TEMP_DB)


def run_benchmark(trace_config_path):
    """
    Run My-YCSB benchmark with a specific trace config.
    Returns parsed throughput/latency results dict.
    Raises on failure.
    """
    bench_binary = os.path.join(BENCH_BINARY_DIR, "run_net_leveldb")
    if not os.path.exists(bench_binary):
        raise FileNotFoundError(f"run_net_leveldb not found: {bench_binary}")

    cmd = [bench_binary, trace_config_path]
    log.info("Running benchmark: %s", " ".join(cmd))
    # Read timing from the config to set an appropriate timeout
    import yaml as pyyaml
    with open(trace_config_path, "r") as f:
        config = pyyaml.safe_load(f)
    warmup = config.get("workload", {}).get("warmup_runtime_seconds", WARMUP_SECONDS)
    runtime = config.get("workload", {}).get("runtime_seconds", RUNTIME_SECONDS)
    result = run_cmd(cmd, timeout=warmup + runtime + 120)
    stdout = result.stdout
    log.info("Benchmark stdout:\n%s", stdout[:2000])

    out = parse_benchmark_results(stdout)
    out["throughput_series_total_ops_per_sec"] = parse_epoch_throughput_series(stdout)
    return out


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


def parse_epoch_throughput_series(stdout: str) -> list[float]:
    """
    Parse My-YCSB 1Hz monitor lines into a throughput-over-time series.

    Keep only benchmark-phase lines (skip any line containing "Warm-Up").
    Example:
      "Zipfian (epoch 3, progress ...): ... total throughput 1700.12 ops/sec"
    """
    series: list[float] = []
    pat = re.compile(r"total throughput\s+(\d+(?:\.\d+)?)\s+ops/sec")
    for raw in stdout.splitlines():
        line = raw.strip()
        if "(epoch" not in line or "total throughput" not in line:
            continue
        if "Warm-Up" in line:
            continue
        m = pat.search(line)
        if not m:
            continue
        try:
            series.append(float(m.group(1)))
        except ValueError:
            continue
    return series


def latency_adjusted_trace_score(tp_mean: float, p99_ns_mean: float,
                                 lat_ref_ms: float) -> float:
    """Combine throughput with a smooth p99 penalty."""
    if tp_mean <= 0:
        return 0.0
    # If p99 is unavailable, fall back to throughput-only score.
    if p99_ns_mean <= 0 or lat_ref_ms <= 0:
        return tp_mean
    p99_ms = p99_ns_mean / 1e6
    return tp_mean / (1.0 + (p99_ms / lat_ref_ms))


# -- Dual-Client Benchmark ----------------------------------------------------


def start_proxy(listen_port, delay_ms, bandwidth_kbps):
    """Start a tcp_delay_proxy subprocess. Returns Popen."""
    cmd = [
        sys.executable, PROXY_SCRIPT,
        "--listen-port", str(listen_port),
        "--target-port", str(SERVER_PORT),
        "--delay-ms", str(delay_ms),
        "--bandwidth-kbps", str(bandwidth_kbps),
    ]
    log.info("Starting proxy: %s", " ".join(cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    if not wait_for_port("127.0.0.1", listen_port, timeout=10):
        if proc.poll() is not None:
            raise RuntimeError(f"Proxy on port {listen_port} exited immediately")
        raise RuntimeError(f"Proxy on port {listen_port} not ready after 10s")
    log.info("Proxy ready on port %d", listen_port)
    return proc


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


def remote_bench_command(bench_binary, remote_path):
    """Run benchmark. Skip cgexec - remote client cgroup often fails with
    'cgroup change of group failed' on worker nodes; eviction only needs
    the server in a cgroup."""
    return f"exec {bench_binary} {remote_path}"


def run_dual_client_benchmark(trace_config_dict):
    """
    Run a dual-client benchmark: two My-YCSB clients in parallel against
    the same server. Clients with a 'host' field are launched on that host
    via SSH; others run locally (optionally through delay proxies).
    Returns results dict with total_throughput (sum of both clients).
    """
    clients = trace_config_dict["clients"]
    proxy_procs = []
    # Each entry: (local_path, remote_host_or_None, remote_path_or_None)
    temp_files = []
    bench_binary = os.path.join(BENCH_BINARY_DIR, "run_net_leveldb")

    try:
        # Start proxies for local clients that need them
        for client in clients:
            if client.get("host"):
                continue
            proxy_port = client.get("proxy_port", 0)
            delay_ms = client.get("proxy_delay_ms", 0)
            bw_kbps = client.get("proxy_bandwidth_kbps", 0)
            if proxy_port > 0 and (delay_ms > 0 or bw_kbps > 0):
                proc = start_proxy(proxy_port, delay_ms, bw_kbps)
                proxy_procs.append(proc)

        # Ensure a shared client cgroup exists on each remote host.
        for host in {c.get("host") for c in clients if c.get("host")}:
            ensure_remote_client_cgroup(host)

        # Write temp config files and launch clients
        client_procs = []
        base_dir = trace_config_dict.get("_schedule_base_dir") or os.getcwd()
        for client in clients:
            config = copy.deepcopy(client["config"])
            wl = config.setdefault("workload", {})
            remote_host = client.get("host")
            rs = wl.get("rate_schedule_file")
            if rs:
                if os.path.isabs(rs):
                    local_sched = rs
                else:
                    local_sched = os.path.normpath(os.path.join(base_dir, rs))
                if not os.path.isfile(local_sched):
                    raise FileNotFoundError(
                        f"rate_schedule_file not found: {local_sched} (from {rs!r})"
                    )
                if remote_host:
                    remote_sched = (
                        f"/tmp/rate_sched_{client['name']}_{os.getpid()}_"
                        f"{random.randrange(1 << 30)}.csv"
                    )
                    scp_to_remote(local_sched, remote_host, remote_sched)
                    wl["rate_schedule_file"] = remote_sched
                else:
                    wl["rate_schedule_file"] = local_sched

            fd, local_path = tempfile.mkstemp(suffix=".yaml",
                                              prefix=f"dual_{client['name']}_")
            with os.fdopen(fd, 'w') as f:
                pyyaml.dump(config, f)

            if remote_host:
                remote_path = f"/tmp/{os.path.basename(local_path)}"
                scp_to_remote(local_path, remote_host, remote_path)
                temp_files.append((local_path, remote_host, remote_path))

                remote_cmd = remote_bench_command(
                    bench_binary,
                    remote_path,
                )
                cmd = ssh_shell_cmd(remote_host, remote_cmd)
                log.info("Starting remote client %s on %s: %s",
                         client["name"], remote_host, " ".join(cmd))
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True)
            else:
                temp_files.append((local_path, None, None))
                cmd = [bench_binary, local_path]
                log.info("Starting local client %s: %s",
                         client["name"], " ".join(cmd))
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True)

            client_procs.append((client["name"], proc))

        # Wait for all clients to finish
        max_timeout = max(
            c["config"]["workload"].get("warmup_runtime_seconds", WARMUP_SECONDS) +
            c["config"]["workload"].get("runtime_seconds", RUNTIME_SECONDS)
            for c in clients
        ) + 120

        results_per_client = {}
        for name, proc in client_procs:
            stdout_buf = []
            stderr_buf = []

            def capture_output(pipe, buf):
                try:
                    for line in iter(pipe.readline, ""):
                        buf.append(line)
                except Exception:
                    pass
                try:
                    pipe.close()
                except Exception:
                    pass

            stdout_reader = None
            stderr_reader = None
            if proc.stdout:
                stdout_reader = threading.Thread(
                    target=capture_output, args=(proc.stdout, stdout_buf)
                )
                stdout_reader.daemon = True
                stdout_reader.start()
            if proc.stderr:
                stderr_reader = threading.Thread(
                    target=capture_output, args=(proc.stderr, stderr_buf)
                )
                stderr_reader.daemon = True
                stderr_reader.start()

            try:
                proc.wait(timeout=max_timeout)
                if stdout_reader:
                    stdout_reader.join(timeout=2)
                if stderr_reader:
                    stderr_reader.join(timeout=2)
                stdout = "".join(stdout_buf)
                stderr = "".join(stderr_buf)

                if proc.returncode != 0:
                    log.error("Client %s failed (rc=%d): %s",
                              name, proc.returncode, stderr[:500])
                    results_per_client[name] = {"total_throughput": 0.0}
                else:
                    parsed = parse_benchmark_results(stdout)
                    parsed["throughput_series_total_ops_per_sec"] = parse_epoch_throughput_series(stdout)
                    results_per_client[name] = parsed
                    log.info("Client %s: throughput=%.2f", name,
                             results_per_client[name].get("total_throughput", 0))
            except subprocess.TimeoutExpired:
                proc.kill()
                if stdout_reader:
                    stdout_reader.join(timeout=2)
                if stderr_reader:
                    stderr_reader.join(timeout=2)
                stdout = "".join(stdout_buf)
                stderr = "".join(stderr_buf)
                log.error("Client %s timed out", name)
                partial = (
                    f"=== Client {name} TIMEOUT - partial stdout ===\n"
                    f"{stdout[-5000:] if stdout else '(none)'}\n"
                    f"=== Client {name} TIMEOUT - partial stderr ===\n"
                    f"{stderr[-2500:] if stderr else '(none)'}\n"
                )
                log.error("Client %s partial output:\n%s", name, partial[:3500])
                # Save full partial output for debugging (caller can pass results_dir)
                if trace_config_dict.get("_debug_results_dir"):
                    try:
                        path = Path(trace_config_dict["_debug_results_dir"]) / "client_timeout_debug.txt"
                        path.write_text(partial, encoding="utf-8")
                        log.info("Saved timeout debug output to %s", path)
                    except Exception as ex:
                        log.warning("Could not save debug output: %s", ex)
                results_per_client[name] = {"total_throughput": 0.0}

        # Combine: sum throughputs from all clients
        total_tp = sum(r.get("total_throughput", 0.0)
                       for r in results_per_client.values())
        combined = {"total_throughput": total_tp}

        # Combine epoch throughput series: sum per-epoch across clients (align by index)
        series_per_client = [
            r.get("throughput_series_total_ops_per_sec", [])
            for r in results_per_client.values()
            if isinstance(r.get("throughput_series_total_ops_per_sec", None), list)
        ]
        if series_per_client:
            min_len = min(len(s) for s in series_per_client)
            if min_len > 0:
                combined["throughput_series_total_ops_per_sec"] = [
                    sum(float(s[i]) for s in series_per_client) for i in range(min_len)
                ]
        # Keep per-client achieved throughput-over-time for feedback/analysis.
        per_client_series = {}
        for client_name, r in results_per_client.items():
            s = r.get("throughput_series_total_ops_per_sec")
            if isinstance(s, list) and s:
                per_client_series[client_name] = [float(v) for v in s]
        if per_client_series:
            combined["per_client_throughput_series_total_ops_per_sec"] = per_client_series

        # Aggregate p99: worst (max) across clients
        p99s = [r.get("read_latency_p99_ns", 0)
                for r in results_per_client.values() if "read_latency_p99_ns" in r]
        if p99s:
            combined["read_latency_p99_ns"] = max(p99s)

        log.info("Dual-client combined throughput: %.2f ops/sec", total_tp)
        return combined

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


# -- Main Evaluation -----------------------------------------------------------


# Serialization lock - only one evaluate() may run at a time regardless of
# how many parallel evaluate.py processes ShinkaEvolve spawns.
EVAL_LOCK_PATH = f"/tmp/cache_ext_evaluate_{os.getuid()}.lock"


def evaluate(program_path: str, results_dir: str, debug: bool = False,
             policy_name: str | None = None):
    """
    Full evaluation pipeline:
      [optional initial DB reset] -> [compile if evolved] -> disable MGLRU ->
      (either one cgroup+policy+server for the suite, or fresh cgroup+policy+server
      before each benchmark run when RESET_ENV_EVERY_RUN) -> benchmarks -> cleanup

    If policy_name is given, use pre-built loader from policies/ (cache_ext_{policy_name}.out) and skip compilation.
    If debug=True: run 1 trace, 1 run, shorter warmup/runtime for faster iteration.
    """
    # Acquire exclusive lock FIRST. If we checked MGLRU before the lock, a second
    # process starting while another holds the lock (and has MGLRU disabled) would
    # see MGLRU disabled and exit with "reboot" - even though the running process
    # will restore it. By acquiring the lock first, we block until the previous run
    # finishes and restores MGLRU; then we're the only runner and can safely check.
    lock_fd = open(EVAL_LOCK_PATH, "w")
    log.info("Waiting for evaluation lock %s ...", EVAL_LOCK_PATH)
    fcntl.flock(lock_fd, fcntl.LOCK_EX)  # blocks until previous run finishes
    log.info("Acquired evaluation lock.")

    # CRITICAL: Now check MGLRU. If a previous run was killed, MGLRU stays disabled.
    # The kernel reclaims aggressively - sudo may segfault. Only the lock holder
    # runs this check; others block until we (or a previous run) finish.
    if os.path.exists(MGLRU_ENABLED_PATH):
        try:
            current_mglru = open(MGLRU_ENABLED_PATH).read().strip()
        except OSError:
            current_mglru = "?"
        if current_mglru in ("0x0000", "0"):
            log.error(
                "MGLRU is DISABLED (left by a killed experiment). "
                "The system is in severe memory pressure - sudo will segfault. "
                "REBOOT the machine to restore MGLRU, then rerun."
            )
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            lock_fd.close()
            raise SystemExit(
                "MGLRU disabled. Reboot to fix. See stderr for details."
            )

    server_proc = None
    policy_proc = None
    mglru_disabled = False

    try:
        # Guard: if a previous run was killed, re-enable MGLRU and clean up.
        if os.path.exists(MGLRU_ENABLED_PATH):
            try:
                current_mglru = open(MGLRU_ENABLED_PATH).read().strip()
            except OSError:
                current_mglru = ""
            if current_mglru in ("0x0000", "0"):
                log.warning("MGLRU was left disabled by a previous killed run - re-enabling now")
                enable_mglru()
            # Also clean up any orphaned cgroup or server from a killed run
            delete_cgroup()

        # 0. Optional one-time DB reclone + drop cache (skipped when per-run reset handles it).
        log.info("=== Step 0: Initial environment ===")
        if not RESET_ENV_EVERY_RUN:
            reset_database()
            drop_page_cache()
        else:
            log.info(
                "Per-run reset enabled (CACHE_EXT_RESET_EVERY_RUN): "
                "each benchmark will reclone DB, drop caches, reload BPF, restart server."
            )

        # 1. Get loader: pre-built policy or compile evolved
        if policy_name:
            loader_path = os.path.join(POLICIES_DIR, f"cache_ext_{policy_name}.out")
            if not os.path.exists(loader_path):
                raise FileNotFoundError(
                    f"Pre-built policy not found: {loader_path}. Run 'make -C {POLICIES_DIR}' first."
                )
            log.info("=== Step 1: Using pre-built policy %s ===", loader_path)
        else:
            log.info("=== Step 1: Compile evolved policy ===")
            loader_path = compile_bpf_policy(program_path, BUILD_DIR)

        # 2. Disable MGLRU so BPF evict_folios is the sole eviction decision maker.
        #    Without this, the kernel routes cgroup reclaim through MGLRU directly,
        #    never calling our BPF hook, and evict_folios never fires.
        #    Start watchdog first: if we're killed, a root process will restore MGLRU.
        log.info("=== Step 2: Disable MGLRU ===")
        _start_mglru_watchdog(debug)
        disable_mglru()
        mglru_disabled = True

        # 3–5. Cgroup + BPF + server (once per suite, or before each run below)
        if not RESET_ENV_EVERY_RUN:
            log.info("=== Step 3: Create cgroup ===")
            create_cgroup(CGROUP_SIZE_BYTES)
            log.info("=== Step 4: Load BPF policy ===")
            policy_proc = start_policy(loader_path, LEVELDB_TEMP_DB)
            log.info("=== Step 5: Start server ===")
            server_proc = start_server(LEVELDB_TEMP_DB, SERVER_PORT, CGROUP_NAME)
        else:
            log.info(
                "=== Steps 3–5: Deferred — cgroup/policy/server start before each benchmark ==="
            )

        # 6. Run all trace benchmarks
        if debug:
            log.info("=== Step 6: DEBUG mode - 1 trace x 1 run (short warmup/runtime) ===")
        else:
            log.info("=== Step 6: Run %d traces x %d runs = %d total benchmarks ===",
                     len(TRACE_CONFIGS), RUNS_PER_TRACE,
                     len(TRACE_CONFIGS) * RUNS_PER_TRACE)
        all_trace_results = {}
        public_metrics = {}
        run_counter = 0

        trace_configs = TRACE_CONFIGS[:1] if debug else TRACE_CONFIGS
        runs_per_trace = 1 if debug else RUNS_PER_TRACE
        total_runs = len(trace_configs) * runs_per_trace

        for trace_idx, (trace_name, trace_file) in enumerate(trace_configs):
            trace_path = os.path.join(TRACES_DIR, trace_file)
            if trace_idx == 0 and not RESET_ENV_EVERY_RUN:
                log.info(
                    "First trace (%s): runs right after fresh leveldb_temp + policy load; "
                    "throughput is often lower than the same trace later in a long suite "
                    "(cold page cache / DB churn vs warmed session).",
                    trace_name,
                )

            with open(trace_path, 'r') as _tf:
                trace_yaml = pyyaml.safe_load(_tf)
            is_dual = trace_yaml.get("type") == "dual_client"

            if debug and is_dual:
                for c in trace_yaml.get("clients", []):
                    wl = c.get("config", {}).get("workload", {})
                    wl["warmup_runtime_seconds"] = 10
                    wl["runtime_seconds"] = 30
                    wl["nr_op"] = 500000
                log.info("Debug mode: shortened warmup=10s runtime=30s nr_op=500k")

            runs = []
            for run_idx in range(runs_per_trace):
                run_counter += 1
                log.info("--- Trace %d/%d (%s) run %d/%d  [%d/%d overall] ---",
                         trace_idx + 1, len(trace_configs), trace_name,
                         run_idx + 1, runs_per_trace, run_counter, total_runs)

                if RESET_ENV_EVERY_RUN:
                    log.info(
                        "Full environment reset before this run "
                        "(stop server, reclone DB, drop caches, cgroup, BPF, server) ..."
                    )
                    teardown_server_and_policy(server_proc, policy_proc)
                    server_proc, policy_proc = prepare_fresh_benchmark_env(loader_path)
                else:
                    drop_page_cache()
                    time.sleep(2)

                try:
                    if is_dual:
                        trace_yaml["_debug_results_dir"] = results_dir
                        trace_yaml["_schedule_base_dir"] = os.path.dirname(trace_path)
                        run_result = run_dual_client_benchmark(trace_yaml)
                    else:
                        run_result = run_benchmark(trace_path)
                    tp = run_result.get("total_throughput", 0.0)
                    log.info("Trace %s run %d: throughput=%.2f ops/sec",
                             trace_name, run_idx + 1, tp)
                except Exception as te:
                    log.error("Trace %s run %d failed: %s", trace_name, run_idx + 1, te)
                    run_result = {"total_throughput": 0.0, "error": str(te)}
                runs.append(run_result)

            # Compute per-trace statistics across runs
            tps = [r.get("total_throughput", 0.0) for r in runs]
            p99s = [r.get("read_latency_p99_ns", 0.0) for r in runs
                    if "read_latency_p99_ns" in r]
            series_runs = [
                r.get("throughput_series_total_ops_per_sec", [])
                for r in runs
                if isinstance(r.get("throughput_series_total_ops_per_sec", None), list)
            ]
            per_client_series_runs: dict[str, list[list[float]]] = {}
            for r in runs:
                pcs = r.get("per_client_throughput_series_total_ops_per_sec")
                if not isinstance(pcs, dict):
                    continue
                for client_name, series in pcs.items():
                    if not isinstance(series, list):
                        continue
                    per_client_series_runs.setdefault(client_name, []).append(
                        [float(v) for v in series]
                    )

            tp_mean = statistics.mean(tps)
            tp_std = statistics.stdev(tps) if len(tps) > 1 else 0.0
            tp_min = min(tps)
            tp_max = max(tps)
            p99_mean = statistics.mean(p99s) if p99s else 0.0
            series_mean: list[float] = []
            if series_runs:
                min_len = min(len(s) for s in series_runs)
                if min_len > 0:
                    series_mean = [
                        statistics.mean(float(s[i]) for s in series_runs)
                        for i in range(min_len)
                    ]
            per_client_series_mean: dict[str, list[float]] = {}
            for client_name, series_list in per_client_series_runs.items():
                if not series_list:
                    continue
                min_len = min(len(s) for s in series_list)
                if min_len <= 0:
                    continue
                per_client_series_mean[client_name] = [
                    statistics.mean(float(s[i]) for s in series_list)
                    for i in range(min_len)
                ]

            trace_summary = {
                "runs": runs,
                "throughput_mean": tp_mean,
                "throughput_std": tp_std,
                "throughput_min": tp_min,
                "throughput_max": tp_max,
                "throughput_cv": (tp_std / tp_mean * 100) if tp_mean > 0 else 0.0,
                "read_p99_ns_mean": p99_mean,
                "throughput_series_total_ops_per_sec_mean": series_mean,
                "per_client_throughput_series_total_ops_per_sec_mean": per_client_series_mean,
            }
            all_trace_results[trace_name] = trace_summary

            public_metrics[f"{trace_name}_throughput_mean"] = tp_mean
            public_metrics[f"{trace_name}_throughput_std"] = tp_std
            public_metrics[f"{trace_name}_throughput_min"] = tp_min
            public_metrics[f"{trace_name}_throughput_max"] = tp_max
            public_metrics[f"{trace_name}_read_p99_ns_mean"] = p99_mean
            if series_mean:
                cap = int(os.environ.get("CACHE_EXT_PUBLIC_TP_SERIES_MAX", "120"))
                cap = min(cap, len(series_mean))
                public_metrics[f"{trace_name}_throughput_series_mean"] = [
                    round(v, 2) for v in series_mean[:cap]
                ]
            if per_client_series_mean:
                cap = int(os.environ.get("CACHE_EXT_PUBLIC_TP_SERIES_MAX", "120"))
                for client_name, cseries in per_client_series_mean.items():
                    n = min(cap, len(cseries))
                    public_metrics[
                        f"{trace_name}_{client_name}_throughput_series_mean"
                    ] = [round(v, 2) for v in cseries[:n]]
            if PUBLIC_PER_RUN_STATS:
                cap = min(len(runs), PUBLIC_PER_RUN_MAX)
                tp_per_run = []
                p99_ms_per_run = []
                for i in range(cap):
                    r = runs[i]
                    tp_per_run.append(
                        round(float(r.get("total_throughput", 0.0)), 2)
                    )
                    p99v = r.get("read_latency_p99_ns")
                    if p99v is not None:
                        p99_ms_per_run.append(round(float(p99v) / 1e6, 2))
                    else:
                        p99_ms_per_run.append(0.0)
                public_metrics[f"{trace_name}_per_run_throughput"] = tp_per_run
                public_metrics[f"{trace_name}_per_run_read_p99_ms"] = p99_ms_per_run
            log.info("Trace %s summary: mean=%.2f std=%.2f min=%.2f max=%.2f (CV=%.1f%%)",
                     trace_name, tp_mean, tp_std, tp_min, tp_max,
                     trace_summary["throughput_cv"])

        # 7. Combined score = harmonic mean of per-trace **mean throughput** (optimization objective).
        #    Latency-adjusted harmonic mean is computed only as a diagnostic (see LAT_REF_MS).
        mean_throughputs = []
        latency_adjusted_scores = []
        for trace_name, _ in TRACE_CONFIGS:
            trace_result = all_trace_results.get(trace_name, {})
            tp_mean = trace_result.get("throughput_mean", 0.0)
            p99_mean = trace_result.get("read_p99_ns_mean", 0.0)
            mean_throughputs.append(tp_mean)
            trace_score = latency_adjusted_trace_score(tp_mean, p99_mean, LAT_REF_MS)
            latency_adjusted_scores.append(trace_score)
            trace_result["latency_adjusted_score"] = trace_score
            trace_result["lat_ref_ms"] = LAT_REF_MS

        nonzero_tps = [t for t in mean_throughputs if t > 0]
        if len(nonzero_tps) == len(mean_throughputs) and len(mean_throughputs) > 0:
            throughput_harmonic_mean = len(mean_throughputs) / sum(
                1.0 / t for t in mean_throughputs
            )
        elif len(nonzero_tps) > 0:
            hm_partial = len(nonzero_tps) / sum(1.0 / t for t in nonzero_tps)
            throughput_harmonic_mean = hm_partial * (len(nonzero_tps) / len(mean_throughputs))
        else:
            throughput_harmonic_mean = 0.0

        nonzero_latency_scores = [s for s in latency_adjusted_scores if s > 0]
        if (
            len(nonzero_latency_scores) == len(latency_adjusted_scores)
            and len(latency_adjusted_scores) > 0
        ):
            latency_adjusted_harmonic_mean = len(latency_adjusted_scores) / sum(
                1.0 / s for s in latency_adjusted_scores
            )
        elif len(nonzero_latency_scores) > 0:
            hm_partial = len(nonzero_latency_scores) / sum(
                1.0 / s for s in nonzero_latency_scores
            )
            latency_adjusted_harmonic_mean = hm_partial * (
                len(nonzero_latency_scores) / len(latency_adjusted_scores)
            )
        else:
            latency_adjusted_harmonic_mean = 0.0

        combined_score = throughput_harmonic_mean
        public_metrics["lat_ref_ms"] = LAT_REF_MS
        public_metrics["combined_score_harmonic_mean_throughput_only"] = throughput_harmonic_mean
        public_metrics["combined_score_harmonic_mean_latency_adjusted"] = latency_adjusted_harmonic_mean
        public_metrics["traces_passed"] = len(nonzero_tps)
        public_metrics["traces_total"] = len(mean_throughputs)
        public_metrics["runs_per_trace"] = runs_per_trace
        public_metrics["reset_env_every_run"] = RESET_ENV_EVERY_RUN

        metrics = {
            "combined_score": combined_score,
            "public": public_metrics,
            "private": all_trace_results,
        }

        save_results(results_dir, metrics, correct=True, error_msg=None)
        log.info("=== Evaluation complete (%d runs per trace) ===", runs_per_trace)
        log.info(
            "Combined score (throughput harmonic mean): %.2f  (%d/%d traces passed)",
            combined_score,
            len(nonzero_tps),
            len(mean_throughputs),
        )
        log.info(
            "Diagnostic: latency-adjusted harmonic mean (LAT_REF_MS=%.1f): %.2f",
            LAT_REF_MS,
            latency_adjusted_harmonic_mean,
        )
        for trace_name, _ in TRACE_CONFIGS:
            ts = all_trace_results.get(trace_name, {})
            log.info(
                "  %s: mean=%.2f std=%.2f [%.2f .. %.2f] p99=%.2fms score=%.2f",
                trace_name,
                ts.get("throughput_mean", 0),
                ts.get("throughput_std", 0),
                ts.get("throughput_min", 0),
                ts.get("throughput_max", 0),
                ts.get("read_p99_ns_mean", 0) / 1e6,
                ts.get("latency_adjusted_score", 0),
            )

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
        _stop_mglru_watchdog()  # always stop; we started it before disable_mglru
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
        help="Path to the evolved .c file (required if --policy_name not given)",
    )
    parser.add_argument(
        "--policy_name",
        type=str,
        help="Pre-built policy name (fifo, lhd, mglru, mru, s3fifo, sampling). Skips compilation.",
    )
    parser.add_argument(
        "--results_dir",
        type=str,
        required=True,
        help="Directory to write metrics.json and correct.json",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Debug mode: 1 trace, 1 run, shorter warmup/runtime, capture timeout output",
    )
    args = parser.parse_args()
    if args.policy_name and args.program_path:
        parser.error("Give only one of --program_path or --policy_name")
    if not args.policy_name and not args.program_path:
        parser.error("Give --program_path or --policy_name")
    evaluate(
        args.program_path or "",
        args.results_dir,
        debug=args.debug,
        policy_name=args.policy_name,
    )


if __name__ == "__main__":
    main()
