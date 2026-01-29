import subprocess
import time
import os
import threading
import csv

TARGET_CGROUP = "/sys/fs/cgroup/cache_ext_test"
INITIAL_SIZE = 10 * 1073741824 # 10GB
TARGET_SIZE = 1073741824   # 1GB
RESULTS_FILE = "resize_results.csv"
LOG_FILE = "bench_log.txt"

def get_eviction_count():
    try:
        with open(f"{TARGET_CGROUP}/memory.stat", 'r') as f:
            for line in f:
                if line.startswith("file "): 
                    return int(line.split()[1])
    except:
        return 0
    return 0

def resize_cgroup(size_bytes):
    print(f"\n[Script] TRIGGERING RESIZE -> {size_bytes / (1024*1024):.0f}MB")
    start = time.time()
    subprocess.run(f"echo {size_bytes} | sudo tee {TARGET_CGROUP}/memory.max", shell=True, stdout=subprocess.DEVNULL)
    duration = time.time() - start
    print(f"[Script] Resize command took {duration:.4f}s")

def wait_for_cgroup_activity():
    print(f"[Script] Waiting for cgroup {TARGET_CGROUP} to appear...")
    while True:
        if os.path.exists(TARGET_CGROUP):
            try:
                with open(f"{TARGET_CGROUP}/cgroup.procs", "r") as f:
                    if f.read().strip():
                        print("[Script] Cgroup active! Benchmark has started.")
                        return
            except:
                pass
        time.sleep(0.5)

def monitor_loop(stop_event):
    print(f"[Script] logging data to {RESULTS_FILE}...")
    start_time = time.time()
    
    with open(RESULTS_FILE, "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Time_Sec", "Evictions_Cumulative"])
        
        while not stop_event.is_set():
            count = get_eviction_count()
            writer.writerow([f"{time.time() - start_time:.2f}", count])
            csvfile.flush()
            time.sleep(0.5)

print(f"[Script] Starting LevelDB Benchmark (Logs -> {LOG_FILE})")
with open(LOG_FILE, "w") as log_out:
    bench_cmd = [
        "sudo", "python3", "bench/bench_leveldb.py",
        "--cpu", "8",
        "--policy-loader", "policies/cache_ext_fifo.out",
        "--results-file", "results/cgroup_testing.json",
        "--leveldb-db", "/mydata/leveldb",
        "--bench-binary-dir", "My-YCSB/build",
        "--benchmark", "ycsb_a",
        "--iterations", "1"
    ]
    proc = subprocess.Popen(bench_cmd, stdout=log_out, stderr=subprocess.STDOUT)

wait_for_cgroup_activity()

stop_event = threading.Event()
monitor = threading.Thread(target=monitor_loop, args=(stop_event,))
monitor.start()

print("[Script] Allow 60s for warmup...")
time.sleep(60)

resize_cgroup(TARGET_SIZE)

time.sleep(30)


stop_event.set()
monitor.join()
proc.wait()