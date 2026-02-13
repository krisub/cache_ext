import socket
import time
import csv
import threading
import random
import struct
from collections import Counter

SERVER_IP = "127.0.0.1"
PORT_A = 9001 # DB A
PORT_B = 9002 # DB B
DURATION_SECONDS = 180 # experiment duration  
SWITCH_INTERVAL = 5 # switch between DBs every 5 seconds         
CSV_FILE = "data/mglru_HALFGB_reaccess50.csv"
NUM_THREADS = 8 
BYTES_PER_REQ = 1048576 # 1MB read per request

NUM_KEYS = 500000
KEYS_PER_SCAN = 256
REACCESS_PROB = 0.50        # p: fraction of requests that are "reaccess" instead of sequential
                            # 20% of requests are reaccess, sampled from normal distribution
HOT_MU = NUM_KEYS // 2        # center of hot region (key id) (center of key range)
HOT_SIGMA = int(NUM_KEYS * 0.10)  # spread of hot region (10% of keys)
BASE_SEED = 12345            # for reproducibility

# data collection
global_bytes = 0
global_reqs = 0
global_latency_ns_sum = 0
global_latency_samples_ns = []
global_connect_errors = 0
global_io_errors = 0


# track scan start keys, checking if reaccess is happening
ENABLE_ACCESS_TRACE = False # true to stop tracking
ACCESS_TRACE_CSV = "data/access_trace.csv"  # per-request (time-ordered) trace
ACCESS_COUNTS_CSV = "data/access_start_id_counts.csv"  # aggregated counts at end
global_start_id_counts = {"A": Counter(), "B": Counter()}
global_access_trace_events = []  # (Time_Sec, DB, StartId, IsReaccess, CumulativeCountForStartId)
lock = threading.Lock()

MAX_LAT_SAMPLES_PER_INTERVAL = 20000  
FLUSH_EVERY_REQS = 8  # flush often so 0.5s windows don't show zeros

def _clamp_start_id(x: int) -> int:
    lo = 0
    hi = NUM_KEYS - KEYS_PER_SCAN
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x


def worker(target_port, stop_event, thread_idx: int, phase_id: int, start_time_global: float):
    global global_bytes, global_reqs, global_latency_ns_sum, global_latency_samples_ns
    global global_connect_errors, global_io_errors
    global global_start_id_counts, global_access_trace_events
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((SERVER_IP, target_port))

        db_label = "A" if target_port == PORT_A else "B"
        rng = random.Random(BASE_SEED + phase_id * 1000 + thread_idx)
        seq_cursor = _clamp_start_id(thread_idx * KEYS_PER_SCAN)
        local_reqs = 0
        local_bytes = 0
        local_latency_ns_sum = 0
        local_latency_samples_ns = []
        local_access_events = []  # (time_sec, start_id, is_reaccess_int)

        while not stop_event.is_set():
            try:
                # should this request be a reaccess
                is_reaccess = (rng.random() < REACCESS_PROB)
                if is_reaccess:
                    # sample a random key in the hot region
                    start_id = int(rng.normalvariate(HOT_MU, HOT_SIGMA))
                    start_id = _clamp_start_id(start_id)
                else:
                    # sequential scan from seq_cursor to seq_cursor + KEYS_PER_SCAN
                    # from the key we last left off on)
                    start_id = seq_cursor
                    seq_cursor += KEYS_PER_SCAN
                    if seq_cursor > (NUM_KEYS - KEYS_PER_SCAN):
                        seq_cursor = 0

                req = struct.pack("!4sI", b"SCAN", start_id) # send the request to the server with the start_id
                # metrics
                t0 = time.perf_counter_ns()
                s.sendall(req)
                resp = s.recv(1024)
                t1 = time.perf_counter_ns()
                if not resp: break
                lat = t1 - t0
                local_reqs += 1
                local_bytes += BYTES_PER_REQ
                local_latency_ns_sum += lat
         
                local_latency_samples_ns.append(lat)
                if ENABLE_ACCESS_TRACE:
                    local_access_events.append(
                        (time.time() - start_time_global, start_id, int(is_reaccess))
                    )

                # write metrics
                if local_reqs >= FLUSH_EVERY_REQS:
                    with lock:
                        global_bytes += local_bytes
                        global_reqs += local_reqs
                        global_latency_ns_sum += local_latency_ns_sum
                        remaining = MAX_LAT_SAMPLES_PER_INTERVAL - len(global_latency_samples_ns)
                        if remaining > 0 and local_latency_samples_ns:
                            global_latency_samples_ns.extend(local_latency_samples_ns[:remaining])
                        if ENABLE_ACCESS_TRACE and local_access_events:
                            cnt = global_start_id_counts[db_label]
                            for ts, sid, reacc in local_access_events:
                                cnt[sid] += 1
                                global_access_trace_events.append((ts, db_label, sid, reacc, cnt[sid]))
                    local_reqs = 0
                    local_bytes = 0
                    local_latency_ns_sum = 0
                    local_latency_samples_ns.clear()
                    local_access_events.clear()
            except:
                with lock:
                    global_io_errors += 1
                break


        if local_reqs or local_bytes or local_latency_ns_sum or local_latency_samples_ns or local_access_events:
            with lock:
                global_bytes += local_bytes
                global_reqs += local_reqs
                global_latency_ns_sum += local_latency_ns_sum
                remaining = MAX_LAT_SAMPLES_PER_INTERVAL - len(global_latency_samples_ns)
                if remaining > 0 and local_latency_samples_ns:
                    global_latency_samples_ns.extend(local_latency_samples_ns[:remaining])
                if ENABLE_ACCESS_TRACE and local_access_events:
                    cnt = global_start_id_counts[db_label]
                    for ts, sid, reacc in local_access_events:
                        cnt[sid] += 1
                        global_access_trace_events.append((ts, db_label, sid, reacc, cnt[sid]))
        s.close()
    except:
        with lock:
            global_connect_errors += 1

def run_phase(target_port, duration, writer, start_time_global, phase_id: int):
    global global_bytes, global_reqs, global_latency_ns_sum, global_latency_samples_ns
    global global_connect_errors, global_io_errors
    global_bytes = 0
    global_reqs = 0
    global_latency_ns_sum = 0
    global_latency_samples_ns = []
    global_connect_errors = 0
    global_io_errors = 0
    stop_event = threading.Event()
    threads = []
    
    for thread_idx in range(NUM_THREADS):
        t = threading.Thread(
            target=worker, args=(target_port, stop_event, thread_idx, phase_id, start_time_global)
        )
        t.start()
        threads.append(t)
    
    phase_end = time.time() + duration
    last_check = time.time()
    
    while time.time() < phase_end:
        time.sleep(0.5)
        now = time.time()
        
        with lock:
            current_bytes = global_bytes
            global_bytes = 0 
            current_reqs = global_reqs
            global_reqs = 0
            current_lat_ns_sum = global_latency_ns_sum
            global_latency_ns_sum = 0
            lat_samples_ns = global_latency_samples_ns
            global_latency_samples_ns = []
            connect_errs = global_connect_errors
            global_connect_errors = 0
            io_errs = global_io_errors
            global_io_errors = 0
            
        dt = now - last_check
        mb_per_sec = (current_bytes / (1024 * 1024)) / dt
        ops_per_sec = (current_reqs / dt) if dt > 0 else 0.0
        lat_avg_ms = (
            (current_lat_ns_sum / current_reqs) / 1e6 if current_reqs > 0 else 0.0
        )
        if lat_samples_ns:
            lat_samples_ns.sort()
            idx = int(0.99 * (len(lat_samples_ns) - 1))
            lat_p99_ms = lat_samples_ns[idx] / 1e6
        else:
            lat_p99_ms = 0.0

        elapsed = now - start_time_global
        active_db = "A" if target_port == PORT_A else "B"
        
        writer.writerow(
            [
                f"{elapsed:.2f}",
                active_db,
                f"{mb_per_sec:.2f}",
                f"{ops_per_sec:.2f}",
                f"{lat_avg_ms:.3f}",
                f"{lat_p99_ms:.3f}",
                str(len(lat_samples_ns)),
                str(connect_errs),
                str(io_errs),
            ]
        )
        print(
            f"[{elapsed:.1f}s] DB {active_db} SCAN "
            f"{mb_per_sec:.2f} MB/s, {ops_per_sec:.2f} ops/s, "
            f"lat_avg {lat_avg_ms:.3f} ms, lat_p99 {lat_p99_ms:.3f} ms "
            f"(n={len(lat_samples_ns)}, conn_errs={connect_errs}, io_errs={io_errs})"
        )
        
        last_check = now

    stop_event.set()
    for t in threads:
        t.join()

print(f"Starting Scan Benchmark (1MB I/O per Req)...")
with open(CSV_FILE, "w", newline='') as f:
    writer = csv.writer(f)
    writer.writerow(
        [
            "Time_Sec",
            "Active_DB",
            "Throughput_MBps",
            "OpsPerSec",
            "LatencyAvg_ms",
            "LatencyP99_ms",
            "LatencySamples",
            "ConnectErrors",
            "IoErrors",
        ]
    )
    
    start_time_global = time.time()
    phase_id = 0
    
    # run and switch between DBs every SWITCH_INTERVAL seconds
    while (time.time() - start_time_global) < DURATION_SECONDS:
        if (time.time() - start_time_global) < DURATION_SECONDS:
            run_phase(PORT_A, SWITCH_INTERVAL, writer, start_time_global, phase_id)
            phase_id += 1 
            
        if (time.time() - start_time_global) < DURATION_SECONDS:
            run_phase(PORT_B, SWITCH_INTERVAL, writer, start_time_global, phase_id)
            phase_id += 1

if ENABLE_ACCESS_TRACE:
    with lock:
        events = list(global_access_trace_events)
        counts_a = global_start_id_counts["A"].copy()
        counts_b = global_start_id_counts["B"].copy()

    events.sort(key=lambda x: x[0])
    with open(ACCESS_TRACE_CSV, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Time_Sec", "DB", "StartId", "IsReaccess", "CumulativeCountForStartId"])
        w.writerows(events)

    with open(ACCESS_COUNTS_CSV, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["DB", "StartId", "Count"])
        for db, counts in (("A", counts_a), ("B", counts_b)):
            for sid, cnt in counts.most_common():
                w.writerow([db, sid, cnt])