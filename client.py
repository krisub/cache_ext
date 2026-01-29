import socket
import time
import os
import csv

SERVER_IP = "127.0.0.1"
PORT_A = 9001
PORT_B = 9002
DURATION_SECONDS = 180       
SWITCH_INTERVAL = 15         
CSV_FILE = "network_results.csv"

def metrics(target_port, duration, writer, start_time_global):
    end_time = time.time() + duration
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_IP, target_port))
        
        # 4KB payload
        payload = os.urandom(4096) 
        
        bytes_sent_interval = 0
        last_measure_time = time.time()
        
        while time.time() < end_time:
            try:
                s.sendall(payload)
                bytes_sent_interval += len(payload)
            except BrokenPipeError:
                break
            
            now = time.time()
            if now - last_measure_time >= 0.5:
                mb_per_sec = (bytes_sent_interval / (1024*1024)) / (now - last_measure_time)
                elapsed = now - start_time_global
                
                active_db = "A" if target_port == PORT_A else "B"
                
                writer.writerow([f"{elapsed:.2f}", active_db, f"{mb_per_sec:.2f}"])
                print(f"[{elapsed:.1f}s] DB {active_db}: {mb_per_sec:.2f} MB/s")
                
                bytes_sent_interval = 0
                last_measure_time = now
                
        s.close()
    except Exception as e:
        print(f"Error connecting to {target_port}: {e}")


print(f"Starting Benchmark for {DURATION_SECONDS} seconds...")
print(f"Saving results to {CSV_FILE}")

with open(CSV_FILE, "w", newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["Time_Sec", "Active_DB", "Throughput_MBps"])
    
    start_time_global = time.time()
    
    while (time.time() - start_time_global) < DURATION_SECONDS:
        if (time.time() - start_time_global) < DURATION_SECONDS:
            metrics(PORT_A, SWITCH_INTERVAL, writer, start_time_global)
            
        if (time.time() - start_time_global) < DURATION_SECONDS:
            metrics(PORT_B, SWITCH_INTERVAL, writer, start_time_global)