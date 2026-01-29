import sys
import time
import signal
from bench_lib import CacheExtPolicy, recreate_cache_ext_cgroup

# sudo python3 load_policy.py <policy_file.out>
# sudo python3 load_policy.py policies/cache_ext_net.out

CGROUP_NAME = "cache_ext_test"
CGROUP_SIZE = 536870912 # 512MB

def signal_handler(sig, frame):
    print("\nUnloading policy...")
    policy.stop()
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 load_policy.py <path_to_policy.out>")
        sys.exit(1)

    policy_path = sys.argv[1]
    
    print(f"--- Setting up Cgroup {CGROUP_NAME} at {CGROUP_SIZE} bytes ---")
    recreate_cache_ext_cgroup(limit_in_bytes=CGROUP_SIZE)

    print(f"--- Loading Policy: {policy_path} ---")
    policy = CacheExtPolicy(CGROUP_NAME, policy_path, "/tmp") 
    policy.start()

    print("Policy Loaded! Press Ctrl+C to stop.")
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.pause()