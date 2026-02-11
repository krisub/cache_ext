import argparse
import signal
import sys
import time

from bench_lib import CacheExtPolicy, recreate_cache_ext_cgroup

# sudo python3 load_policy.py <policy_file.out> --watch-dir /mydata/db_A
# sudo python3 load_policy.py policies/cache_ext_net.out --watch-dir /mydata/db_A

CGROUP_NAME = "cache_ext_test"
CGROUP_SIZE = 0.5 * 1024 * 1024 * 1024 # 0.5 GB
# CGROUP_SIZE = 32 * 1024 * 1024 * 1024 # 32GB
# CGROUP_SIZE = 64 * 1024 * 1024 # 128MB

def signal_handler(sig, frame):
    print("\nUnloading policy...")
    policy.stop()
    sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("policy_path", help="Path to policy .out")
    parser.add_argument(
        "--watch-dir",
        default="/mydata/my_dbs",
        help="Directory to watch (keep narrow to avoid huge watchlists)",
    )
    args = parser.parse_args()
    policy_path = args.policy_path
    
    print(f"--- Setting up Cgroup {CGROUP_NAME} at {CGROUP_SIZE} bytes ---")
    recreate_cache_ext_cgroup(limit_in_bytes=CGROUP_SIZE)

    print(f"--- Loading Policy: {policy_path} ---")
    policy = CacheExtPolicy(CGROUP_NAME, policy_path, args.watch_dir)
    policy.start()

    print("Policy Loaded! Press Ctrl+C to stop.")
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.pause()