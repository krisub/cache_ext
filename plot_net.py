import argparse
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

parser = argparse.ArgumentParser(description="Plot throughput for a given policy")
parser.add_argument("policy", help="Policy name (cache_ext_net)")
args = parser.parse_args()

policy = args.policy

df = pd.read_csv(f"data/{policy}.csv")

# comment out for all data
# df = df[(df["Time_Sec"] >= 0) & (df["Time_Sec"] <= 45)]

plt.figure(figsize=(12, 6))

a_data = df[df["Active_DB"] == "A"]
plt.plot(a_data["Time_Sec"], a_data["Throughput_MBps"], 'o-', label="DB A (Port 9001)", color="blue", markersize=4)

b_data = df[df["Active_DB"] == "B"]
plt.plot(b_data["Time_Sec"], b_data["Throughput_MBps"], 'o-', label="DB B (Port 9002)", color="orange", markersize=4)

for x in range(0, int(df["Time_Sec"].max()) + 5, 5):
    plt.axvline(x=x, color='gray', linestyle='--', alpha=0.3)

plt.title(f"{policy} Policy Throughput (5s Switch)")
plt.xlabel("Time (seconds)")
plt.ylabel("Throughput (MB/s)")
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()

max_t = int(df["Time_Sec"].max())
plt.xticks(np.arange(0, max_t + 1, 15))

plt.savefig(f"data/{policy}_plot.png")