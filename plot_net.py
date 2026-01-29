import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

df = pd.read_csv("2_mglru_network_results.csv")

plt.figure(figsize=(12, 6))

a_data = df[df["Active_DB"] == "A"]
plt.plot(a_data["Time_Sec"], a_data["Throughput_MBps"], 'o-', label="DB A (Port 9001)", color="blue", markersize=4)

b_data = df[df["Active_DB"] == "B"]
plt.plot(b_data["Time_Sec"], b_data["Throughput_MBps"], 'o-', label="DB B (Port 9002)", color="orange", markersize=4)

for x in range(0, int(df["Time_Sec"].max()) + 5, 5):
    plt.axvline(x=x, color='gray', linestyle='--', alpha=0.3)

plt.title("MGLRU Network Throughput (15s Switch)")
plt.xlabel("Time (seconds)")
plt.ylabel("Throughput (MB/s)")
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()

max_t = int(df["Time_Sec"].max())
plt.xticks(np.arange(0, max_t + 1, 15))

plt.savefig("2_mglru_plot_net.png")