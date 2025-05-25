import matplotlib.pyplot as plt
import re

# --- Config ---
iperf_logs = ["logs/iperf3_before.log", "logs/iperf3_during.log", "logs/iperf3_after.log"]
ping_logs  = ["logs/ping_before.log", "logs/ping_during.log", "logs/ping_after.log"]
labels     = ["Before Tarpit", "During Tarpit", "After Tarpit"]

# --- Parse iPerf3 Logs ---
def parse_iperf_log(filename):
    times, bitrates = [], []
    pattern = re.compile(r"\[\s*\d+\]\s+[\d.]+-([\d.]+)\s+sec\s+[\d.]+\s+MBytes\s+([\d.]+)\s+Mbits/sec")

    with open(filename, 'r') as f:
        for line in f:
            match = pattern.search(line)
            if match:
                time = float(match.group(1))
                bitrate = float(match.group(2))
                times.append(time)
                bitrates.append(bitrate)

    return times, bitrates

# --- Parse Ping Logs ---
def parse_ping_log(filename):
    times, rtts = [], []
    pattern = re.compile(r"\[(\d+\.\d+)\].*time=([\d.]+)\s*ms")

    with open(filename, 'r') as f:
        for line in f:
            match = pattern.search(line)
            if match:
                timestamp = float(match.group(1))
                rtt = float(match.group(2))
                times.append(timestamp)
                rtts.append(rtt)

    return times, rtts

# --- Load and Normalize Data ---

# Parse iPerf logs
iperf_data = [parse_iperf_log(f) for f in iperf_logs]

offset_during = iperf_data[0][0][-1] if iperf_data[0][0] else 0
offset_after = offset_during + (iperf_data[1][0][-1] if iperf_data[1][0] else 0)

iperf_data[1] = ([t + offset_during for t in iperf_data[1][0]], iperf_data[1][1])
iperf_data[2] = ([t + offset_after for t in iperf_data[2][0]], iperf_data[2][1])

# Parse ping logs
ping_data = [parse_ping_log(f) for f in ping_logs]

# Normalize and align ping timestamps
duration_before = ping_data[0][0][-1] - ping_data[0][0][0]
duration_during = ping_data[1][0][-1] - ping_data[1][0][0]

offset_during = duration_before
offset_after  = duration_before + duration_during

base_before = ping_data[0][0][0]
base_during = ping_data[1][0][0]
base_after  = ping_data[2][0][0]

ping_data[0] = ([t - base_before for t in ping_data[0][0]], ping_data[0][1])
ping_data[1] = ([t - base_during + offset_during for t in ping_data[1][0]], ping_data[1][1])
ping_data[2] = ([t - base_after  + offset_after  for t in ping_data[2][0]], ping_data[2][1])

# --- Plotting ---
fig, ax1 = plt.subplots(figsize=(14, 6))

# Plot raw iPerf bitrate
for (x, y), label in zip(iperf_data, labels):
    ax1.plot(x, y, label=f"{label} (Bitrate)", linewidth=1.5)

ax1.set_xlabel("Time (s)")
ax1.set_ylabel("Bitrate (Mbits/sec)", color="blue")
ax1.tick_params(axis="y", labelcolor="blue")
ax1.set_ylim(bottom=0)  # Force bitrate axis to start at 0
ax1.grid(True)

# Plot raw ping RTT
ax2 = ax1.twinx()
for (x, y), label in zip(ping_data, labels):
    ax2.plot(x, y, linestyle='dotted', label=f"{label} (RTT)", linewidth=1.0)

ax2.set_ylabel("Ping RTT (ms)", color="red")
ax2.tick_params(axis="y", labelcolor="red")

# Vertical lines for tarpit start/stop
ax1.axvline(x=offset_during, color='green', linestyle='--', label="Tarpit Started")
ax1.axvline(x=offset_after, color='red', linestyle='--', label="Tarpit Stopped")

# Legend and layout
fig.legend(loc="center right", bbox_transform=ax1.transAxes, bbox_to_anchor=(1.0, 0.5))
# plt.subplots_adjust(right=0.95)  # Make room for the legend inside the figure
plt.title("iPerf3 Bitrate and Ping RTT Over Time (Raw)")
plt.tight_layout()

# Save to file
plt.savefig("iperf_ping_raw_plot.png", dpi=300)
print("Saved plot as: iperf_ping_raw_plot.png")
