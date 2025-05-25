import re
import matplotlib.pyplot as plt

def parse_ping_log(filename):
    timestamps = []
    rtts = []

    with open(filename, 'r') as f:
        for line in f:
            # Match format: [timestamp] ... time=XX.X ms
            match = re.search(r'\[(\d+\.\d+)\].*time=([\d.]+)\s*ms', line)
            if match:
                timestamp = float(match.group(1))
                rtt = float(match.group(2))
                timestamps.append(timestamp)
                rtts.append(rtt)

    return timestamps, rtts

# === Replace with your filename ===
log_file = "ping.log"
x, y = parse_ping_log(log_file)

# Plotting
plt.figure(figsize=(10, 5))
plt.plot(x, y, marker='o', linestyle='-', label="Ping RTT")
plt.xlabel("Unix Time (s)")
plt.ylabel("RTT (ms)")
plt.title("Ping Round Trip Time (RTT) Over Time")
plt.grid(True)
plt.tight_layout()
plt.savefig("ping_rtt_plot.png", dpi=300)
print("✅ Saved plot as ping_rtt_plot.png")
