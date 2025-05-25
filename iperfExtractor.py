import matplotlib.pyplot as plt
import re

def parse_iperf_log(filename):
    import re
    end_times = []
    bitrates = []

    # This regex is more relaxed about spacing
    pattern = re.compile(
        r"\[\s*\d+\]\s+([\d.]+)-([\d.]+)\s+sec\s+[\d.]+\s+MBytes\s+([\d.]+)\s+Mbits/sec"
    )

    with open(filename, 'r') as f:
        for line in f:
            match = pattern.search(line)
            if match:
                end_time = float(match.group(2))
                bitrate = float(match.group(3))
                end_times.append(end_time)
                bitrates.append(bitrate)

    return end_times, bitrates

# Replace these with your actual filenames
before_log = "logs/iperf3_before.log"
during_log = "logs/iperf3_during.log"
after_log  = "logs/iperf3_after.log"

# Parse logs
x_before, y_before = parse_iperf_log(before_log)
x_during, y_during = parse_iperf_log(during_log)
x_after, y_after   = parse_iperf_log(after_log)

# Offset time for continuity
offset_during = x_before[-1]
x_during = [t + offset_during for t in x_during]

offset_after = x_during[-1]
x_after = [t + offset_after for t in x_after]

# Plotting
plt.figure(figsize=(12, 6))
plt.plot(x_before, y_before, label="Before Tarpit", color='blue')
plt.plot(x_during, y_during, label="During Tarpit", color='orange')
plt.plot(x_after, y_after, label="After Tarpit", color='green')

# Add vertical lines for tarpit start/stop
plt.axvline(x=offset_during, color='green', linestyle='--', label="Tarpit Started")
plt.axvline(x=offset_after, color='red', linestyle='--', label="Tarpit Stopped")

plt.title("iPerf3 Bitrate Over Time")
plt.xlabel("Time (s)")
plt.ylabel("Bitrate (Mbits/sec)")
plt.grid(True)
plt.legend()
plt.tight_layout()
plt.savefig("iperf3_plot.png", dpi=300)
