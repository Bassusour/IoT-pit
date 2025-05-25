import re
import matplotlib.pyplot as plt

# --- Configuration ---
cpu_logs = ["logs/cpu_before.log", "logs/cpu_during.log", "logs/cpu_after.log"]
labels = ["Before Tarpit", "During Tarpit", "After Tarpit"]
sample_interval = 5  # seconds between top samples

# --- Function to extract CPU usage from a top log ---
def extract_cpu_usage(log_file):
    usages = []
    with open(log_file, "r") as f:
        for line in f:
            match = re.search(r'%Cpu\(s\):.*?([\d.]+)\s+id', line)
            if match:
                idle = float(match.group(1))
                usage = 100.0 - idle
                usages.append(usage)
    return usages

# --- Extract and align all logs ---
all_usages = [extract_cpu_usage(f) for f in cpu_logs]

# Calculate x-axis offsets based on durations
offsets = []
current_offset = 0
for usage in all_usages:
    offsets.append(current_offset)
    current_offset += len(usage) * sample_interval

# Extract X, Y data
all_times = [
    [offset + i * sample_interval for i in range(len(usage))]
    for offset, usage in zip(offsets, all_usages)
]

# Plotting
plt.figure(figsize=(12, 5))

colors = ["blue", "orange", "green"]
for times, usages, label, color in zip(all_times, all_usages, labels, colors):
    plt.plot(times, usages, label=label, linewidth=1.5, color=color)

# Add vertical lines for tarpit phase
plt.axvline(x=offsets[1], color="green", linestyle="--", label="Tarpit Started")
plt.axvline(x=offsets[2], color="red", linestyle="--", label="Tarpit Stopped")

plt.xlabel("Time (s)")
plt.ylabel("CPU Usage (%)")
plt.title("CPU Usage Over Time Across All Phases")
plt.ylim(0, 100)
plt.grid(True)
plt.legend()
plt.tight_layout()
plt.savefig("cpu_usage_all_phases.png", dpi=300)
print("✅ Saved: cpu_usage_all_phases.png")
