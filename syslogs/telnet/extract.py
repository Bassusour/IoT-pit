import re
import os
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime
from collections import defaultdict

# === CONFIGURATION ===
log_dir = os.path.dirname(os.path.abspath(__file__))
log_filenames = [f"syslog.{i}" for i in range(37, 0, -1)] + ["syslog"]
# log_filenames = ["syslogTest"]

# === REGEX PATTERNS ===
accepted_pattern = re.compile(r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Accepted connection from (?P<ip>\d+\.\d+\.\d+\.\d+)")
disconnected_pattern = re.compile(r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Client disconnected from IP: (?P<ip>\d+\.\d+\.\d+\.\d+).*time (?P<duration>\d+)")
stats_pattern1 = re.compile(r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Server is running with (?P<current>\d+) connected clients")
stats_pattern2 = re.compile(r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Current statistics: wasted time: (?P<wasted>\d+) ms. Total connected clients: (?P<total>\d+)")
repeat_pattern = re.compile(r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*message repeated (?P<count>\d+) times: \[\s*(?P<inner>.+?)\s*\]")

# === DATA STRUCTURES ===
ip_connections = defaultdict(int)
ip_durations = defaultdict(int)
unique_ips = set()

timestamps = []
current_clients_list = []
wasted_times = []
total_connections_list = []

def extract_telnet_data():
    # === PROCESS LOG FILES ===
    for fname in log_filenames:
        # print("Current working directory:", os.getcwd())
        script_dir = os.path.dirname(os.path.abspath(__file__))
        log_dir = script_dir

        full_path = os.path.join(log_dir, fname)
        if not os.path.isfile(full_path):
            continue

        with open(full_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                if "telnet_tarpit" not in line:
                    continue

                repeat_match = repeat_pattern.search(line)
                lines_to_process = [(line, 1)]

                if repeat_match:
                    timestamp = repeat_match.group("timestamp")
                    inner_message = repeat_match.group("inner")
                    repeat_count = int(repeat_match.group("count"))
                    lines_to_process = [(f"{timestamp} {inner_message}", repeat_count)]

                for processed_line, multiplier in lines_to_process:
                    if (match := accepted_pattern.search(processed_line)):
                        ip = match.group("ip")
                        ip_connections[ip] += multiplier
                        unique_ips.add(ip)

                    elif (match := disconnected_pattern.search(processed_line)):
                        ip = match.group("ip")
                        duration = int(match.group("duration"))
                        ip_durations[ip] += duration * multiplier
                        unique_ips.add(ip)

                    elif (match := stats_pattern1.search(processed_line)):
                        timestamp = datetime.strptime(match.group("timestamp"), "%Y-%m-%dT%H:%M:%S")
                        current = int(match.group("current"))
                        timestamps.append(timestamp)
                        current_clients_list.append(current)

                    elif (match := stats_pattern2.search(processed_line)):
                        timestamp = datetime.strptime(match.group("timestamp"), "%Y-%m-%dT%H:%M:%S")
                        wasted = int(match.group("wasted"))
                        total = int(match.group("total"))
                        wasted_times.append(wasted)
                        total_connections_list.append(total)

    # === ALIGN TIME SERIES DATAFRAME ===
    min_len = min(len(timestamps), len(current_clients_list), len(wasted_times), len(total_connections_list))
    df = pd.DataFrame({
        "Timestamp": timestamps[:min_len],
        "Current Connected Clients": current_clients_list[:min_len],
        "Wasted Time (ms)": wasted_times[:min_len],
        "Total Connections": total_connections_list[:min_len]
    }).set_index("Timestamp")

    # df.loc[df.index[0], "Wasted Time (ms)"] = 0
    # df.loc[df.index[1], "Wasted Time (ms)"] = 0

    # output_dir = os.path.join(os.path.dirname(__file__), "data")
    os.makedirs("data", exist_ok=True)

    # === SAVE UNIQUE IPs ===
    with open("data/unique_ips.txt", "w") as f:
        for ip in sorted(unique_ips):
            f.write(ip + "\n")

    # === SAVE IP STATS ===
    with open("data/ip_stats.txt", "w") as f:
        f.write(f"{'IP Address':<20} {'Connections':<12} {'Total Time (ms)':<16}\n")
        f.write("=" * 50 + "\n")
        for ip in sorted(ip_connections.keys()):
            count = ip_connections[ip]
            total_time = ip_durations[ip]
            f.write(f"{ip:<20} {count:<12} {total_time:<16}\n")

    def save_plot(x, y, title, ylabel, filename, color='blue'):
        plt.figure(figsize=(16, 6))
        plt.plot(x, y, label=title, color=color)
        plt.title(title)
        plt.xlabel("Time")
        plt.ylabel(ylabel)
        plt.legend()
        plt.grid(True)
        plt.xticks(rotation=45)
        # plt.xlim(x.min(), x.max())
        plt.tight_layout()
        plt.savefig(filename)
        plt.close()

    # --------- Combined Dual-Axis Plot
    fig, ax1 = plt.subplots(figsize=(16, 6))

    # Primary y-axis: cumulative total connections
    ax1.set_xlabel("Time")
    ax1.set_ylabel("Cumulative Total Connections", color="green")
    ax1.plot(df.index, df["Total Connections"], color="green", label="Cumulative Total Connections")
    ax1.tick_params(axis="y", labelcolor="green")

    # Format x-axis
    ax1.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d\n%H:%M'))
    ax1.tick_params(axis='x', rotation=45)

    # Secondary y-axis: current connected clients
    ax2 = ax1.twinx()
    ax2.set_ylabel("Current Connected Clients", color="blue")
    ax2.plot(df.index, df["Current Connected Clients"], color="blue", label="Current Connected Clients")
    ax2.tick_params(axis="y", labelcolor="blue")

    # Title and layout
    plt.title("Current vs. Total Connected Clients Over Time")
    fig.tight_layout()
    plt.grid(True)

    # Save combined plot
    plt.savefig(os.path.join("data", "combined_clients_plot.png"))
    plt.close()

    # Other individual plots
    save_plot(df.index, df["Current Connected Clients"], "Current Connected Clients Over Time", "Clients", "data/current_connected_clients.png", color='blue')
    save_plot(df.index, df["Wasted Time (ms)"], "Wasted Time Over Time", "Wasted Time (ms)", "data/wasted_time_over_time.png", color='orange')
    save_plot(df.index, df["Total Connections"], "Total Number of Connections Over Time", "Total Connections", "data/cumulative_total_connections.png", color='green')

    return df[["Wasted Time (ms)"]].rename(columns={"Wasted Time (ms)": "Telnet"})

if __name__ == '__main__':
    extract_telnet_data()