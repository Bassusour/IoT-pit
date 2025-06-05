import re
import os
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from collections import defaultdict
# from ace_tools import display_dataframe_to_user

# === CONFIGURATION ===
log_dir = os.path.dirname(os.path.abspath(__file__))
log_filenames = [f"syslog.{i}" for i in range(37, 0, -1)] + ["syslog"]
# log_filenames = ["syslogTest"]

# === IPs TO FILTER OUT ===
blacklisted_ips = {
    "147.185.132.219", "147.185.133.15", "167.88.164.186", "167.88.170.69", "172.86.112.132",
    "172.86.112.8", "172.86.117.19", "45.61.160.234", "45.61.160.74", "45.61.165.36",
    "172.86.115.4", "35.203.211.103", "172.86.73.6", "45.61.160.104", "172.86.123.25",
    "35.203.210.50", "162.216.149.98", "172.86.117.56", "162.216.149.225", "45.61.158.6",
    "172.86.73.51", "162.216.150.94", "162.216.149.157", "35.203.210.37", "45.61.165.128",
    "35.203.211.224", "35.203.211.101", "35.203.210.235", "45.61.169.47", "35.203.211.141",
    "45.61.169.254", "35.203.210.32", "35.203.210.82", "167.88.168.133", "162.216.150.232",
    "35.203.210.13", "162.216.149.231", "35.203.211.151", "162.216.150.221", "34.122.156.88",
    "162.216.150.3", "162.216.150.208", "35.203.210.202", "45.61.159.64", "35.203.211.214",
    "172.86.117.28", "172.86.73.101", "35.203.210.157", "172.86.84.72", "167.88.166.91", "172.86.114.170",
}

# === REGEX PATTERNS ===
request_pattern = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Received (?P<method>[A-Z<\?#0-9]+) request with (?P<url>.+?) url from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
disconnect_pattern = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Client disconnected from IP: (?P<ip>\d+\.\d+\.\d+\.\d+).*time (?P<duration>\d+)"
)
stats_pattern = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Server is running with (?P<current>\d+) connected clients"
)
ssdp_request_pattern = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Received SSDP M-SEARCH request from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
xml_http_ssdp_pattern = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Total HTTP requests: (?P<http>\d+).*XML requests: (?P<xml>\d+)"
)
repeat_pattern = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*message repeated (?P<count>\d+) times: \[\s*(?P<inner>.+?)\s*\]"
)
restart_pattern = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*UPnP listener started on port 1900"
)
accept_pattern = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Accepted GET request from from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# === DATA STRUCTURES ===
def extract_upnp_data():
    request_counts = defaultdict(int)
    ip_connections = defaultdict(int)
    ip_durations = defaultdict(int)
    timestamps = []
    current_clients = []
    cumulative_total_connections = 0
    cumulative_connections = []
    wasted_time_series = []
    restart_times = []
    wasted_time_total = 0
    last_http_count = 0
    ssdp_total = 0
    ssdp_counts = defaultdict(int)
    http_counts = defaultdict(int)
    xml_counts = defaultdict(int)
    active_clients = {}  # ip -> connection start timestamp
    non_reset_wasted_total = 0
    non_reset_wasted_series = []

    non_reset_wasted_series.append((datetime.strptime("2025-04-23 05:45:09", "%Y-%m-%d %H:%M:%S"), 0))

    # === PROCESS FILES ===
    # non_reset_wasted_total = 0
    # non_reset_wasted_series = []

    for fname in log_filenames:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        log_dir = script_dir
        full_path = os.path.join(log_dir, fname)
        if not os.path.isfile(full_path):
            continue

        with open(full_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                repeat_match = repeat_pattern.search(line)
                lines_to_process = [(line, 1)]

                if repeat_match:
                    lines_to_process = [(f"{repeat_match.group('timestamp')} {repeat_match.group('inner')}",
                                        int(repeat_match.group("count")))]

                for processed_line, multiplier in lines_to_process:
                    if "upnp_tarpit" not in processed_line or any(ip in line for ip in blacklisted_ips):
                        continue

                    if (match := request_pattern.search(processed_line)):
                        method, url, ip = match["method"], match["url"], match["ip"]
                        # if ip not in blacklisted_ips:
                        request_counts[(method, url)] += multiplier
                        ip_connections[ip] += multiplier

                    elif (match := disconnect_pattern.search(processed_line)):
                        ip = match["ip"]
                        duration = int(match["duration"])
                        ip_durations[ip] += duration * multiplier
                        ts = datetime.strptime(match["timestamp"], "%Y-%m-%dT%H:%M:%S")
                        for _ in range(multiplier):
                            wasted_time_total += duration
                            wasted_time_series.append((ts, wasted_time_total))

                            non_reset_wasted_total += duration
                            non_reset_wasted_series.append((ts, non_reset_wasted_total))
                        
                        if ip in active_clients:
                            del active_clients[ip]

                    elif (match := stats_pattern.search(processed_line)):
                        ts = datetime.strptime(match["timestamp"], "%Y-%m-%dT%H:%M:%S")
                        timestamps.append(ts)
                        current_clients.append(int(match["current"]))
                        cumulative_total_connections += int(match["current"])
                        cumulative_connections.append(cumulative_total_connections)

                        incremental = 0
                        for start_ts in active_clients.values():
                            duration = (ts - start_ts).total_seconds() * 1000  # ms
                            incremental += int(duration)

                        virtual_total = wasted_time_total + incremental
                        wasted_time_series.append((ts, virtual_total))
                        # print(f"[{ts}] Actual: {wasted_time_total} ms, Smoothed: {simulated_total} ms, Clients: {len(active_clients)}")

                    elif (match := ssdp_request_pattern.search(processed_line)):
                        ip = match["ip"]
                        ts = datetime.strptime(match["timestamp"], "%Y-%m-%dT%H:%M:%S")
                        ssdp_total += multiplier
                        ssdp_counts[ts] = ssdp_total

                    elif (match := xml_http_ssdp_pattern.search(processed_line)):
                        ts = datetime.strptime(match["timestamp"], "%Y-%m-%dT%H:%M:%S")
                        http_counts[ts] = int(match["http"])
                        xml_counts[ts] = int(match["xml"])
                        # if int(match["http"]) < last_http_count:
                        #     ssdp_total = 0
                        #     ssdp_counts[ts] = 0
                        #     wasted_time_total = 0
                        #     wasted_time_series.append((ts, 0))
                        #     cumulative_total_connections = 0

                        # last_http_count = int(match["http"])

                    elif (match := restart_pattern.search(processed_line)):
                        ts = datetime.strptime(match["timestamp"], "%Y-%m-%dT%H:%M:%S")
                        restart_times.append(ts)

                        # Reset all cumulative counters
                        ssdp_total = 0
                        wasted_time_total = 0
                        cumulative_total_connections = 0

                        # Append zeros to graph tracking
                        ssdp_counts[ts] = 0
                        wasted_time_series.append((ts, 0))
                        timestamps.append(ts)
                        current_clients.append(0)
                        cumulative_connections.append(0)
                        active_clients.clear()
                    
                    elif (match := accept_pattern.search(processed_line)):
                        ip = match["ip"]
                        ts = datetime.strptime(match["timestamp"], "%Y-%m-%dT%H:%M:%S")
                        if ip not in blacklisted_ips:
                            active_clients[ip] = ts

    # === WRITE SUMMARY FILE ===
    with open("./data/text.txt", "w") as f:
        f.write("Request Counts (method, url):\n")
        for (method, url), count in sorted(request_counts.items(), key=lambda x: -x[1]):
            f.write(f"{method} {url}: {count}\n")

        f.write("\nIP Connections and Trapped Time:\n")
        for ip in sorted(ip_connections, key=lambda x: -ip_connections[x]):
            f.write(f"{ip}: {ip_connections[ip]} connections, {ip_durations[ip]} ms trapped\n")
    
    unique_ips = set(ip_connections.keys())
    with open("./data/unique_ips.txt", "w") as f_ip:
        for ip in sorted(unique_ips):
            f_ip.write(ip + "\n")

    # === BUILD PLOTTING DATA ===
    df_stats = pd.DataFrame({
        "Timestamp": timestamps,
        "Connected Clients": current_clients,
        "Cumulative Connections": cumulative_connections
    }).set_index("Timestamp")

    df_traffic = pd.DataFrame({
        "SSDP": pd.Series(ssdp_counts),
        "HTTP": pd.Series(http_counts),
        "XML": pd.Series(xml_counts)
    }).sort_index().ffill()

    df_wasted = pd.DataFrame(wasted_time_series, columns=["Timestamp", "Accumulated Wasted Time"]).set_index("Timestamp")

    df_wasted = pd.DataFrame(wasted_time_series, columns=["Timestamp", "Accumulated Wasted Time"]).set_index("Timestamp")
    df_wasted.index = pd.to_datetime(df_wasted.index)

    df_nonreset_wasted = pd.DataFrame(non_reset_wasted_series, columns=["Timestamp", "UPnP (Non-Resetting)"]).set_index("Timestamp")
    df_nonreset_wasted.index = pd.to_datetime(df_nonreset_wasted.index)

    plt.figure(figsize=(16, 6))
    df_nonreset_wasted.plot(legend=False, figsize=(16, 6), drawstyle='steps-pre')
    plt.ylabel("Milliseconds")
    plt.savefig("data/non_reset_wasted_time_over_time.png")
    
    # df_wasted = pd.DataFrame(simulated_wasted_series, columns=["Timestamp", "Accumulated Wasted Time"]).set_index("Timestamp")
    
    # === SAVE GRAPHS ===
    plt.figure(figsize=(16, 6))
    df_stats.plot(title="Concurrent and Cumulative Connections", figsize=(16, 6))
    for rt in restart_times:
        plt.axvline(x=rt, color='red', linestyle='--', alpha=0.6, linewidth=1)
    plt.savefig("data/connections_over_time.png")

    plt.figure(figsize=(16, 6))
    df_traffic.plot(title="SSDP, HTTP, and XML Requests Over Time", figsize=(16, 6), drawstyle='steps-pre')
    for rt in restart_times:
        plt.axvline(x=rt, color='red', linestyle='--', alpha=0.6, linewidth=1)
    plt.savefig("data/request_types_over_time.png")

    plt.figure(figsize=(16, 6))
    df_wasted.plot(title="Accumulated Wasted Time (ms)", legend=False, figsize=(16, 6), drawstyle='steps-pre')
    plt.ylabel("Milliseconds")

    for rt in restart_times:
        plt.axvline(x=rt, color='red', linestyle='--', alpha=0.6, linewidth=1)

    plt.savefig("data/wasted_time_over_time.png")

    return df_nonreset_wasted.rename(columns={"Accumulated Wasted Time": "UPnP"})

if __name__ == '__main__':
    extract_upnp_data()