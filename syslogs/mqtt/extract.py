import os
import re
import matplotlib.pyplot as plt
from collections import Counter, defaultdict
import pandas as pd
from datetime import datetime

log_dir = os.path.dirname(os.path.abspath(__file__))
log_filenames = [f"syslog.{i}" for i in range(35, 0, -1)] + ["syslog"]
# log_filenames = ["syslog"]

# === REGEX PATTERNS ===
version_pattern = re.compile(r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Client connected with (?P<version>v[\d.]+)")
connect_pattern = re.compile(r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*CONNECT request with keep-alive: (?P<keep_alive>\d+) username: (?P<username>.*?) password: (?P<password>.*)")
subscribe_pattern = re.compile(r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*SUBSCRIBE request with topic: (?P<topic>.*?) and QoS (?P<qos>\d+)")
removed_pattern = re.compile(r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Client removed with IP: (?P<ip>[\d.]+).*connected time (?P<duration>\d+) ms")
wasted_pattern = re.compile(r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*wasted time is (?P<wasted>\d+).*Total connected clients: (?P<total>\d+)")
stats_pattern = re.compile(r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Server is running with (?P<current>\d+)")
malformed_pattern = re.compile(r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Malformed CONNECT request.*but got \"(?P<value>.*?)\"")
unknown_pattern = re.compile(r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Unknown request (?P<value>\d+)")
incomplete_pattern = re.compile(r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Incomplete packet at offset (?P<offset>\d+): expected length = (?P<expected>\d+), available = (?P<available>\d+)")
repeat_pattern = re.compile(r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*message repeated (?P<count>\d+) times: \[\s*(?P<inner>.+?)\s*\]")

# === DATA STRUCTURES ===
version_counter = Counter()
connect_info = []
subscribe_info = []
wasted_time = []
client_counts = []
connection_durations = []

malformed_requests = []
unknown_requests = []
incomplete_packets = []

def extract_mqtt_data():
    # === PROCESS LOG FILES ===
    for fname in log_filenames:
        full_path = os.path.join(log_dir, fname)
        if not os.path.isfile(full_path):
            continue

        with open(full_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                if "mqtt_tarpit" not in line:
                    continue

                repeat_match = repeat_pattern.search(line)
                lines_to_process = [(line, 1)]

                if repeat_match:
                    timestamp = repeat_match.group("timestamp")
                    inner_message = repeat_match.group("inner")
                    repeat_count = int(repeat_match.group("count"))
                    lines_to_process = [(f"{timestamp} {inner_message}", repeat_count)]

                for processed_line, multiplier in lines_to_process:
                    # print(f"[DEBUG] Processing line: {processed_line.strip()}")
                    for _ in range(multiplier):
                        if (m := version_pattern.search(processed_line)):
                            version = m.group("version")
                            version_counter[version] += 1

                        elif (m := connect_pattern.search(processed_line)):
                            keepAlive = m.group("keep_alive")
                            username = m.group("username")
                            password = m.group("password")

                            # connect_info.append((keepAlive, username, password))
                            connect_info.append({
                                "keepAlive": keepAlive,
                                "username": username,
                                "password": password
                            })
                            # connect_info.append(m.groupdict())

                        elif (m := subscribe_pattern.search(processed_line)):
                            subscribe_info.append(m.groupdict())

                        elif (m := removed_pattern.search(processed_line)):
                            connection_durations.append({
                                # "timestamp": m.group("timestamp"),
                                "ip": m.group("ip"),
                                "duration": int(m.group("duration"))
                            })
                            # connection_durations.append(m.groupdict())

                        elif (m := wasted_pattern.search(processed_line)):
                            wasted_time.append({
                                "timestamp": m.group("timestamp"),
                                "wasted_time": int(m.group("wasted")),
                                "total_clients": int(m.group("total"))
                            })

                        elif (m := stats_pattern.search(processed_line)):
                            client_counts.append({
                                "timestamp": m.group("timestamp"),
                                "current_clients": int(m.group("current"))
                            })

                        elif (m := malformed_pattern.search(processed_line)):
                            malformed_requests.append({
                                "connectValue": m.group("value")
                            })
                            # malformed_requests.append(m.groupdict())

                        elif (m := unknown_pattern.search(processed_line)):
                            unknown_requests.append({
                                "value": m.group("value")
                            })
                            # unknown_requests.append(m.groupdict())

                        elif (m := incomplete_pattern.search(processed_line)):
                            incomplete_packets.append({
                                "offset": m.group("offset"),
                                "expected": m.group("expected"),
                                "available": m.group("available")
                            })
                            # incomplete_packets.append(m.groupdict())

    # === UTILITIES ===
    def save_txt(data, filename):
        df = pd.DataFrame(data)
        df.to_csv(f"{filename}.txt", sep="\t", index=False)

    def safe_set_timestamp(df):
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
            df.set_index("timestamp", inplace=True)
        return df

    # === PLOT: MQTT Versions ===
    version_counter['v5'] = version_counter.get('v5', 0)
    plt.figure(figsize=(6, 6))
    plt.bar(version_counter.keys(), version_counter.values(), width=0.3)
    plt.title("MQTT Version Usage")
    plt.xlabel("Version")
    plt.ylabel("Count")
    plt.savefig("data/mqtt_version_usage.png")
    plt.clf()

    # 2. Connected Clients Over Time
    df_clients = pd.DataFrame(client_counts)
    if not df_clients.empty:
        df_clients = safe_set_timestamp(df_clients)
        plt.figure(figsize=(16, 6))
        df_clients["current_clients"].plot()
        plt.title("Connected Clients Over Time")
        plt.xlabel("Time")
        plt.ylabel("Clients")
        plt.savefig("data/connected_clients_over_time.png")
        plt.clf()

    # 3. Wasted Time Over Time
    # df_waste = pd.DataFrame(wasted_time)
    # if not df_waste.empty:
    #     df_waste = safe_set_timestamp(df_waste)
    #     plt.figure(figsize=(16, 6))
    #     df_waste["wasted_time"].plot()
    #     plt.title("Accumulated Wasted Time Over Time")
    #     plt.xlabel("Time")
    #     plt.ylabel("Wasted Time")
    #     plt.savefig("data/wasted_time_over_time_unedited.png")
    #     plt.clf()

    df_waste = pd.DataFrame(wasted_time)
    df_clients = pd.DataFrame(client_counts)

    if not df_waste.empty and not df_clients.empty:
        df_waste["timestamp"] = pd.to_datetime(df_waste["timestamp"])
        df_clients["timestamp"] = pd.to_datetime(df_clients["timestamp"])

        # Merge data on timestamp
        df_combined = pd.merge_asof(
            df_clients.sort_values("timestamp"),
            df_waste.sort_values("timestamp"),
            on="timestamp",
            direction="backward"
        )

        df_combined = df_combined.sort_values("timestamp").reset_index(drop=True)

        # Start with actual wasted time
        smooth_times = [df_combined.loc[0, "timestamp"]]
        smooth_waste = [df_combined.loc[0, "wasted_time"]]

        for i in range(1, len(df_combined)):
            t1 = df_combined.loc[i - 1, "timestamp"]
            t2 = df_combined.loc[i, "timestamp"]
            dt = (t2 - t1).total_seconds() * 1000  # in milliseconds
            n_clients = df_combined.loc[i - 1, "current_clients"]
            prev_waste = smooth_waste[-1]

            simulated_waste = prev_waste + (dt * n_clients)
            smooth_times.append(t2)
            smooth_waste.append(simulated_waste)

        # Plot smoothed data
        plt.figure(figsize=(16, 6))
        plt.plot(smooth_times, smooth_waste, label="Estimated Accumulated Waste")
        plt.title("Smoothed Accumulated Wasted Time Over Time")
        plt.xlabel("Time")
        plt.ylabel("Estimated Wasted Time (ms)")
        plt.legend()
        plt.savefig("data/wasted_time_over_time.png")
        plt.clf()
    
        # df = pd.DataFrame({
        #     "Timestamp": smooth_times,
        #     "MQTT": smooth_waste
        # }).set_index("Timestamp")
        # df.index = pd.to_datetime(df.index)
        # return df # Comment out this block if needed

    # 4. Connection Duration Histogram (log scale)
    durations = [int(d["duration"]) for d in connection_durations if "duration" in d]
    if durations:
        plt.figure(figsize=(16, 6))
        plt.hist(durations, bins=30, log=True)
        plt.title("Log Distribution of Connection Durations")
        plt.xlabel("Duration (ms)")
        plt.ylabel("Log Frequency")
        plt.savefig("data/connection_duration_distribution.png")
        plt.clf()

    # === EXPORT TEXT DATA ===
    if connect_info:
        df_connect = pd.DataFrame(connect_info)
        grouped = df_connect.groupby(["keepAlive", "username", "password"]).size().reset_index(name="count")
        grouped.to_csv("data/connect_info.txt", sep="\t", index=False)

    # 2. connection_durations: count disconnections per IP
    if connection_durations:
        df_duration = pd.DataFrame(connection_durations)
        ip_counts = df_duration["ip"].value_counts().to_dict()
        df_duration["count"] = df_duration["ip"].map(ip_counts)
        df_duration.to_csv("data/connection_durations.txt", sep="\t", index=False)
    
    if connection_durations:
        unique_ips = sorted({entry["ip"] for entry in connection_durations if "ip" in entry})
        with open("data/unique_ips.txt", "w") as f:
            for ip in unique_ips:
                f.write(f"{ip}\n")

    # 3. subscribe_info: topic + qos with count
    if subscribe_info:
        df_subs = pd.DataFrame(subscribe_info)
        grouped = df_subs.groupby(["topic", "qos"]).size().reset_index(name="count")
        grouped.to_csv("data/subscribe_info.txt", sep="\t", index=False)

    # 4. malformed_requests: count per value
    if malformed_requests:
        df_malformed = pd.DataFrame(malformed_requests)
        grouped = df_malformed.groupby("connectValue").size().reset_index(name="count")
        grouped.to_csv("data/malformed_requests.txt", sep="\t", index=False)

    # 5. unknown_requests: count per value
    if unknown_requests:
        df_unknown = pd.DataFrame(unknown_requests)
        grouped = df_unknown.groupby("value").size().reset_index(name="count")
        grouped.to_csv("data/unknown_requests.txt", sep="\t", index=False)

    # 6. incomplete_packets: count per unique packet
    if incomplete_packets:
        df_incomplete = pd.DataFrame(incomplete_packets)
        grouped = df_incomplete.groupby(["offset", "expected", "available"]).size().reset_index(name="count")
        grouped.to_csv("data/incomplete_packets.txt", sep="\t", index=False)

if __name__ == '__main__':
    extract_mqtt_data()