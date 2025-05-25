import sys
import os

# Add the parent directory (syslogs) to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import matplotlib.pyplot as plt
import pandas as pd

from telnet.extract import extract_telnet_data
from upnp.extract import extract_upnp_data
from mqtt.extract import extract_mqtt_data

def prepare_df(df):
    df.index = pd.to_datetime(df.index)
    # return df[~df.index.duplicated(keep='first')]
    return df.groupby(df.index).mean()

# Load data
df_telnet = extract_telnet_data()
df_upnp = extract_upnp_data()
df_mqtt = extract_mqtt_data()

df_telnet = prepare_df(df_telnet)
df_upnp = prepare_df(df_upnp)
df_mqtt = prepare_df(df_mqtt)

# print("First Telnet timestamp:", df_telnet.index[0])
# print("First UPnP timestamp:", df_upnp.index[0])
# print("First MQTT timestamp:", df_mqtt.index[0])

# Combine on timestamp
df_combined = pd.concat([df_telnet, df_upnp, df_mqtt], axis=1, join='outer')
df_combined = df_combined.sort_index()
df_combined = df_combined.interpolate(method='time')
# df_combined = df_combined.sort_index().interpolate(method='time')

# Optional: interpolate per column if needed, but only that column
# df_combined["Telnet"] = df_combined["Telnet"].interpolate("time")
# df_combined["UPnP"] = df_combined["UPnP"].interpolate("time")
# df_combined["MQTT"] = df_combined["MQTT"].interpolate("time")

# print(df_combined.head(100))
# print(df_combined.columns)

print("Telnet:\n", df_telnet.head())
print("UPnP:\n", df_upnp.head())
print("MQTT:\n", df_mqtt.head())
print("Rows -> Telnet:", len(df_telnet), "UPnP:", len(df_upnp), "MQTT:", len(df_mqtt))

# Plot
plt.figure(figsize=(16, 6))
# df_combined = df_combined.replace(0, 1e-1)
# print("df_combined columns:", df_combined.columns.tolist())

for col in df_combined.columns:
    plt.plot(df_combined.index, df_combined[col], label=col)

plt.title("Wasted Time Comparison Over Time")
plt.xlabel("Time")
plt.ylabel("Wasted Time (ms)")
plt.legend()
plt.grid(True)
plt.xticks(rotation=45)
plt.tight_layout()
plt.yscale("log")
plt.ylim(bottom=1)
plt.savefig("data/combined_wasted_time.png")
plt.close()