import matplotlib.pyplot as plt
import pandas as pd
from telnet.extract import extract_telnet_data
from upnp.extract import extract_upnp_data
from mqtt.extract import extract_mqtt_data

# Get the data
telnet_df = extract_telnet_data()
upnp_df = extract_upnp_data()
mqtt_df = extract_mqtt_data()

# Combine all data on the same time axis
combined_df = pd.concat([telnet_df, upnp_df, mqtt_df], axis=1)

# Optional: sort by time and interpolate missing values
combined_df = combined_df.sort_index().interpolate(method='time')

# Plot
plt.figure(figsize=(16, 6))
for col in combined_df.columns:
    plt.plot(combined_df.index, combined_df[col], label=col)

plt.title("Wasted Time Comparison Over Time")
plt.xlabel("Time")
plt.ylabel("Wasted Time (ms)")
plt.legend()
plt.grid(True)
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("data/wasted_time_comparison.png")
plt.close()
