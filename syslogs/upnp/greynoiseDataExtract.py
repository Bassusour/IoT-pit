import os
import pandas as pd
from greynoise import GreyNoise
from io import StringIO

# Load your API key from an environment variable
api_key = "OMXKW5fEjFbhmC5CKbdpsCTwpqGL9KZpPOuecJ92oGdGB2MJE1GU92T5JmXRcrZn"

# # Initialize the client
gn = GreyNoise(api_key=api_key)

# Load your IPs from a file (assuming whitespace-separated format)
with open("./data/unique_ips.txt", "r") as f:
    ip_list = [line.strip() for line in f if line.strip()]

# Split IPs into chunks of 1000 (API limit for /multi/quick)
def chunk_list(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

# # Collect all responses
results = []
for chunk in chunk_list(ip_list, 1000):
    response = gn.ip_multi(chunk)
    results.extend(response)

# # Convert to DataFrame and save
results_df = pd.DataFrame(results)
results_df.to_csv("./data/greynoise_results.csv", index=False)

print("Lookup complete. Results saved to greynoise_results.csv")