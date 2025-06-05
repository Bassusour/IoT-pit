import pandas as pd
import matplotlib.pyplot as plt
import ast
import os
import matplotlib.cm as cm
import numpy as np
import textwrap

# Create output directory for plots
output_dir = "./greynoise_plots"
os.makedirs(output_dir, exist_ok=True)

script_dir = os.path.dirname(os.path.abspath(__file__))

# Paths to all three data files
csv_paths = [
    os.path.join(script_dir, '..', 'telnet', 'data', 'greynoise_results.csv'),
    os.path.join(script_dir, '..', 'upnp', 'data', 'greynoise_results.csv'),
    os.path.join(script_dir, '..', 'mqtt', 'data', 'greynoise_results.csv'),
]

# Load the CSV file
df_list = [pd.read_csv(path) for path in csv_paths]
df = pd.concat(df_list, ignore_index=True)

# Parse list/dict columns
df['tags'] = df['tags'].apply(lambda x: ast.literal_eval(x) if pd.notnull(x) and x.strip() != '' else [])
df['metadata'] = df['metadata'].apply(lambda x: ast.literal_eval(x) if pd.notnull(x) and x.strip() != '' else {})

# 1. Pie chart of 'seen' field
seen_counts = df['seen'].value_counts()
plt.figure()
seen_counts.plot.pie(autopct='%1.1f%%', startangle=90, labels=['Seen', 'Not Seen'])
plt.title('Percentage of Seen IP Addresses')
plt.ylabel('')
plt.savefig(os.path.join(output_dir, 'seen_pie_chart.png'))
plt.close()

# 2. Bar chart of tags distribution
all_tags = df['tags'].explode()
tag_counts = all_tags.value_counts()
top_tags = tag_counts.head(10)
# other_count = tag_counts[10:].sum()
# tag_plot_data = pd.concat([top_tags, pd.Series({'Other': other_count})])

tag_plot_data_percent = top_tags / top_tags.sum() * 100
wrapped_labels = [textwrap.fill(label, width=20) for label in top_tags.index]

plt.figure(figsize=(12, 6))
# tag_plot_data.plot(kind='bar')
tag_plot_data_percent.plot(kind='bar')
plt.title('Tag Distribution (Top 10)')
plt.xlabel('Tag')
plt.ylabel('Percentage of Tags (%)')
plt.xticks(ticks=range(len(wrapped_labels)), labels=wrapped_labels, rotation=45, ha='right')
plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'tag_distribution_top10.png'))
plt.close()

# 3. Pie chart of classification
classification_counts = df['classification'].value_counts()
plt.figure()
classification_counts.plot.pie(autopct='%1.1f%%', startangle=90)
plt.title('Classification Distribution')
plt.ylabel('')
plt.savefig(os.path.join(output_dir, 'classification_pie_chart.png'))
plt.close()

# 4. Count of bots
bot_counts = df['bot'].value_counts()
plt.figure()
bot_counts.plot.pie(autopct='%1.1f%%', startangle=90, labels=['Not Bot', 'Bot'] if len(bot_counts) == 2 else bot_counts.index)
plt.title('Bot vs Non-Bot IPs')
plt.ylabel('')
plt.savefig(os.path.join(output_dir, 'bot_pie_chart.png'))
plt.close()

# 5. Pie chart of source countries from metadata
countries = df['metadata'].apply(lambda x: x.get('country') if isinstance(x, dict) else None)
country_counts = countries.value_counts()
top_countries = country_counts.head(10)
other_count = country_counts[10:].sum()
country_plot_data = pd.concat([top_countries, pd.Series({'Other': other_count})])

colors = list(cm.tab10(np.linspace(0, 1, 10)))  # Get 10 distinct colors
colors.append('lightgrey')  # Add unique color for "Other"

plt.figure()
country_plot_data.plot.pie(autopct='%1.1f%%', startangle=90, colors=colors)
plt.title('IP Source Country Distribution (Top 10 + Other)')
plt.ylabel('')
plt.savefig(os.path.join(output_dir, 'country_distribution_top10.png'))
plt.close()

# 6. ASN pie chart (Top 10 + Other)
asns = df['metadata'].apply(lambda x: x.get('asn') if isinstance(x, dict) else None)
asn_counts = asns.value_counts()
top_asns = asn_counts.head(10)
other_asns_count = asn_counts[10:].sum()
asn_plot_data = pd.concat([top_asns, pd.Series({'Other': other_asns_count})])

# Colors
colors = list(cm.tab10(np.linspace(0, 1, 10)))
colors.append('lightgrey')

plt.figure()
asn_plot_data.plot.pie(autopct='%1.1f%%', startangle=90, colors=colors)
plt.title('ASN Distribution (Top 10 + Other)')
plt.ylabel('')
plt.savefig(os.path.join(output_dir, 'asn_distribution_top10.png'))
plt.close()

# 7. Organization bar chart (Top 10 + Other)
orgs = df['metadata'].apply(lambda x: x.get('organization') if isinstance(x, dict) else None)
org_counts = orgs.value_counts()
top_orgs = org_counts.head(10)
other_orgs_count = org_counts[10:].sum()
org_plot_data = pd.concat([top_orgs, pd.Series({'Other': other_orgs_count})])

org_plot_data_percent = org_plot_data / org_plot_data.sum() * 100

plt.figure(figsize=(12, 6))
org_plot_data_percent.plot(kind='bar')
plt.title('Organization Distribution (Top 10 + Other)')
plt.xlabel('Organization')
plt.ylabel('Percentage of IPs (%)')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'organization_distribution_top10_percent.png'))
plt.close()