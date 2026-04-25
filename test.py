import pandas as pd

df = pd.read_csv("Tuesday-WorkingHours.pcap_ISCX.csv", encoding='utf-8', low_memory=False)

df.columns = df.columns.str.strip()

print(df['Label'].value_counts())