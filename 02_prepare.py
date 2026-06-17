import pandas as pd
import numpy as np
import os
import glob

DATA_DIR = r"E:\ids-project\MachineLearningCVE"

print("Reading files...")
csv_files = glob.glob(os.path.join(DATA_DIR, "*.csv"))
data = pd.concat(
    [pd.read_csv(f, low_memory=False) for f in csv_files],
    ignore_index=True
)
data.columns = data.columns.str.strip()
print(f"Merged data: {len(data):,} rows, {data.shape[1]} columns\n")

SELECTED_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Fwd Packet Length Max",
    "Bwd Packet Length Max",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Max",
    "Flow IAT Min",
]

missing = [f for f in SELECTED_FEATURES if f not in data.columns]
if missing:
    print("WARNING! These features were not found in the data:")
    for m in missing:
        print(f"  - {m}")
    print("\nAll column names in the data:")
    for c in data.columns:
        print(f"  {c}")
    raise SystemExit("We need to fix the missing feature names first.")
else:
    print("All 15 selected features are present in the data.\n")

df = data[SELECTED_FEATURES + ["Label"]].copy()

before = len(df)
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
after = len(df)
print(f"Corrupt-value cleanup: {before - after:,} rows dropped.")
print(f"Remaining rows: {after:,}\n")

df["Label_multi"] = df["Label"]
df["Label_binary"] = (df["Label"] != "BENIGN").astype(int)

print("=== Class distribution after cleaning ===")
print(df["Label_multi"].value_counts())
print()
print(f"Normal (0): {(df['Label_binary'] == 0).sum():,}")
print(f"Attack (1): {(df['Label_binary'] == 1).sum():,}\n")

out_path = r"E:\ids-project\clean_data.pkl"
df.to_pickle(out_path)
print(f"Cleaned data saved: {out_path}")
print("We will use this file in the next step.")