import pandas as pd
import numpy as np
import os
import glob

DATA_DIR = r"E:\ids-project\MachineLearningCVE"

csv_files = glob.glob(os.path.join(DATA_DIR, "*.csv"))
print(f"Number of CSV files found: {len(csv_files)}\n")

all_dataframes = []
for file in csv_files:
    name = os.path.basename(file)
    print(f"Reading: {name}")
    df = pd.read_csv(file, low_memory=False)
    print(f"  Rows: {len(df):,}  |  Columns: {df.shape[1]}")
    all_dataframes.append(df)
    print()

print("Merging all files...")
data = pd.concat(all_dataframes, ignore_index=True)
print(f"Total merged rows: {len(data):,}")
print(f"Total columns: {data.shape[1]}\n")

data.columns = data.columns.str.strip()

print("=== Attack types and counts (Label column) ===")
print(data["Label"].value_counts())
print()

n_inf = np.isinf(data.select_dtypes(include=[np.number])).sum().sum()
n_nan = data.isnull().sum().sum()
print("=== Data health check ===")
print(f"Infinite (inf) values: {n_inf:,}")
print(f"Missing (NaN) values: {n_nan:,}")