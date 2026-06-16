# 02_prepare.py
# Amac: Veriyi temizlemek (bozuk degerleri atmak) ve canlida
# kullanabilecegimiz 15 ozelligi secmek. Sonucu kaydedip bir
# sonraki adimda (model egitimi) hizlica kullanacagiz.

import pandas as pd
import numpy as np
import os
import glob

DATA_DIR = r"E:\ids-project\MachineLearningCVE"

# --- 1. Tum CSV'leri oku ve birlestir ---
print("Dosyalar okunuyor...")
csv_files = glob.glob(os.path.join(DATA_DIR, "*.csv"))
data = pd.concat(
    [pd.read_csv(f, low_memory=False) for f in csv_files],
    ignore_index=True
)
# Sutun isimlerindeki bosluklari temizle
data.columns = data.columns.str.strip()
print(f"Birlesik veri: {len(data):,} satir, {data.shape[1]} sutun\n")

# --- 2. Canlida cikarabilecegimiz 15 ozellik ---
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

# Secilen ozellikler veride gercekten var mi kontrol et
missing = [f for f in SELECTED_FEATURES if f not in data.columns]
if missing:
    print("UYARI! Su ozellikler veride bulunamadi:")
    for m in missing:
        print(f"  - {m}")
    print("\nVerideki tum sutun isimleri:")
    for c in data.columns:
        print(f"  {c}")
    raise SystemExit("Once eksik ozellik isimlerini duzeltmemiz lazim.")
else:
    print("Secilen 15 ozelligin hepsi veride mevcut.\n")

# --- 3. Sadece secili ozellikleri + etiketi tut ---
df = data[SELECTED_FEATURES + ["Label"]].copy()

# --- 4. Bozuk degerleri temizle ---
# Sonsuz (inf) degerleri once NaN yap, sonra tum NaN satirlarini at
before = len(df)
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
after = len(df)
print(f"Bozuk deger temizligi: {before - after:,} satir atildi.")
print(f"Kalan satir sayisi: {after:,}\n")

# --- 5. Iki tur etiket olustur ---
# (a) Cok-sinifli: Random Forest icin (saldiri tipini tanir)
df["Label_multi"] = df["Label"]
# (b) Ikili: 0 = normal, 1 = saldiri (genel degerlendirme icin)
df["Label_binary"] = (df["Label"] != "BENIGN").astype(int)

print("=== Temizlik sonrasi sinif dagilimi ===")
print(df["Label_multi"].value_counts())
print()
print(f"Normal (0): {(df['Label_binary'] == 0).sum():,}")
print(f"Saldiri (1): {(df['Label_binary'] == 1).sum():,}\n")

# --- 6. Temizlenmis veriyi kaydet ---
out_path = r"E:\ids-project\clean_data.pkl"
df.to_pickle(out_path)
print(f"Temizlenmis veri kaydedildi: {out_path}")
print("Bir sonraki adimda bu dosyayi kullanacagiz.")