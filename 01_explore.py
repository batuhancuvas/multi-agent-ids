# 01_explore.py
# Amac: CICIDS2017 veri setini tanimak. Henuz model egitmiyoruz,
# sadece veride ne oldugunu, kac satir oldugunu ve sorunlu deger
# olup olmadigini goruyoruz.

import pandas as pd
import numpy as np
import os
import glob

# Veri setinin bulundugu klasor
DATA_DIR = r"E:\ids-project\MachineLearningCVE"

# Klasordeki tum CSV dosyalarini bul
csv_files = glob.glob(os.path.join(DATA_DIR, "*.csv"))
print(f"Bulunan CSV dosya sayisi: {len(csv_files)}\n")

# Her dosyayi tek tek okuyup ozetini cikar
all_dataframes = []
for file in csv_files:
    name = os.path.basename(file)
    print(f"Okunuyor: {name}")
    df = pd.read_csv(file, low_memory=False)
    print(f"  Satir sayisi: {len(df):,}  |  Sutun sayisi: {df.shape[1]}")
    all_dataframes.append(df)
    print()

# Tum dosyalari tek bir buyuk tabloda birlestir
print("Tum dosyalar birlestiriliyor...")
data = pd.concat(all_dataframes, ignore_index=True)
print(f"Birlesik toplam satir sayisi: {len(data):,}")
print(f"Toplam sutun sayisi: {data.shape[1]}\n")

# Sutun isimlerinin basinda/sonunda bosluk olabilir, temizleyelim
data.columns = data.columns.str.strip()

# Etiket (Label) sutununda hangi saldiri tipleri var ve kacar tane?
print("=== Saldiri tipleri ve sayilari (Label sutunu) ===")
print(data["Label"].value_counts())
print()

# Veri saglik kontrolu: bozuk degerler var mi?
# CICIDS2017'de bilinen sorun: sonsuz (inf) ve eksik (NaN) degerler
n_inf = np.isinf(data.select_dtypes(include=[np.number])).sum().sum()
n_nan = data.isnull().sum().sum()
print("=== Veri saglik kontrolu ===")
print(f"Sonsuz (inf) deger sayisi: {n_inf:,}")
print(f"Eksik (NaN) deger sayisi: {n_nan:,}")