# 04_train_if.py
# Amac: Isolation Forest egitmek. Bu model DENETIMSIZ (unsupervised):
# ona saldiri etiketi VERMEYIZ. Sadece NORMAL trafigi gosterip
# "normal boyle gorunur" diye ogretiriz. Normalden sapan her sey
# anomali olarak isaretlenir -> bilinmeyen/yeni saldirilari yakalar.

import pandas as pd
import numpy as np
import joblib
import time
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix)

# --- 1. Veriyi ve kayitli test setini yukle ---
print("Veri yukleniyor...")
df = pd.read_pickle(r"E:\ids-project\clean_data.pkl")
test = joblib.load(r"E:\ids-project\test_data.pkl")
X_test = test["X_test"]
yb_test = test["yb_test"]
FEATURES = test["features"]

# --- 2. Egitim icin SADECE normal trafik ---
# Isolation Forest'i sadece normal (BENIGN) ornekleriyle egitiyoruz.
# RF ile ayni satirlari test'e ayirmak icin test indekslerini cikariyoruz.
df_train = df.drop(index=X_test.index)              # test disindaki kisim
normal_train = df_train[df_train["Label_binary"] == 0]   # sadece normal
X_normal = normal_train[FEATURES]
print(f"Egitim icin normal trafik: {len(X_normal):,} satir\n")

# Cok buyuk; egitimi hizlandirmak icin ornekleme (200.000 yeterli)
if len(X_normal) > 200000:
    X_normal = X_normal.sample(n=200000, random_state=42)
    print(f"Hizlandirmak icin orneklendi: {len(X_normal):,} satir\n")

# --- 3. Isolation Forest egitimi ---
# contamination: verinin ne kadarinin anomali oldugu tahmini.
# Sadece normalle egittigimiz icin dusuk tutuyoruz.
# n_estimators=100: 100 izolasyon agaci
print("Isolation Forest egitiliyor...")
iso = IsolationForest(n_estimators=100, contamination=0.05,
                      n_jobs=-1, random_state=42)
t0 = time.time()
iso.fit(X_normal)
train_time = time.time() - t0
print(f"Egitim tamamlandi. Sure: {train_time:.1f} saniye\n")

# --- 4. Test verisinde tahmin ---
# IF ciktisi: +1 = normal, -1 = anomali.
# Bizim etiket: 0 = normal, 1 = saldiri. Donusturuyoruz.
print("Test verisinde tahmin yapiliyor...")
raw_pred = iso.predict(X_test)              # +1 veya -1
if_pred = (raw_pred == -1).astype(int)      # -1(anomali)->1(saldiri), +1->0

# --- 5. Metrikler (RF ile ayni test, adil karsilastirma) ---
acc  = accuracy_score(yb_test, if_pred)
prec = precision_score(yb_test, if_pred, zero_division=0)
rec  = recall_score(yb_test, if_pred, zero_division=0)
f1   = f1_score(yb_test, if_pred, zero_division=0)
cm = confusion_matrix(yb_test, if_pred)
tn, fp, fn, tp = cm.ravel()
fpr = fp / (fp + tn)

print("\n" + "="*50)
print("ISOLATION FOREST SONUCLARI")
print("="*50)
print(f"Accuracy       : {acc:.4f}")
print(f"Precision      : {prec:.4f}")
print(f"Recall         : {rec:.4f}")
print(f"F1-Score       : {f1:.4f}")
print(f"False Positive Rate (FPR): {fpr:.4f}")
print(f"Egitim suresi  : {train_time:.1f} saniye")
print("="*50)

# --- 6. Modeli kaydet ---
joblib.dump(iso, r"E:\ids-project\if_model.pkl")
print("\nKaydedildi: if_model.pkl")
print("Sonraki adimda RF + IF'i voting ile birlestirip karsilastiracagiz.")