# 03_train_rf.py
# Amac: Random Forest modelini egitmek. Bu model DENETIMLI (supervised):
# etiketli veriyle egitilir ve BILINEN saldiri tiplerini tanir.
# Ayrica veriyi train/test diye boluyoruz; test kismini kaydedip
# sonraki adimlarda (Isolation Forest, voting) ayni test ile adil
# karsilastirma yapacagiz.

import pandas as pd
import numpy as np
import joblib
import time
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix, classification_report)

# --- 1. Temiz veriyi yukle ---
print("Temiz veri yukleniyor...")
df = pd.read_pickle(r"E:\ids-project\clean_data.pkl")
print(f"Veri: {len(df):,} satir\n")

# Egitimde kullanacagimiz 15 ozellik (02_prepare ile ayni sira)
FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Mean",
    "Bwd Packet Length Mean", "Fwd Packet Length Max",
    "Bwd Packet Length Max", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Max", "Flow IAT Min",
]

X = df[FEATURES]
y_multi = df["Label_multi"]    # saldiri tipi (BENIGN, PortScan, SSH-Patator...)
y_binary = df["Label_binary"]  # 0 = normal, 1 = saldiri

# --- 2. Egitim / test bolmesi ---
# stratify: her sinifin orani train ve test'te ayni kalsin
print("Veri egitim/test olarak bolunuyor (%70 egitim, %30 test)...")
X_train, X_test, ym_train, ym_test, yb_train, yb_test = train_test_split(
    X, y_multi, y_binary, test_size=0.30, random_state=42, stratify=y_multi
)
print(f"Egitim: {len(X_train):,} satir  |  Test: {len(X_test):,} satir\n")

# --- 3. Random Forest egitimi ---
# n_estimators=100: 100 karar agaci
# n_jobs=-1: tum islemci cekirdeklerini kullan (hizlandirir)
print("Random Forest egitiliyor... (birkac dakika surebilir)")
rf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
t0 = time.time()
rf.fit(X_train, ym_train)
train_time = time.time() - t0
print(f"Egitim tamamlandi. Sure: {train_time:.1f} saniye\n")

# --- 4. Test verisinde tahmin ---
print("Test verisinde tahmin yapiliyor...")
ym_pred = rf.predict(X_test)

# (a) Cok-sinifli dogruluk: saldiri TIPINI ne kadar dogru bildi?
acc_multi = accuracy_score(ym_test, ym_pred)

# (b) Ikili metrikler: "saldiri var mi yok mu" performansi
# Tahminleri ikiliye cevir: BENIGN -> 0, diger her sey -> 1
yb_pred = (ym_pred != "BENIGN").astype(int)
prec = precision_score(yb_test, yb_pred)
rec  = recall_score(yb_test, yb_pred)
f1   = f1_score(yb_test, yb_pred)

# Confusion matrix: [[TN, FP], [FN, TP]]
cm = confusion_matrix(yb_test, yb_pred)
tn, fp, fn, tp = cm.ravel()
fpr = fp / (fp + tn)   # False Positive Rate

# --- 5. Sonuclari yazdir ---
print("\n" + "="*50)
print("RANDOM FOREST SONUCLARI")
print("="*50)
print(f"Cok-sinifli dogruluk (saldiri tipi): {acc_multi:.4f}")
print(f"Ikili Accuracy : {accuracy_score(yb_test, yb_pred):.4f}")
print(f"Precision      : {prec:.4f}")
print(f"Recall         : {rec:.4f}")
print(f"F1-Score       : {f1:.4f}")
print(f"False Positive Rate (FPR): {fpr:.4f}")
print(f"Egitim suresi  : {train_time:.1f} saniye")
print("="*50)

# --- 6. Model ve test verisini kaydet ---
joblib.dump(rf, r"E:\ids-project\rf_model.pkl")
joblib.dump(
    {"X_test": X_test, "yb_test": yb_test, "ym_test": ym_test, "features": FEATURES},
    r"E:\ids-project\test_data.pkl"
)
print("\nKaydedildi: rf_model.pkl (model) + test_data.pkl (test verisi)")
print("Sonraki adimda Isolation Forest'i ayni test verisiyle degerlendirecegiz.")