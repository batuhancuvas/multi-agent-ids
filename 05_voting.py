# 05_voting.py
# Amac: RF ve IF'i bir VOTING (oylama) mekanizmasiyla birlestirmek.
# Ensemble artik tek bir 0/1 degil, 3 SEVIYELI RISK SKORU uretiyor:
#   - DUSUK  : ikisi de temiz        -> sadece logla
#   - ORTA   : sadece IF anomali der -> uyari (potansiyel yeni/zero-day saldiri)
#   - YUKSEK : RF bilinen saldiri der -> IP blokla
# Bu, karar ajaninin skora gore farkli aksiyon secmesini saglar.

import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix)

# --- 1. Modelleri ve test verisini yukle ---
print("Modeller ve test verisi yukleniyor...")
rf = joblib.load(r"E:\ids-project\rf_model.pkl")
iso = joblib.load(r"E:\ids-project\if_model.pkl")
test = joblib.load(r"E:\ids-project\test_data.pkl")
X_test = test["X_test"]
yb_test = test["yb_test"]   # gercek: 0=normal, 1=saldiri

# --- 2. Her modelin tahmini ---
rf_multi = rf.predict(X_test)
rf_pred = (rf_multi != "BENIGN").astype(int)   # RF: 0/1
if_raw = iso.predict(X_test)
if_pred = (if_raw == -1).astype(int)           # IF: 0/1

# --- 3. AGIRLIKLI RISK SKORU ---
# Her modele oy agirligi ver. RF daha guvenilir -> agirligi yuksek.
W_RF = 0.7
W_IF = 0.3
risk_score = W_RF * rf_pred + W_IF * if_pred   # 0.0, 0.3, 0.7 veya 1.0

# --- 4. RISK SEVIYESI (karar ajaninin kullanacagi 3 seviye) ---
# skor 0.0        -> DUSUK  (ikisi de temiz)
# skor 0.3        -> ORTA   (sadece IF anomali: olasi yeni saldiri)
# skor 0.7 / 1.0  -> YUKSEK (RF bilinen saldiri buldu)
def risk_level(score):
    if score >= 0.7:
        return "YUKSEK"
    elif score >= 0.3:
        return "ORTA"
    else:
        return "DUSUK"

levels = np.array([risk_level(s) for s in risk_score])

# --- 5. Risk seviyesi dagilimi ---
print("\n" + "="*55)
print("RISK SEVIYESI DAGILIMI (ensemble karari)")
print("="*55)
unique, counts = np.unique(levels, return_counts=True)
for lvl, cnt in zip(unique, counts):
    aksiyon = {"DUSUK": "logla", "ORTA": "uyari uret / izle",
               "YUKSEK": "IP blokla"}[lvl]
    print(f"  {lvl:7s}: {cnt:>8,} kayit  ->  aksiyon: {aksiyon}")
print("="*55)

# --- 6. Karsilastirma icin: ensemble'i ikiliye indirgeme ---
# Degerlendirmede ORTA ve YUKSEK'i "saldiri" (1), DUSUK'u "normal" (0) sayariz.
ensemble_pred = (risk_score >= 0.3).astype(int)

# Karsilastirma icin OR ve AND oylamasi da hesaplayalim
vote_or = ((rf_pred == 1) | (if_pred == 1)).astype(int)
vote_and = ((rf_pred == 1) & (if_pred == 1)).astype(int)

# --- 7. Metrik fonksiyonu ---
def evaluate(name, y_true, y_pred):
    acc  = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec  = recall_score(y_true, y_pred, zero_division=0)
    f1   = f1_score(y_true, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    fpr = fp / (fp + tn)
    return {"Model": name, "Accuracy": acc, "Precision": prec,
            "Recall": rec, "F1": f1, "FPR": fpr}

results = [
    evaluate("Random Forest (tek)", yb_test, rf_pred),
    evaluate("Isolation Forest (tek)", yb_test, if_pred),
    evaluate("Voting - OR", yb_test, vote_or),
    evaluate("Voting - AND", yb_test, vote_and),
    evaluate("Ensemble (ORTA+YUKSEK=saldiri)", yb_test, ensemble_pred),
]

# --- 8. Karsilastirma tablosu ---
table = pd.DataFrame(results)
pd.set_option("display.width", 120)
pd.set_option("display.float_format", lambda x: f"{x:.4f}")
print("\n" + "="*80)
print("KARSILASTIRMA TABLOSU (ayni test verisi)")
print("="*80)
print(table.to_string(index=False))
print("="*80)

table.to_csv(r"E:\ids-project\comparison_results.csv", index=False)
print("\nTablo kaydedildi: comparison_results.csv (rapora koyabilirsin)")

# --- 9. Voting agirliklari ve esikleri bir dosyaya kaydet ---
# (Ajanlar bu ayarlari kullanacak, tek yerden yonetelim)
config = {"W_RF": W_RF, "W_IF": W_IF,
          "esik_orta": 0.3, "esik_yuksek": 0.7,
          "features": test["features"]}
joblib.dump(config, r"E:\ids-project\voting_config.pkl")
print("Voting ayarlari kaydedildi: voting_config.pkl (ajanlar kullanacak)")