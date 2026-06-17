import pandas as pd
import numpy as np
import joblib
import time
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix, classification_report)

print("Loading cleaned data...")
df = pd.read_pickle(r"E:\ids-project\clean_data.pkl")
print(f"Data: {len(df):,} rows\n")

FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Mean",
    "Bwd Packet Length Mean", "Fwd Packet Length Max",
    "Bwd Packet Length Max", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Max", "Flow IAT Min",
]

X = df[FEATURES]
y_multi = df["Label_multi"]
y_binary = df["Label_binary"]

print("Splitting data into train/test (70% train, 30% test)...")
X_train, X_test, ym_train, ym_test, yb_train, yb_test = train_test_split(
    X, y_multi, y_binary, test_size=0.30, random_state=42, stratify=y_multi
)
print(f"Train: {len(X_train):,} rows  |  Test: {len(X_test):,} rows\n")

print("Training Random Forest... (may take a few minutes)")
rf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
t0 = time.time()
rf.fit(X_train, ym_train)
train_time = time.time() - t0
print(f"Training done. Time: {train_time:.1f} seconds\n")

print("Predicting on test data...")
ym_pred = rf.predict(X_test)

acc_multi = accuracy_score(ym_test, ym_pred)

yb_pred = (ym_pred != "BENIGN").astype(int)
prec = precision_score(yb_test, yb_pred)
rec  = recall_score(yb_test, yb_pred)
f1   = f1_score(yb_test, yb_pred)

cm = confusion_matrix(yb_test, yb_pred)
tn, fp, fn, tp = cm.ravel()
fpr = fp / (fp + tn)

print("\n" + "="*50)
print("RANDOM FOREST RESULTS")
print("="*50)
print(f"Multi-class accuracy (attack type): {acc_multi:.4f}")
print(f"Binary Accuracy: {accuracy_score(yb_test, yb_pred):.4f}")
print(f"Precision      : {prec:.4f}")
print(f"Recall         : {rec:.4f}")
print(f"F1-Score       : {f1:.4f}")
print(f"False Positive Rate (FPR): {fpr:.4f}")
print(f"Training time  : {train_time:.1f} seconds")
print("="*50)

joblib.dump(rf, r"E:\ids-project\rf_model.pkl")
joblib.dump(
    {"X_test": X_test, "yb_test": yb_test, "ym_test": ym_test, "features": FEATURES},
    r"E:\ids-project\test_data.pkl"
)
print("\nSaved: rf_model.pkl (model) + test_data.pkl (test data)")
print("Next step: evaluate Isolation Forest on the same test data.")