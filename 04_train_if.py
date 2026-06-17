import pandas as pd
import numpy as np
import joblib
import time
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix)

print("Loading data...")
df = pd.read_pickle(r"E:\ids-project\clean_data.pkl")
test = joblib.load(r"E:\ids-project\test_data.pkl")
X_test = test["X_test"]
yb_test = test["yb_test"]
FEATURES = test["features"]

df_train = df.drop(index=X_test.index)
normal_train = df_train[df_train["Label_binary"] == 0]
X_normal = normal_train[FEATURES]
print(f"Normal traffic for training: {len(X_normal):,} rows\n")

if len(X_normal) > 200000:
    X_normal = X_normal.sample(n=200000, random_state=42)
    print(f"Sampled to speed up: {len(X_normal):,} rows\n")

print("Training Isolation Forest...")
iso = IsolationForest(n_estimators=100, contamination=0.05,
                      n_jobs=-1, random_state=42)
t0 = time.time()
iso.fit(X_normal)
train_time = time.time() - t0
print(f"Training done. Time: {train_time:.1f} seconds\n")

print("Predicting on test data...")
raw_pred = iso.predict(X_test)
if_pred = (raw_pred == -1).astype(int)

acc  = accuracy_score(yb_test, if_pred)
prec = precision_score(yb_test, if_pred, zero_division=0)
rec  = recall_score(yb_test, if_pred, zero_division=0)
f1   = f1_score(yb_test, if_pred, zero_division=0)
cm = confusion_matrix(yb_test, if_pred)
tn, fp, fn, tp = cm.ravel()
fpr = fp / (fp + tn)

print("\n" + "="*50)
print("ISOLATION FOREST RESULTS")
print("="*50)
print(f"Accuracy       : {acc:.4f}")
print(f"Precision      : {prec:.4f}")
print(f"Recall         : {rec:.4f}")
print(f"F1-Score       : {f1:.4f}")
print(f"False Positive Rate (FPR): {fpr:.4f}")
print(f"Training time  : {train_time:.1f} seconds")
print("="*50)

joblib.dump(iso, r"E:\ids-project\if_model.pkl")
print("\nSaved: if_model.pkl")
print("Next step: combine RF + IF with voting and compare.")