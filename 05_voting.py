import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix)

print("Loading models and test data...")
rf = joblib.load(r"E:\ids-project\rf_model.pkl")
iso = joblib.load(r"E:\ids-project\if_model.pkl")
test = joblib.load(r"E:\ids-project\test_data.pkl")
X_test = test["X_test"]
yb_test = test["yb_test"]

rf_multi = rf.predict(X_test)
rf_pred = (rf_multi != "BENIGN").astype(int)
if_raw = iso.predict(X_test)
if_pred = (if_raw == -1).astype(int)

W_RF = 0.7
W_IF = 0.3
risk_score = W_RF * rf_pred + W_IF * if_pred

def risk_level(score):
    if score >= 0.7:
        return "HIGH"
    elif score >= 0.3:
        return "MEDIUM"
    else:
        return "LOW"

levels = np.array([risk_level(s) for s in risk_score])

print("\n" + "="*55)
print("RISK LEVEL DISTRIBUTION (ensemble decision)")
print("="*55)
unique, counts = np.unique(levels, return_counts=True)
for lvl, cnt in zip(unique, counts):
    action = {"LOW": "log", "MEDIUM": "warn / monitor",
              "HIGH": "block IP"}[lvl]
    print(f"  {lvl:7s}: {cnt:>8,} records  ->  action: {action}")
print("="*55)

ensemble_pred = (risk_score >= 0.3).astype(int)

vote_or = ((rf_pred == 1) | (if_pred == 1)).astype(int)
vote_and = ((rf_pred == 1) & (if_pred == 1)).astype(int)

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
    evaluate("Random Forest (only)", yb_test, rf_pred),
    evaluate("Isolation Forest (only)", yb_test, if_pred),
    evaluate("Voting - OR", yb_test, vote_or),
    evaluate("Voting - AND", yb_test, vote_and),
    evaluate("Ensemble (MEDIUM+HIGH=attack)", yb_test, ensemble_pred),
]

table = pd.DataFrame(results)
pd.set_option("display.width", 120)
pd.set_option("display.float_format", lambda x: f"{x:.4f}")
print("\n" + "="*80)
print("COMPARISON TABLE (same test data)")
print("="*80)
print(table.to_string(index=False))
print("="*80)

table.to_csv(r"E:\ids-project\comparison_results.csv", index=False)
print("\nTable saved: comparison_results.csv (you can put it in the report)")

config = {"W_RF": W_RF, "W_IF": W_IF,
          "threshold_medium": 0.3, "threshold_high": 0.7,
          "features": test["features"]}
joblib.dump(config, r"E:\ids-project\voting_config.pkl")
print("Voting settings saved: voting_config.pkl (used by the agents)")