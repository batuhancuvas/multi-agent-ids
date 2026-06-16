# agent_monitor.py
# IZLEME AJANI: Su an gercek ag yerine TEST VERISINDEN akis okur
# (gercek trafik yakalama Ubuntu demo adiminda gelecek).
# Her akistan 15 ozelligi cikarir, mesaj olusturur.
# Bu dosya ayni zamanda ilk ENTEGRASYON TESTI: izleme -> analiz.

import joblib
import pandas as pd
from agents_common import create_message, log_event
from agent_analysis import AnalysisAgent

class MonitorAgent:
    def __init__(self):
        cfg = joblib.load(r"E:\ids-project\voting_config.pkl")
        self.features = cfg["features"]
        log_event("IZLEME", "Hazir. Trafik izlemeye basliyor.")

    def flow_to_message(self, row, flow_id, src_ip):
        """Bir veri satirini (akisi) ajan mesajina cevirir."""
        feats = {f: float(row[f]) for f in self.features}
        return create_message("IZLEME", flow_id, src_ip, features=feats)


# ---------------- ENTEGRASYON TESTI ----------------
if __name__ == "__main__":
    log_event("SISTEM", "=== Izleme -> Analiz entegrasyon testi ===")

    # Test verisinden birkac ornek akis al
    test = joblib.load(r"E:\ids-project\test_data.pkl")
    X_test = test["X_test"].reset_index(drop=True)

    monitor = MonitorAgent()
    analysis = AnalysisAgent()

    # Ilk 10 akisi ajanlardan gecir
    for i in range(10):
        row = X_test.iloc[i]
        # src_ip: simdilik sahte bir IP (demo'da gercek IP gelecek)
        msg = monitor.flow_to_message(row, flow_id=i+1, src_ip=f"192.168.1.{i+1}")
        msg = analysis.analyze(msg)

    log_event("SISTEM", "Test bitti. Izleme ve Analiz ajanlari calisiyor.")