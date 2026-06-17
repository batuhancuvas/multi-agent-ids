import joblib
import pandas as pd
from agents_common import create_message, log_event
from agent_analysis import AnalysisAgent

class MonitorAgent:
    def __init__(self):
        cfg = joblib.load(r"E:\ids-project\voting_config.pkl")
        self.features = cfg["features"]
        log_event("MONITOR", "Ready. Starting traffic monitoring.")

    def flow_to_message(self, row, flow_id, src_ip):
        """Converts a data row (a flow) into an agent message."""
        feats = {f: float(row[f]) for f in self.features}
        return create_message("MONITOR", flow_id, src_ip, features=feats)

if __name__ == "__main__":
    log_event("SYSTEM", "=== Monitor -> Analysis integration test ===")

    test = joblib.load(r"E:\ids-project\test_data.pkl")
    X_test = test["X_test"].reset_index(drop=True)

    monitor = MonitorAgent()
    analysis = AnalysisAgent()

    for i in range(10):
        row = X_test.iloc[i]
        msg = monitor.flow_to_message(row, flow_id=i+1, src_ip=f"192.168.1.{i+1}")
        msg = analysis.analyze(msg)

    log_event("SYSTEM", "Test done. Monitor and Analysis agents are working.")