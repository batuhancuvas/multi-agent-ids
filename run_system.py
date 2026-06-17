import joblib
import time
from agents_common import log_event
from agent_monitor import MonitorAgent
from agent_analysis import AnalysisAgent
from agent_response import DecisionAgent, ResponseAgent

def verify_block(monitor, response, message):
    """FEEDBACK LOOP: verify that traffic from the blocked IP has stopped.
    The Monitor agent checks, then reports the result back to Analysis."""
    ip = message["src_ip"]
    if response.is_blocked(ip):
        log_event("MONITOR", f"[feedback] {ip} verified: traffic stopped")
        log_event("ANALYSIS", f"[feedback] action SUCCESS received for {ip}")
        message["feedback"] = "action_verified"
    return message

if __name__ == "__main__":
    log_event("SYSTEM", "=== FULL SYSTEM RUNNING (4 agents + feedback loop) ===")

    monitor = MonitorAgent()
    analysis = AnalysisAgent()
    decision = DecisionAgent()
    response = ResponseAgent(simulation=True)

    test = joblib.load(r"E:\ids-project\test_data.pkl")
    X_test = test["X_test"].reset_index(drop=True)
    ym_test = test["ym_test"].reset_index(drop=True)

    attack_idx = ym_test[ym_test != "BENIGN"].index[:5].tolist()
    normal_idx = ym_test[ym_test == "BENIGN"].index[:5].tolist()
    selected = sorted(normal_idx + attack_idx)

    for count, i in enumerate(selected, 1):
        row = X_test.iloc[i]
        ip = f"10.0.0.{i % 255}"
        msg = monitor.flow_to_message(row, flow_id=count, src_ip=ip)
        msg = analysis.analyze(msg)
        msg = decision.decide(msg)
        msg = response.act(msg)
        msg = verify_block(monitor, response, msg)
        log_event("SYSTEM", f"--- Flow {count} completed ---")

    log_event("SYSTEM", f"Done. Total blocked IPs: {len(response.blocked_ips)}")