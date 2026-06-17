import joblib
import numpy as np
import pandas as pd
import time
from collections import defaultdict
from agents_common import log_event

RF_PATH = "/home/batu/ids-project/rf_model.pkl"
IF_PATH = "/home/batu/ids-project/if_model.pkl"
CFG_PATH = "/home/batu/ids-project/voting_config.pkl"

class AnalysisAgent:
    def __init__(self):
        log_event("ANALYSIS", "Loading models...")
        self.rf = joblib.load(RF_PATH)
        self.iso = joblib.load(IF_PATH)
        cfg = joblib.load(CFG_PATH)
        self.W_RF = cfg["W_RF"]
        self.W_IF = cfg["W_IF"]
        self.features = cfg["features"]
        self.ip_ports = defaultdict(set)
        self.ip_conn_count = defaultdict(int)
        self.ip_first_time = {}
        self.flagged_ips = set()
        self.warned_ips = set()
        log_event("ANALYSIS", "Ready. RF + IF + behavioral rules loaded.")

    def behavioral_check(self, message):
        """Behavioral rules. Returns: (level, reason)
        level: 'HIGH', 'MEDIUM' or None"""
        ip = message["src_ip"]
        feats = message["features"]
        port = int(feats.get("Destination Port", 0))
        now = time.time()

        self.ip_ports[ip].add(port)
        self.ip_conn_count[ip] += 1
        if ip not in self.ip_first_time:
            self.ip_first_time[ip] = now

        distinct_ports = len(self.ip_ports[ip])
        total_conns = self.ip_conn_count[ip]
        elapsed = now - self.ip_first_time[ip]

        if distinct_ports >= 10:
            return "HIGH", f"Port scan ({distinct_ports} distinct ports)"
        auth_fails = message.get("auth_failures", 0)
        if port == 22 and total_conns >= 5:
            if auth_fails > 0:
                return "HIGH", f"SSH brute-force ({total_conns} connections on port 22, {auth_fails} failed logins in auth.log)"
            return "HIGH", f"SSH brute-force ({total_conns} attempts on port 22)"
        if auth_fails >= 5:
            return "HIGH", f"SSH brute-force ({auth_fails} failed logins in auth.log)"

        if 2 <= distinct_ports < 10 and total_conns >= 3:
            return "MEDIUM", f"Low-and-slow suspicious access ({distinct_ports} ports, {total_conns} connections)"

        return None, ""

    def analyze(self, message):
        ip = message["src_ip"]

        if ip in self.flagged_ips:
            message["risk_score"] = 1.0
            message["risk_level"] = "HIGH"
            message["rf_label"] = "(already detected)"
            return message

        feat_values = [[message["features"][f] for f in self.features]]
        X = pd.DataFrame(feat_values, columns=self.features)

        rf_label = self.rf.predict(X)[0]
        rf_vote = 0 if rf_label == "BENIGN" else 1
        if_raw = self.iso.predict(X)[0]
        if_vote = 1 if if_raw == -1 else 0
        risk_score = self.W_RF * rf_vote + self.W_IF * if_vote

        rule_level, reason = self.behavioral_check(message)
        if rule_level == "HIGH":
            risk_score = 1.0
            message["rule_triggered"] = reason
            self.flagged_ips.add(ip)
        elif rule_level == "MEDIUM":
            if risk_score < 0.3:
                risk_score = 0.3
            message["rule_triggered"] = reason

        if risk_score >= 0.7:
            level = "HIGH"
        elif risk_score >= 0.3:
            level = "MEDIUM"
        else:
            level = "LOW"

        message["risk_score"] = round(risk_score, 2)
        message["risk_level"] = level
        message["rf_label"] = rf_label

        if level == "HIGH":
            extra = f" | RULE: {reason}" if rule_level else ""
            log_event("ANALYSIS",
                      f"Flow {message['flow_id']} | RF={rf_label} "
                      f"IF={'anomaly' if if_vote else 'normal'} | "
                      f"score={risk_score:.2f} -> {level}{extra}")
        elif level == "MEDIUM":
            if ip not in self.warned_ips:
                self.warned_ips.add(ip)
                extra = f" | RULE: {reason}" if rule_level else ""
                log_event("ANALYSIS",
                          f"Flow {message['flow_id']} | RF={rf_label} "
                          f"IF={'anomaly' if if_vote else 'normal'} | "
                          f"score={risk_score:.2f} -> {level}{extra}")
        return message