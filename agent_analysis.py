# agent_analysis.py
# ANALIZ AJANI: RF + IF modellerini calistirir, agirlikli oylamayla
# risk skoru uretir. AYRICA davranissal kural katmani:
#   - YUKSEK: port tarama (10+ port) veya SSH brute-force (port 22'ye 5+)
#   - ORTA:   low-and-slow (az sayida porta yavas/tekrarli erisim, kurallari
#             tetiklemeyen ama supheli desen) -> Isolation Forest mantigi
# 3 katmanli tespit: RF (imza) + IF (anomali) + kural (davranis).

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
        log_event("ANALIZ", "Modeller yukleniyor...")
        self.rf = joblib.load(RF_PATH)
        self.iso = joblib.load(IF_PATH)
        cfg = joblib.load(CFG_PATH)
        self.W_RF = cfg["W_RF"]
        self.W_IF = cfg["W_IF"]
        self.features = cfg["features"]
        self.ip_ports = defaultdict(set)
        self.ip_conn_count = defaultdict(int)
        self.ip_first_time = {}          # IP ilk goruldugu zaman (low-and-slow icin)
        self.flagged_ips = set()         # YUKSEK tehdit olarak isaretlenen IP'ler
        self.warned_ips = set()          # ORTA (low-and-slow) olarak isaretlenen IP'ler
        log_event("ANALIZ", "Hazir. RF + IF + davranis kurallari yuklendi.")

    def behavioral_check(self, message):
        """Davranissal kurallar. Doner: (seviye, aciklama)
        seviye: 'YUKSEK', 'ORTA' veya None"""
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
        elapsed = now - self.ip_first_time[ip]   # IP ne kadar suredir aktif

        # --- YUKSEK seviye kurallar (bariz saldiri) ---
        # KURAL 1: Port tarama - cok sayida FARKLI porta erisim
        if distinct_ports >= 10:
            return "YUKSEK", f"Port tarama ({distinct_ports} farkli port)"
        # KURAL 2: SSH brute-force - port 22'ye cok baglanti
        if port == 22 and total_conns >= 5:
            return "YUKSEK", f"SSH brute-force (port 22'ye {total_conns} deneme)"

        # --- ORTA seviye kural (low-and-slow / sinsi sizma) ---
        # Az sayida (2-9) farkli porta, tekrarli erisim: bariz tarama degil
        # ama normal kullanici da boyle davranmaz -> supheli, izlenmeli.
        if 2 <= distinct_ports < 10 and total_conns >= 3:
            return "ORTA", f"Low-and-slow supheli erisim ({distinct_ports} port, {total_conns} baglanti)"

        return None, ""

    def analyze(self, message):
        ip = message["src_ip"]

        # Zaten YUKSEK tehdit olarak isaretlendiyse, sessizce tekrar dondur
        if ip in self.flagged_ips:
            message["risk_score"] = 1.0
            message["risk_level"] = "YUKSEK"
            message["rf_label"] = "(zaten tespit edildi)"
            return message

        feat_values = [[message["features"][f] for f in self.features]]
        X = pd.DataFrame(feat_values, columns=self.features)

        rf_label = self.rf.predict(X)[0]
        rf_vote = 0 if rf_label == "BENIGN" else 1
        if_raw = self.iso.predict(X)[0]
        if_vote = 1 if if_raw == -1 else 0
        risk_score = self.W_RF * rf_vote + self.W_IF * if_vote

        # Davranissal kural katmani
        rule_level, reason = self.behavioral_check(message)
        if rule_level == "YUKSEK":
            risk_score = 1.0
            message["rule_triggered"] = reason
            self.flagged_ips.add(ip)
        elif rule_level == "ORTA":
            # En az ORTA seviyeye cikar (IF zaten yuksekse dokunma)
            if risk_score < 0.3:
                risk_score = 0.3
            message["rule_triggered"] = reason

        if risk_score >= 0.7:
            level = "YUKSEK"
        elif risk_score >= 0.3:
            level = "ORTA"
        else:
            level = "DUSUK"

        message["risk_score"] = round(risk_score, 2)
        message["risk_level"] = level
        message["rf_label"] = rf_label

        # ORTA ve YUKSEK ekrana basilir; DUSUK sessiz (live_monitor ozetler)
        if level == "YUKSEK":
            extra = f" | KURAL: {reason}" if rule_level else ""
            log_event("ANALIZ",
                      f"Akis {message['flow_id']} | RF={rf_label} "
                      f"IF={'anomali' if if_vote else 'normal'} | "
                      f"skor={risk_score:.2f} -> {level}{extra}")
        elif level == "ORTA":
            # ORTA icin tek uyari yeter (ayni IP'yi tekrar basma)
            if ip not in self.warned_ips:
                self.warned_ips.add(ip)
                extra = f" | KURAL: {reason}" if rule_level else ""
                log_event("ANALIZ",
                          f"Akis {message['flow_id']} | RF={rf_label} "
                          f"IF={'anomali' if if_vote else 'normal'} | "
                          f"skor={risk_score:.2f} -> {level}{extra}")
        return message