# agent_response.py
# KARAR AJANI + MUDAHALE AJANI.
# Mudahale ajani TTD (Time to Detect) ve TTR (Time to Respond) olcer:
#   TTD = saldiri DAVRANISININ basladigi an -> tespit edildigi an
#   TTR = tespit ani -> bloklama tamamlandigi an
# Not: TTD, arka plan trafigini degil, saldiriyla ilgili ilk supheli
# akisi baslangic alir (daha dogru olcum).

import subprocess
import time
from agents_common import log_event

# ---------------- KARAR AJANI ----------------
class DecisionAgent:
    def decide(self, message):
        level = message["risk_level"]
        if level == "YUKSEK":
            decision = "BLOKLA"
        elif level == "ORTA":
            decision = "UYAR"
        else:
            decision = "LOGLA"
        message["decision"] = decision
        return message


# ---------------- MUDAHALE AJANI ----------------
class ResponseAgent:
    def __init__(self, simulation=True):
        self.simulation = simulation
        self.blocked_ips = set()
        self.warned_ips = set()
        # Her IP icin saldiri davranisinin ILK goruldugu an (TTD icin)
        self.attack_start = {}
        mode = "SIMULASYON" if simulation else "GERCEK (iptables)"
        log_event("MUDAHALE", f"Hazir. Mod: {mode}")

    def note_attack_start(self, ip, ts):
        """Saldiri davranisi ilk goruldugunde cagrilir (sadece ilk seferde kaydeder)."""
        if ip not in self.attack_start:
            self.attack_start[ip] = ts

    def act(self, message):
        decision = message["decision"]
        ip = message["src_ip"]

        if decision == "LOGLA":
            message["action_result"] = "loglandi"

        elif decision == "UYAR":
            if ip not in self.warned_ips:
                self.warned_ips.add(ip)
                log_event("MUDAHALE", f"UYARI: {ip} supheli (orta risk), izleniyor")
            message["action_result"] = "uyari_uretildi"

        elif decision == "BLOKLA":
            if ip not in self.blocked_ips:
                # --- TTD: saldiri davranisinin basladigi andan tespit anina kadar ---
                detect_time = time.time()
                start = self.attack_start.get(ip, detect_time)
                ttd = detect_time - start

                reason = message.get("rule_triggered", message.get("rf_label", "saldiri"))
                log_event("MUDAHALE", f">>> THREAT DETECTED: {ip} | {reason}")
                log_event("MUDAHALE", f">>> Time to Detect (TTD): {ttd:.3f} saniye")

                # --- TTR: tespit aninda bloklamayi baslat, suresini olc ---
                t0 = time.time()
                self._block_ip(ip)
                ttr = time.time() - t0

                log_event("MUDAHALE", f">>> ACTION: {ip} BLOCKED via iptables")
                log_event("MUDAHALE", f">>> Time to Respond (TTR): {ttr*1000:.1f} ms")
            message["action_result"] = "bloklandi"

        return message

    def _block_ip(self, ip):
        self.blocked_ips.add(ip)
        if self.simulation:
            pass
        else:
            try:
                subprocess.run(
                    ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True
                )
            except Exception as e:
                log_event("MUDAHALE", f"[ERROR] iptables failed: {e}")

    def is_blocked(self, ip):
        return ip in self.blocked_ips