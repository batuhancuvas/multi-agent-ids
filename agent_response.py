import subprocess
import time
from agents_common import log_event

class DecisionAgent:
    def decide(self, message):
        level = message["risk_level"]
        if level == "HIGH":
            decision = "BLOCK"
        elif level == "MEDIUM":
            decision = "WARN"
        else:
            decision = "LOG"
        message["decision"] = decision
        return message

class ResponseAgent:
    def __init__(self, simulation=True):
        self.simulation = simulation
        self.blocked_ips = set()
        self.warned_ips = set()
        self.attack_start = {}
        mode = "SIMULATION" if simulation else "REAL (iptables)"
        log_event("RESPONSE", f"Ready. Mode: {mode}")

    def note_attack_start(self, ip, ts):
        """Called when attack behavior is first seen (records only the first time)."""
        if ip not in self.attack_start:
            self.attack_start[ip] = ts

    def act(self, message):
        decision = message["decision"]
        ip = message["src_ip"]

        if decision == "LOG":
            message["action_result"] = "logged"

        elif decision == "WARN":
            if ip not in self.warned_ips:
                self.warned_ips.add(ip)
                log_event("RESPONSE", f"WARNING: {ip} suspicious (medium risk), monitoring")
            message["action_result"] = "warning_raised"

        elif decision == "BLOCK":
            if ip not in self.blocked_ips:
                detect_time = time.time()
                start = self.attack_start.get(ip, detect_time)
                ttd = detect_time - start

                reason = message.get("rule_triggered", message.get("rf_label", "attack"))
                log_event("RESPONSE", f">>> THREAT DETECTED: {ip} | {reason}")
                log_event("RESPONSE", f">>> Time to Detect (TTD): {ttd:.3f} seconds")

                t0 = time.time()
                self._block_ip(ip)
                ttr = time.time() - t0

                log_event("RESPONSE", f">>> ACTION: {ip} BLOCKED via iptables")
                log_event("RESPONSE", f">>> Time to Respond (TTR): {ttr*1000:.1f} ms")
            message["action_result"] = "blocked"

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
                log_event("RESPONSE", f"[ERROR] iptables failed: {e}")

    def is_blocked(self, ip):
        return ip in self.blocked_ips