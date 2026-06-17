import time
import threading
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP

from agents_common import create_message, log_event
from agent_analysis import AnalysisAgent
from agent_response import DecisionAgent, ResponseAgent
from agent_logwatch import LogWatchAgent

IFACE = "enp0s8"
FLOW_TIMEOUT = 2.0
SUMMARY_INTERVAL = 10.0

class Flow:
    """Represents a flow (same source-destination-port group)."""
    def __init__(self, src_ip):
        self.src_ip = src_ip
        self.start_time = time.time()
        self.last_time = self.start_time
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.fwd_lengths = []
        self.bwd_lengths = []
        self.timestamps = []
        self.dst_port = 0

    def add_packet(self, pkt, is_forward):
        now = time.time()
        self.last_time = now
        self.timestamps.append(now)
        length = len(pkt)
        if is_forward:
            self.fwd_packets += 1
            self.fwd_bytes += length
            self.fwd_lengths.append(length)
        else:
            self.bwd_packets += 1
            self.bwd_bytes += length
            self.bwd_lengths.append(length)
        if pkt.haslayer(TCP):
            self.dst_port = int(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            self.dst_port = int(pkt[UDP].dport)

    def to_features(self):
        duration = max((self.last_time - self.start_time) * 1_000_000, 1)
        iats = []
        for i in range(1, len(self.timestamps)):
            iats.append((self.timestamps[i] - self.timestamps[i-1]) * 1_000_000)
        iat_mean = sum(iats)/len(iats) if iats else 0
        iat_max = max(iats) if iats else 0
        iat_min = min(iats) if iats else 0
        total_packets = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_bytes + self.bwd_bytes
        def mean(lst): return sum(lst)/len(lst) if lst else 0
        def mx(lst): return max(lst) if lst else 0
        return {
            "Destination Port": self.dst_port,
            "Flow Duration": duration,
            "Total Fwd Packets": self.fwd_packets,
            "Total Backward Packets": self.bwd_packets,
            "Total Length of Fwd Packets": self.fwd_bytes,
            "Total Length of Bwd Packets": self.bwd_bytes,
            "Fwd Packet Length Mean": mean(self.fwd_lengths),
            "Bwd Packet Length Mean": mean(self.bwd_lengths),
            "Fwd Packet Length Max": mx(self.fwd_lengths),
            "Bwd Packet Length Max": mx(self.bwd_lengths),
            "Flow Bytes/s": total_bytes / (duration/1_000_000),
            "Flow Packets/s": total_packets / (duration/1_000_000),
            "Flow IAT Mean": iat_mean,
            "Flow IAT Max": iat_max,
            "Flow IAT Min": iat_min,
        }

class LiveMonitor:
    def __init__(self):
        self.analysis = AnalysisAgent()
        self.decision = DecisionAgent()
        self.response = ResponseAgent(simulation=False)
        self.logwatch = LogWatchAgent()
        self.flows = defaultdict(lambda: None)
        self.flow_counter = 0
        self.low_risk_count = 0
        self.last_summary = time.time()
        log_event("MONITOR", f"Live monitoring started. Interface: {IFACE}")

    def get_my_ip(self):
        return "192.168.56.103"

    def process_packet(self, pkt):
        if not pkt.haslayer(IP):
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        my_ip = self.get_my_ip()
        dport = 0
        if pkt.haslayer(TCP):
            dport = int(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            dport = int(pkt[UDP].dport)
        if src == my_ip:
            key = (dst, dport)
            is_forward = False
            flow_ip = dst
        else:
            key = (src, dport)
            is_forward = True
            flow_ip = src
        if self.flows[key] is None:
            self.flows[key] = Flow(src_ip=flow_ip)
        self.flows[key].add_packet(pkt, is_forward)

    def evaluate_flows(self):
        while True:
            time.sleep(FLOW_TIMEOUT)
            now = time.time()
            expired = []
            for key, flow in list(self.flows.items()):
                if flow is None:
                    continue
                if now - flow.last_time >= FLOW_TIMEOUT:
                    expired.append(key)

            for key in expired:
                flow = self.flows.pop(key)
                if flow is None:
                    continue
                self.flow_counter += 1
                feats = flow.to_features()
                msg = create_message("MONITOR", self.flow_counter, flow.src_ip, features=feats)
                self.logwatch.check()
                msg["auth_failures"] = self.logwatch.get_total_failures(flow.src_ip)
                dport = int(feats.get("Destination Port", 0))
                if dport == 22 or dport in range(1, 1025):
                    self.response.note_attack_start(flow.src_ip, flow.start_time)
                msg = self.analysis.analyze(msg)
                msg = self.decision.decide(msg)
                msg = self.response.act(msg)
                if msg["risk_level"] == "LOW":
                    self.low_risk_count += 1

            if now - self.last_summary >= SUMMARY_INTERVAL:
                if self.low_risk_count > 0:
                    log_event("MONITOR",
                              f"Normal traffic summary: {self.low_risk_count} flows "
                              f"logged as LOW risk (not blocked)")
                    self.low_risk_count = 0
                self.last_summary = now

    def start(self):
        t = threading.Thread(target=self.evaluate_flows, daemon=True)
        t.start()
        log_event("MONITOR", "Capturing packets... (Ctrl+C to stop)")
        sniff(iface=IFACE, prn=self.process_packet, store=False)

if __name__ == "__main__":
    monitor = LiveMonitor()
    monitor.start()