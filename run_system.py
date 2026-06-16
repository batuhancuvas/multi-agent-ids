# run_system.py
# ANA ORKESTRATOR: dort ajani tam zincire baglar ve FEEDBACK LOOP kurar.
# Akis: IZLEME -> ANALIZ -> KARAR -> MUDAHALE -> (feedback) IZLEME dogrulama
# Su an test verisiyle calisir (Windows). Demo'da gercek trafige baglanacak.

import joblib
import time
from agents_common import log_event
from agent_monitor import MonitorAgent
from agent_analysis import AnalysisAgent
from agent_response import DecisionAgent, ResponseAgent

def verify_block(monitor, response, message):
    """FEEDBACK LOOP: bloklanan IP'den trafik kesildi mi diye dogrula.
    Izleme ajani kontrol eder, sonucu analize geri bildirir."""
    ip = message["src_ip"]
    if response.is_blocked(ip):
        # Gercek sistemde: izleme ajani bu IP'den yeni paket geliyor mu bakar.
        # Simulasyonda: bloklandiysa trafik kesilmis sayariz.
        log_event("IZLEME", f"[feedback] {ip} dogrulandi: trafik kesildi")
        log_event("ANALIZ", f"[feedback] {ip} icin aksiyon BASARILI bilgisi alindi")
        message["feedback"] = "aksiyon_dogrulandi"
    return message

if __name__ == "__main__":
    log_event("SISTEM", "=== TAM SISTEM CALISIYOR (4 ajan + feedback loop) ===")

    # Ajanlari baslat
    monitor = MonitorAgent()
    analysis = AnalysisAgent()
    decision = DecisionAgent()
    response = ResponseAgent(simulation=True)   # Windows'ta simulasyon

    # Test verisinden akislar al
    test = joblib.load(r"E:\ids-project\test_data.pkl")
    X_test = test["X_test"].reset_index(drop=True)
    ym_test = test["ym_test"].reset_index(drop=True)

    # Cesitlilik icin: birkac normal + birkac saldiri akisi sec
    # (saldiri olanlari bul ki blokla senaryosunu gorelim)
    attack_idx = ym_test[ym_test != "BENIGN"].index[:5].tolist()
    normal_idx = ym_test[ym_test == "BENIGN"].index[:5].tolist()
    selected = sorted(normal_idx + attack_idx)

    for count, i in enumerate(selected, 1):
        row = X_test.iloc[i]
        ip = f"10.0.0.{i % 255}"
        # 1. IZLEME: akisi yakala
        msg = monitor.flow_to_message(row, flow_id=count, src_ip=ip)
        # 2. ANALIZ: risk skoru uret
        msg = analysis.analyze(msg)
        # 3. KARAR: aksiyon sec
        msg = decision.decide(msg)
        # 4. MUDAHALE: uygula
        msg = response.act(msg)
        # 5. FEEDBACK LOOP: bloklandiysa dogrula
        msg = verify_block(monitor, response, msg)
        log_event("SISTEM", f"--- Akis {count} tamamlandi ---")

    log_event("SISTEM", f"Bitti. Toplam bloklanan IP: {len(response.blocked_ips)}")