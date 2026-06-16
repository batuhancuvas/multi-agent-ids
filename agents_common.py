# agents_common.py
# Amac: Tum ajanlarin ortak kullandigi yapilar.
# - Mesaj formati (ajanlar birbirine bu formatla konusur)
# - Ortak loglama
# Bu dosya tek basina calistirilmaz; diger ajanlar bunu "import" eder.

import time
import json
from datetime import datetime

# --- Ajanlar arasi mesaj formati ---
# Her ajan bir digerine bu sozluk (dict) yapisinda mesaj gonderir.
def create_message(source_agent, flow_id, src_ip, features=None):
    """Yeni bir trafik akisi mesaji olusturur (Izleme Ajani uretir)."""
    return {
        "flow_id": flow_id,           # akisin kimligi
        "src_ip": src_ip,             # trafigin geldigi IP
        "timestamp": time.time(),     # akisin yakalandigi an (TTD/TTR icin)
        "features": features or {},   # 15 ozellik (analiz ajani kullanir)
        "source": source_agent,       # mesaji ureten ajan
        # asagidakiler surec ilerledikce doldurulur:
        "risk_score": None,           # analiz ajani doldurur
        "risk_level": None,           # analiz ajani doldurur (DUSUK/ORTA/YUKSEK)
        "decision": None,             # karar ajani doldurur (logla/uyar/blokla)
        "action_result": None,        # mudahale ajani doldurur (basarili/basarisiz)
    }

# --- Ortak loglama ---
LOG_FILE = r"E:\ids-project\system.log"

def log_event(agent_name, message):
    """Tum ajanlar olaylari buraya yazar. Hem ekrana hem dosyaya."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    line = f"[{timestamp}] [{agent_name}] {message}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")