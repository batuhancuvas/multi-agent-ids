import time
import json
from datetime import datetime

def create_message(source_agent, flow_id, src_ip, features=None):
    """Creates a new traffic-flow message (produced by the Monitor agent)."""
    return {
        "flow_id": flow_id,
        "src_ip": src_ip,
        "timestamp": time.time(),
        "features": features or {},
        "source": source_agent,
        "risk_score": None,
        "risk_level": None,
        "decision": None,
        "action_result": None,
    }

LOG_FILE = r"E:\ids-project\system.log"

def log_event(agent_name, message):
    """All agents write events here, to both screen and file."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    line = f"[{timestamp}] [{agent_name}] {message}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")