import json
from datetime import datetime, timezone

MITRE = {
    "id": "T1557.002",
    "name": "Adversary-in-the-Middle: ARP Cache Poisoning",
}

def build_event(alert):
    """Transforme une alerte de analyze() en événement prêt à logger."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detector": "arp-guard",
        "type": alert["type"],
        "message": alert["msg"],
        "ip": alert.get("ip"),
        "mac": alert.get("mac"),
        "mitre_attack": MITRE,
    }

def write_event(event, path="arpguard_alerts.jsonl"):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")