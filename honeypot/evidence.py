import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import List

from honeypot.models import Alert, SessionEvent


class EvidenceStore:
    def __init__(self, artifacts_dir: str):
        self.base = Path(artifacts_dir)
        self.base.mkdir(parents=True, exist_ok=True)
        self.events: List[SessionEvent] = []
        self.alerts: List[Alert] = []

    def record_event(self, event: SessionEvent):
        self.events.append(event)
        with (self.base / "session_events.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(event.to_dict()) + "\n")

    def record_alert(self, alert: Alert):
        self.alerts.append(alert)
        with (self.base / "alerts.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(alert.to_dict()) + "\n")

    def finalize(self):
        techniques = Counter()
        by_ip = defaultdict(int)
        for e in self.events:
            techniques[e.technique_id] += 1
            by_ip[e.src_ip] += 1

        ioc_summary = {
            "unique_source_ips": list(by_ip.keys()),
            "command_count_by_ip": dict(by_ip),
            "mitre_technique_frequency": dict(techniques),
            "total_events": len(self.events),
            "total_alerts": len(self.alerts),
        }

        with (self.base / "ioc_summary.json").open("w", encoding="utf-8") as f:
            json.dump(ioc_summary, f, indent=2)

        with (self.base / "soc_report.md").open("w", encoding="utf-8") as f:
            f.write("# SOC Incident Summary (Defensive Honeypot)\n\n")
            f.write(f"- Total commands observed: {len(self.events)}\n")
            f.write(f"- Total alerts raised: {len(self.alerts)}\n")
            f.write(f"- Unique source IPs: {len(by_ip)}\n\n")
            f.write("## Top MITRE ATT&CK Techniques\n")
            for tid, count in techniques.most_common(10):
                f.write(f"- {tid}: {count}\n")
