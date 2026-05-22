from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, List


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SessionEvent:
    ts: str
    session_id: str
    src_ip: str
    src_port: int
    command: str
    deception_response: str
    tactic: str
    technique_id: str
    technique_name: str
    severity: str

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Alert:
    ts: str
    session_id: str
    src_ip: str
    title: str
    severity: str
    mitre_techniques: List[str]
    evidence_commands: List[str]

    def to_dict(self) -> Dict:
        return asdict(self)
