import yaml
from pathlib import Path


def load_enterprise_profile(path: str = "configs/fake_enterprise_profile.yaml") -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
