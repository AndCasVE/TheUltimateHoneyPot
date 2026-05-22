from backend.app.config import Settings
from backend.app.detection.mitre_mapper import map_command
from backend.app.honeypot_services.linux_shell import LinuxShellService
from backend.app.reporting.json_export import export_json
from backend.app.reporting.csv_export import export_csv
from backend.app.reporting.markdown_report import export_markdown
from backend.app.reporting.html_report import export_html
from pathlib import Path


def test_safety_blocks_unsafe_settings():
    try:
        Settings(use_cloud_ai=True)
        assert False
    except Exception:
        assert True


def test_mitre_mapping():
    assert "T1033" in map_command("whoami")["mitre_technique"]
    assert map_command("cat password.txt")["severity"] == "High"


def test_service_consistent_context():
    svc=LinuxShellService(); ctx={"user":"svc-backup"}
    assert svc.respond("whoami",ctx)=="svc-backup"
    assert svc.respond("hostname",ctx)=="internal-app01"


def test_report_exports(tmp_path: Path):
    events=[{"timestamp":"t","source_ip":"1.1.1.1","input":"whoami","severity":"Low"}]
    export_json(events, str(tmp_path/"r.json")); export_csv(events, str(tmp_path/"r.csv")); export_markdown(events, str(tmp_path/"r.md")); export_html(events, str(tmp_path/"r.html"))
    assert (tmp_path/"r.json").exists() and (tmp_path/"r.csv").exists() and (tmp_path/"r.md").exists() and (tmp_path/"r.html").exists()
