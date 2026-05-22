from fastapi import FastAPI
from .config import Settings
from .database.db import get_conn
from .listener import TCPListener
from .session_manager import SessionManager
from .reporting.csv_export import export_csv
from .reporting.html_report import export_html
from .reporting.json_export import export_json
from .reporting.markdown_report import export_markdown
from .honeypot_services.linux_shell import LinuxShellService

app=FastAPI(title="Offline AI Honeypot")
settings=Settings()
sessions=SessionManager()
db=get_conn()
service=LinuxShellService()
listener=TCPListener(settings,service,sessions,db)

@app.get("/health")
def health(): return {"status":"ok","offline_mode":settings.offline_mode}

@app.get("/dashboard/summary")
def summary():
    return {"active_sessions":0,"recent_sessions":len(sessions.events),"top_source_ips":sessions.top_source_ips(),"top_mitre":{}}

@app.post("/reports/export")
def export_reports():
    events=sessions.events
    export_json(events); export_csv(events); export_markdown(events); export_html(events)
    return {"ok":True,"files":["reports/report.json","reports/report.csv","reports/report.md","reports/report.html"]}
