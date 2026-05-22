from pathlib import Path

def export_html(events:list,path="reports/report.html"):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    rows="".join([f"<tr><td>{e['timestamp']}</td><td>{e['source_ip']}</td><td>{e['input']}</td><td>{e['severity']}</td></tr>" for e in events])
    Path(path).write_text(f"<html><body><h1>AI Honeypot Session Report</h1><table>{rows}</table></body></html>",encoding="utf-8")
