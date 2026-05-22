from pathlib import Path

def export_markdown(events:list,path="reports/report.md"):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    lines=["# AI Honeypot Session Report","","## Executive Summary",f"Events: {len(events)}","","## Timeline of Activity"]
    lines += [f"- {e['timestamp']} {e['source_ip']} {e['input']} -> {e['severity']}" for e in events]
    lines += ["","## Suggested Splunk SPL","index=honeypot sourcetype=ai_honeypot | stats count by source_ip", "","## Suggested Sentinel KQL","AIHoneypot_CL | summarize count() by SourceIP_s"]
    Path(path).write_text("\n".join(lines),encoding="utf-8")
