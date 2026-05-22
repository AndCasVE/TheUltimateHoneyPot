import csv
from pathlib import Path

def export_csv(events:list, path="reports/report.csv"):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    if not events: return
    with open(path,"w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=list(events[0].keys())); w.writeheader(); w.writerows(events)
