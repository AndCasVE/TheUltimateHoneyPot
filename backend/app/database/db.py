import sqlite3
from pathlib import Path


def get_conn(path: str = "logs/honeypot.db"):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute("""CREATE TABLE IF NOT EXISTS events(timestamp TEXT,session_id TEXT,source_ip TEXT,source_port INT,service TEXT,hostname TEXT,input TEXT,simulated_response TEXT,mitre_technique TEXT,severity TEXT)""")
    return conn
