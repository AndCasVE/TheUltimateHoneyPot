# Offline AI Honeypot

Offline defensive honeypot for blue team/purple team exercises.

## Safety
Never executes commands, no cloud AI, local-only default bind, simulated outputs only.

## Run locally
```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## TCP listener
Instantiate `TCPListener` from `app.listener` to run on `127.0.0.1:2222`.

## Docker
`docker compose up --build`

## Offline model setup
Supports local provider patterns (Ollama/llama.cpp/LM Studio) through offline-only architecture. Cloud endpoints blocked by config validation.

## Splunk/Sentinel
Use `logs/session_events.jsonl` or exported report JSON.

## Windows installer (offline)
- `pyinstaller --onefile --name OfflineAIHoneypot backend\app\main.py`
- Package frontend static assets.
- Install configs/logs/reports into `C:\ProgramData\OfflineAIHoneypot\...` via Inno Setup/NSIS.

## Known limitations
Current dashboard UI is minimal and service personalities beyond Linux/Windows are starter stubs.
