from honeypot.config import GUARDRAILS, HoneypotConfig
from honeypot.engine import HoneypotServer


def main():
    print("[+] Starting offline defensive honeypot")
    print(f"[+] Guardrails: {GUARDRAILS}")
    cfg = HoneypotConfig()
    server = HoneypotServer(cfg)
    server.serve_forever()


if __name__ == "__main__":
    main()
