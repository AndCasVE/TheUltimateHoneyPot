import secrets
import socket
import threading
from honeypot.config import HoneypotConfig
from honeypot.deception import DeceptionResponder
from honeypot.detection import map_command
from honeypot.evidence import EvidenceStore
from honeypot.models import Alert, SessionEvent, utc_now


class HoneypotServer:
    def __init__(self, cfg: HoneypotConfig):
        self.cfg = cfg
        self.responder = DeceptionResponder(cfg)
        self.store = EvidenceStore(cfg.artifacts_dir)
        self._shutdown = threading.Event()

    def serve_forever(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.cfg.host, self.cfg.port))
            server.listen(20)
            print(f"[+] Honeypot listening on {self.cfg.host}:{self.cfg.port}")
            while not self._shutdown.is_set():
                client, addr = server.accept()
                t = threading.Thread(target=self._handle_client, args=(client, addr), daemon=True)
                t.start()

    def _handle_client(self, client: socket.socket, addr):
        src_ip, src_port = addr
        session_id = secrets.token_hex(8)
        with client:
            client.sendall((self.cfg.banner + "\nlogin: ").encode())
            _ = self._recv_line(client)
            client.sendall(b"Password: ")
            _ = self._recv_line(client)
            client.sendall(("Last login: Fri May 22 03:03:00 UTC 2026\n" + self.cfg.prompt).encode())

            while True:
                cmd = self._recv_line(client)
                if cmd is None:
                    break
                cmd = cmd.strip()
                if cmd in {"exit", "quit"}:
                    client.sendall(b"logout\n")
                    break

                tactic, tid, tname, sev = map_command(cmd)
                response = self.responder.respond(cmd)

                evt = SessionEvent(
                    ts=utc_now(),
                    session_id=session_id,
                    src_ip=src_ip,
                    src_port=src_port,
                    command=cmd,
                    deception_response=response,
                    tactic=tactic,
                    technique_id=tid,
                    technique_name=tname,
                    severity=sev,
                )
                self.store.record_event(evt)

                if sev in {"high", "critical"}:
                    alert = Alert(
                        ts=utc_now(),
                        session_id=session_id,
                        src_ip=src_ip,
                        title=f"High-risk activity from {src_ip}",
                        severity=sev,
                        mitre_techniques=[tid],
                        evidence_commands=[cmd],
                    )
                    self.store.record_alert(alert)

                client.sendall((response + "\n" + self.cfg.prompt).encode())

        self.store.finalize()

    @staticmethod
    def _recv_line(client: socket.socket):
        data = b""
        while True:
            b = client.recv(1)
            if not b:
                return None
            if b in {b"\n", b"\r"}:
                return data.decode(errors="ignore")
            data += b
