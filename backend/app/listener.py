import json, secrets, socket, threading
from datetime import datetime, timezone
from pathlib import Path
from .detection.mitre_mapper import map_command


def now(): return datetime.now(timezone.utc).isoformat()

class TCPListener:
    def __init__(self, settings, service, session_manager, db_conn):
        self.settings=settings; self.service=service; self.sessions=session_manager; self.db=db_conn

    def serve(self):
        s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((self.settings.bind_address,self.settings.listener_port)); s.listen(5)
        while True:
            c,a=s.accept(); threading.Thread(target=self.handle,args=(c,a),daemon=True).start()

    def handle(self, client, addr):
        sid=secrets.token_hex(4); ip,port=addr; ctx={"hostname":self.service.profile.hostname,"user":self.service.profile.users[0] if self.service.profile.users else "user"}
        client.sendall((self.service.profile.banner+"\nlogin: ").encode()); user=self._line(client); client.sendall(b"Password: "); pw=self._line(client)
        ok=self.service.login_success(user,pw,self.settings.access_trigger.model_dump())
        if not ok: client.sendall(b"Access denied\n"); client.close(); return
        client.sendall(self.service.profile.prompt.encode())
        while True:
            cmd=self._line(client)
            if cmd is None or cmd in {"exit","quit"}: break
            out=self.service.respond(cmd,ctx); mapped=map_command(cmd)
            ev={"timestamp":now(),"session_id":sid,"source_ip":ip,"source_port":port,"service":self.service.profile.name,"hostname":ctx["hostname"],"username_attempted":user,"authenticated":True,"input":cmd,"simulated_response":out,"event_type":"command",**mapped,"tags":["honeypot"]}
            self.sessions.record(ev); self._store(ev); client.sendall((out+"\n"+self.service.profile.prompt).encode())
        client.close()

    def _store(self,e):
        Path("logs").mkdir(exist_ok=True)
        with open("logs/session_events.jsonl","a",encoding="utf-8") as f: f.write(json.dumps(e)+"\n")
        self.db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?)",(e["timestamp"],e["session_id"],e["source_ip"],e["source_port"],e["service"],e["hostname"],e["input"],e["simulated_response"],e["mitre_technique"],e["severity"])); self.db.commit()

    def _line(self,c):
        b=b""
        while True:
            ch=c.recv(1)
            if not ch:return None
            if ch in {b"\n",b"\r"}: return b.decode(errors="ignore").strip()
            b+=ch
