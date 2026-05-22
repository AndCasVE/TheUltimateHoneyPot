class SessionManager:
    def __init__(self): self.events=[]
    def record(self,event): self.events.append(event)
    def top_source_ips(self):
        out={}
        for e in self.events: out[e["source_ip"]]=out.get(e["source_ip"],0)+1
        return out
