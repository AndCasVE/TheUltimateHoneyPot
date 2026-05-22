from .base import BaseService, ServiceProfile

class WindowsCmdService(BaseService):
    def __init__(self):
        self.profile = ServiceProfile("windows_cmd","Microsoft Windows [Version 10.0.17763.0]","WKST-FIN-044","C:\\> ",["CORP\\svc-reporting"],{},"Simulated cmd.exe only")

    def respond(self, command: str, session_ctx: dict) -> str:
        c=command.lower().strip()
        if c=="whoami": return "corp\\svc-reporting"
        if c.startswith("systeminfo"): return "Host Name: WKST-FIN-044\nOS Name: Microsoft Windows Server 2019"
        if c.startswith("type "): return "The system cannot find the file specified."
        return "'{}' is not recognized as an internal or external command,".format(command.split()[0] if command else "")
