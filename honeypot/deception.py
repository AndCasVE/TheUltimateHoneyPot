import random
import re
from honeypot.config import HoneypotConfig


class DeceptionResponder:
    """Offline generative-style responder with strict non-execution behavior."""

    def __init__(self, cfg: HoneypotConfig):
        self.cfg = cfg

    def respond(self, command: str) -> str:
        c = command.strip()
        if not c:
            return ""

        patterns = [
            (r"^whoami$", lambda: self.cfg.fake_user),
            (r"^id$", lambda: f"uid={self.cfg.fake_uid}({self.cfg.fake_user}) gid={self.cfg.fake_gid}({self.cfg.fake_user}) groups={self.cfg.fake_gid}({self.cfg.fake_user})"),
            (r"^hostname$", lambda: self.cfg.fake_hostname),
            (r"^uname -a$", lambda: "Linux srv-gw01 5.4.0-174-generic #194-Ubuntu SMP x86_64 GNU/Linux"),
            (r"^cat /etc/passwd$", self._fake_passwd),
            (r"^(curl|wget)\b", self._fake_fetch),
            (r"^(chmod|chown|./|bash |sh )", self._fake_exec_denied),
            (r"^(python|perl|nc|ncat|socat)\b", self._fake_missing),
            (r"^ls( .*)?$", self._fake_ls),
            (r"^ps( .*)?$", self._fake_ps),
        ]

        for pat, fn in patterns:
            if re.search(pat, c):
                return fn() if callable(fn) else str(fn)

        return random.choice([
            f"bash: {c.split()[0]}: command not found",
            "Permission denied",
            "Operation not permitted",
        ])

    def _fake_passwd(self) -> str:
        return "\n".join([
            "root:x:0:0:root:/root:/bin/bash",
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            "backup:x:1002:1002:Backup Operator:/home/backup:/bin/bash",
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
        ])

    def _fake_fetch(self) -> str:
        return "Connecting... failed: Temporary failure in name resolution"

    def _fake_exec_denied(self) -> str:
        return "bash: permission denied: execution prevented by kernel policy"

    def _fake_missing(self) -> str:
        return "command unavailable in restricted profile"

    def _fake_ls(self) -> str:
        return "backup.sh\nlogs\ntmp\nREADME.old"

    def _fake_ps(self) -> str:
        return "  PID TTY          TIME CMD\n 1021 pts/0    00:00:00 bash\n 1088 pts/0    00:00:00 ps"
