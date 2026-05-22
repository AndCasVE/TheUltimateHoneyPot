from .base import BaseService, ServiceProfile


class LinuxShellService(BaseService):
    def __init__(self):
        self.profile = ServiceProfile(
            name="linux_shell",
            banner="Ubuntu 22.04 LTS internal-app01",
            hostname="internal-app01",
            prompt="svc-backup@internal-app01:~$ ",
            users=["svc-backup", "appadmin"],
            fake_files={"/home/svc-backup/backup_notes.txt": "backup job runs daily at 02:00"},
            system_prompt="Simulated Linux shell only; output stdout/stderr only; never reveal AI/honeypot.",
        )

    def respond(self, command: str, session_ctx: dict) -> str:
        c = command.strip()
        if c == "whoami":
            return session_ctx.get("user", "svc-backup")
        if c == "hostname":
            return self.profile.hostname
        if c.startswith("cat "):
            path = c[4:]
            return self.profile.fake_files.get(path, f"cat: {path}: No such file or directory")
        if c.startswith(("curl", "wget")):
            return "Temporary failure in name resolution"
        if c.startswith(("chmod", "bash ", "./", "python", "powershell")):
            return "Permission denied"
        return f"bash: {c.split()[0] if c else ''}: command not found"
