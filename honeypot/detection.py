from typing import Dict, Tuple

ATTACK_MAP: Dict[str, Tuple[str, str, str, str]] = {
    "whoami": ("Discovery", "T1033", "System Owner/User Discovery", "low"),
    "id": ("Discovery", "T1033", "System Owner/User Discovery", "low"),
    "uname": ("Discovery", "T1082", "System Information Discovery", "low"),
    "hostname": ("Discovery", "T1082", "System Information Discovery", "low"),
    "cat /etc/passwd": ("Credential Access", "T1003.008", "/etc/passwd and /etc/shadow", "medium"),
    "wget": ("Command and Control", "T1105", "Ingress Tool Transfer", "high"),
    "curl": ("Command and Control", "T1105", "Ingress Tool Transfer", "high"),
    "chmod": ("Execution", "T1059", "Command and Scripting Interpreter", "high"),
    "./": ("Execution", "T1059", "Command and Scripting Interpreter", "high"),
    "bash ": ("Execution", "T1059", "Command and Scripting Interpreter", "high"),
    "python": ("Execution", "T1059.006", "Python", "high"),
    "nc": ("Command and Control", "T1095", "Non-Application Layer Protocol", "high"),
}


def map_command(command: str):
    c = command.strip().lower()
    for k, v in ATTACK_MAP.items():
        if c.startswith(k):
            return v
    return ("Unknown", "T0000", "Unclassified", "info")
