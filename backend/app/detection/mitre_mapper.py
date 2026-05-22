MAP=[("whoami","T1033","System Owner/User Discovery","Low"),("id","T1033","System Owner/User Discovery","Low"),("hostname","T1082","System Information Discovery","Low"),("uname","T1082","System Information Discovery","Low"),("ifconfig","T1016","System Network Configuration Discovery","Low"),("ip addr","T1016","System Network Configuration Discovery","Low"),("/etc/passwd","T1087","Account Discovery","Medium"),("net user","T1087","Account Discovery","Medium"),("ls","T1083","File and Directory Discovery","Low"),("dir","T1083","File and Directory Discovery","Low"),("password","T1552","Unsecured Credentials","High"),(".env","T1552","Unsecured Credentials","High"),("crontab","T1053","Scheduled Task/Job","High"),("systemctl enable","T1547","Boot or Logon Autostart","High"),("ssh","T1021","Remote Services","High"),("psexec","T1021","Remote Services","High"),("curl","T1105","Ingress Tool Transfer","High"),("wget","T1105","Ingress Tool Transfer","High")]

def map_command(cmd:str):
    c=cmd.lower()
    for k,t,n,s in MAP:
        if k in c:
            return {"mitre_technique":f"{t} - {n}","mitre_tactic":"Discovery" if t in {"T1033","T1082","T1016","T1083"} else "Credential Access","severity":s}
    return {"mitre_technique":"T0000 - Unclassified","mitre_tactic":"Unknown","severity":"Info"}
