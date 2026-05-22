from dataclasses import dataclass


@dataclass(frozen=True)
class HoneypotConfig:
    host: str = "127.0.0.1"
    port: int = 2222
    banner: str = "Ubuntu 20.04.6 LTS srv-gw01 ttyS0"
    fake_hostname: str = "srv-gw01"
    fake_user: str = "backup"
    fake_uid: int = 1002
    fake_gid: int = 1002
    prompt: str = "backup@srv-gw01:~$ "
    artifacts_dir: str = "artifacts"
    enable_transcript_echo: bool = True


GUARDRAILS = {
    "defensive_only": True,
    "cloud_ai_disabled": True,
    "execute_attacker_input": False,
    "real_credentials_allowed": False,
    "egress_block_expected": True,
}
