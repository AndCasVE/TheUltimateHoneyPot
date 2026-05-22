from dataclasses import dataclass, field


@dataclass
class ServiceProfile:
    name: str
    banner: str
    hostname: str
    prompt: str
    users: list[str] = field(default_factory=list)
    fake_files: dict[str, str] = field(default_factory=dict)
    system_prompt: str = ""


class BaseService:
    profile: ServiceProfile

    def login_success(self, username: str, password: str, trigger: dict) -> bool:
        return trigger.get("type") != "fake_login" or (
            username == trigger.get("username") and password == trigger.get("password")
        )

    def respond(self, command: str, session_ctx: dict) -> str:
        raise NotImplementedError
