from pydantic import BaseModel, Field, field_validator


class AccessTrigger(BaseModel):
    type: str = "fake_login"
    username: str = "admin"
    password: str = "password123"
    max_attempts: int = 5
    simulated_cve: str | None = None
    pattern: list[int] = Field(default_factory=list)


class AIConfig(BaseModel):
    ai_provider: str = "ollama"
    ollama_url: str = "http://127.0.0.1:11434"
    model_name: str = "llama3.1"
    temperature: float = 0.1
    max_tokens: int = 500


class Settings(BaseModel):
    offline_mode: bool = True
    bind_address: str = "127.0.0.1"
    listener_port: int = 2222
    allow_external_bind: bool = False
    execute_commands: bool = False
    allow_outbound_network: bool = False
    use_cloud_ai: bool = False
    store_real_credentials: bool = False
    dashboard_bind_address: str = "127.0.0.1"
    dashboard_port: int = 8080
    lab_override_enabled: bool = False
    service_type: str = "linux_shell"
    access_trigger: AccessTrigger = Field(default_factory=AccessTrigger)
    ai: AIConfig = Field(default_factory=AIConfig)

    @field_validator("bind_address", "dashboard_bind_address")
    @classmethod
    def safe_bind(cls, v: str) -> str:
        if v != "127.0.0.1":
            raise ValueError("External bind blocked unless explicitly overridden in lab build")
        return v

    @field_validator("use_cloud_ai", "execute_commands", "allow_outbound_network", "store_real_credentials")
    @classmethod
    def enforce_offline_safety(cls, v: bool) -> bool:
        if v:
            raise ValueError("Unsafe setting blocked by defensive safety policy")
        return v
