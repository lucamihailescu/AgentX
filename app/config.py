from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    client_id: str
    client_secret: str
    authority: str = "https://login.microsoftonline.com/consumers"
    redirect_uri: str = "http://localhost:8080/auth/callback"
    scopes: list[str] = ["Mail.ReadWrite"]

    session_secret: str
    db_path: str = "tasks.db"
    worker_poll_interval_seconds: float = 2.0

    max_messages_per_audit: int = 200

    ollama_url: str = "http://host.docker.internal:11434"
    ollama_model: str = "llama3.2"
    ollama_timeout_seconds: float = 30.0
    ollama_concurrency: int = 4

    # Comma-separated; parsed into BLOCKED_DOMAINS below. Kept as a raw string
    # to avoid pydantic-settings auto-JSON-decoding it.
    blocked_domains: str = ""

    model_config = SettingsConfigDict(env_file=".env", env_prefix="AGENT_", extra="ignore")


settings = Settings()

BLOCKED_DOMAINS: frozenset[str] = frozenset(
    d.strip().lower() for d in settings.blocked_domains.split(",") if d.strip()
)
