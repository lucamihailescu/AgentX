from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # ── Microsoft (Outlook.com) ──────────────────────────────────────────
    client_id: str | None = None
    client_secret: str | None = None
    authority: str = "https://login.microsoftonline.com/consumers"
    redirect_uri: str = "http://localhost:8080/auth/microsoft/callback"
    scopes: list[str] = ["Mail.ReadWrite"]

    # ── Google (Gmail) ───────────────────────────────────────────────────
    google_client_id: str | None = None
    google_client_secret: str | None = None
    google_redirect_uri: str = "http://localhost:8080/auth/google/callback"
    google_scopes: list[str] = ["https://www.googleapis.com/auth/gmail.modify"]

    session_secret: str
    db_path: str = "tasks.db"
    worker_poll_interval_seconds: float = 2.0
    default_schedule_interval_minutes: int | None = None
    scheduler_tick_seconds: float = 60.0

    max_messages_per_audit: int = 200

    ollama_url: str = "http://host.docker.internal:11434"
    ollama_model: str = "llama3.2"
    ollama_timeout_seconds: float = 30.0
    ollama_concurrency: int = 4
    ollama_num_ctx: int = 1024
    ollama_temperature: float = 0.0
    ollama_num_predict: int = 200

    # Comma-separated; parsed into BLOCKED_DOMAINS below. Kept as a raw string
    # to avoid pydantic-settings auto-JSON-decoding it.
    blocked_domains: str = ""

    model_config = SettingsConfigDict(env_file=".env", env_prefix="AGENT_", extra="ignore")


settings = Settings()

BLOCKED_DOMAINS: frozenset[str] = frozenset(
    d.strip().lower() for d in settings.blocked_domains.split(",") if d.strip()
)
