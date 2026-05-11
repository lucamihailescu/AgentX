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
    cache_key: str | None = None
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
    ollama_examples_per_class: int = 3

    # Chat (mem0 + Ollama embeddings + Qdrant) ─────────────────────────────
    # Falls back to `ollama_model` when unset/empty so a single OLLAMA_MODEL
    # env var configures both the classifier and the chat. Override only to
    # use a different (typically larger) model for chat.
    chat_model: str | None = None
    embed_model: str = "nomic-embed-text"
    embed_dims: int = 768
    qdrant_host: str = "qdrant"
    qdrant_port: int = 6333
    chat_history_window: int = 12         # turns of recent history sent to LLM
    chat_memory_top_k: int = 5            # mem0 results injected into prompt

    # Comma-separated; parsed into BLOCKED_DOMAINS below. Kept as a raw string
    # to avoid pydantic-settings auto-JSON-decoding it.
    blocked_domains: str = ""
    suggest_block_threshold: int = 3
    suggest_max_items: int = 5

    model_config = SettingsConfigDict(env_file=".env", env_prefix="AGENT_", extra="ignore")


settings = Settings()

BLOCKED_DOMAINS: frozenset[str] = frozenset(
    d.strip().lower() for d in settings.blocked_domains.split(",") if d.strip()
)
