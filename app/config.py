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
    # When set (e.g. https://agent.example.com), the agent assumes it's
    # reachable on this URL over HTTPS. OAuth redirect URIs derive from
    # it, the session cookie gets the Secure flag, and CSRF protection
    # is enforced on every state-changing form post. Leave None for
    # localhost dev.
    public_base_url: str | None = None
    worker_poll_interval_seconds: float = 2.0
    default_schedule_interval_minutes: int | None = None
    scheduler_tick_seconds: float = 60.0
    # Digest cadence in days. Per-user override on `users.digest_interval_days`
    # wins. 0 / None disables.
    default_digest_interval_days: int | None = 7

    max_messages_per_audit: int = 200

    ollama_url: str = "http://host.docker.internal:11434"
    ollama_model: str = "llama3.2"
    ollama_timeout_seconds: float = 30.0
    ollama_concurrency: int = 4
    ollama_num_ctx: int = 1024
    ollama_temperature: float = 0.0
    ollama_num_predict: int = 200
    ollama_examples_per_class: int = 3
    # Blend per-sender prior (from accumulated delete/unsub actions) into
    # the model's verdict. Disable to make Ollama's call authoritative.
    calibration_enabled: bool = True

    # ── Rspamd second-opinion classifier ─────────────────────────────────
    # When set, every message classified by Ollama is also checked against
    # Rspamd and the two verdicts are blended (plus the per-sender prior).
    # Set to None / empty to disable. User actions (delete/unsub/allow/deny)
    # additionally train Rspamd's per-user Bayes when enabled.
    rspamd_url: str | None = None
    # Weight of Rspamd's verdict in the blend, relative to Ollama (weight 1.0).
    # 0.6 ≈ "trusted second opinion"; 1.0 = equal vote; 0 disables.
    rspamd_weight: float = 0.6
    rspamd_timeout_seconds: float = 3.0

    # Chat (mem0 + Ollama embeddings + ChromaDB) ──────────────────────────
    # Falls back to `ollama_model` when unset/empty so a single OLLAMA_MODEL
    # env var configures both the classifier and the chat. Override only to
    # use a different (typically larger) model for chat.
    chat_model: str | None = None
    embed_model: str = "nomic-embed-text"
    embed_dims: int = 768
    # Directory where ChromaDB persists its in-process collections. Sits
    # inside the same /data bind mount as the SQLite db.
    chroma_path: str = "/data/chroma"
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


def redirect_uri_for(provider_name: str) -> str:
    """Return the OAuth callback URL for a provider.

    When `public_base_url` is configured (cloudflared / public hostname),
    derive from it so callbacks land on the external HTTPS URL. Otherwise
    fall back to the per-provider env setting (localhost by default).
    """
    if settings.public_base_url:
        base = settings.public_base_url.rstrip("/")
        return f"{base}/auth/{provider_name}/callback"
    if provider_name == "microsoft":
        return settings.redirect_uri
    if provider_name == "google":
        return settings.google_redirect_uri
    raise ValueError(f"Unknown provider: {provider_name}")
