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
    # Human-readable build identifier shown in the UI footer. Baked into the
    # image at build time (Dockerfile ARG BUILD_VERSION → AGENT_BUILD_VERSION),
    # so every running build is identifiable. Defaults to "dev" for local runs.
    build_version: str = "dev"
    # When set (e.g. https://agent.example.com), the agent assumes it's
    # reachable on this URL over HTTPS. OAuth redirect URIs derive from
    # it, the session cookie gets the Secure flag, and CSRF protection
    # is enforced on every state-changing form post. Leave None for
    # localhost dev.
    public_base_url: str | None = None
    worker_poll_interval_seconds: float = 2.0
    default_schedule_interval_minutes: int | None = None
    scheduler_tick_seconds: float = 60.0

    # ── Real-time polling (delta) ────────────────────────────────────────
    # Poll each enabled user's inbox for newly-arrived mail and scan it in
    # near-real-time, instead of waiting for the next scheduled audit. Reuses
    # the same metadata fetch — no public webhook endpoint required, so it
    # works on localhost. Scheduled audits remain the backstop.
    #   poll_enabled                  — master switch for the Poller loop.
    #   default_poll_interval_seconds — fallback for users without a per-user
    #                                   override (None/0 = polling off).
    #   poll_min_interval_seconds     — floor + the loop's tick cadence.
    #   poll_fetch_limit              — newest-N headers pulled per poll; a
    #                                   burst larger than this is caught by the
    #                                   next scheduled audit.
    poll_enabled: bool = True
    default_poll_interval_seconds: int | None = None
    poll_min_interval_seconds: int = 30
    poll_fetch_limit: int = 25
    # Daily digest of the last 24h, emitted once each morning. digest_hour is
    # the local hour (0-23) it fires; digest_timezone is the IANA zone that
    # defines "local"; digest_window_hours is the look-back window.
    digest_enabled: bool = True
    digest_hour: int = 9
    digest_timezone: str = "America/New_York"
    digest_window_hours: int = 24

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

    # ── Triage / categorization ──────────────────────────────────────────
    # Ask the classifier to also bucket each message into a fixed category
    # (see app/categories.py) and flag whether it wants a human reply.
    categorize_enabled: bool = True
    # Write the resulting category back to the real mailbox as an Outlook
    # category / Gmail label. Disable to classify-and-display only (no
    # mailbox writes).
    apply_labels_enabled: bool = True
    # Prefix for every label the agent applies, so its labels are namespaced
    # and easy to find/remove (e.g. "AgentX/Finance", "AgentX/Needs Reply").
    label_prefix: str = "AgentX"

    # ── Phishing / BEC review ────────────────────────────────────────────
    # Deterministic header heuristics (display-name spoofing, Reply-To
    # mismatch, SPF/DKIM/DMARC failures, brand impersonation) surfaced as a
    # verdict separate from spam. See app/phishing.py.
    phishing_enabled: bool = True

    # ── Action layer (extraction + draft replies) ───────────────────────
    # Ask the classifier to also pull a one-line action + optional due date
    # out of messages that request something. Surfaced in the report + digest.
    extract_actions_enabled: bool = True
    # Generate reply drafts (saved to the mailbox, never sent) on demand.
    drafts_enabled: bool = True
    # Model for draft generation; falls back to chat_model, then ollama_model.
    draft_model: str | None = None
    draft_num_predict: int = 400

    # ── Semantic mailbox search ──────────────────────────────────────────
    # Index audited messages into a Chroma collection (reusing the embed
    # model + chroma_path the chat layer already uses) for semantic recall.
    search_enabled: bool = True
    search_top_k: int = 20

    # ── Rspamd second-opinion classifier ─────────────────────────────────
    # When set, every message classified by Ollama is also checked against
    # Rspamd and the two verdicts are blended (plus the per-sender prior).
    # Set to None / empty to disable. User actions (delete/unsub/allow/deny)
    # additionally train Rspamd's per-user Bayes when enabled.
    # `rspamd_url` is the SCANNER (normal worker, default :11333) — /checkv2.
    rspamd_url: str | None = None
    # Bayes training (/learnspam, /learnham) is a CONTROLLER command on a
    # different worker (default :11334) — NOT the scanner. When unset but
    # rspamd_url ends in :11333, the controller URL is derived by swapping the
    # port to 11334. Set explicitly for a non-default controller host/port.
    rspamd_controller_url: str | None = None
    # Controller password (sent as the `Password` header on learn). Leave empty
    # when the controller trusts the agent via `secure_ip` — the default for the
    # bundled rspamd (see rspamd/local.d/worker-controller.inc).
    rspamd_password: str | None = None
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
    # "Optimize rules": when this many distinct address-level deny rules share
    # one domain, suggest collapsing them into a single domain deny rule.
    optimize_rules_threshold: int = 3

    # env_ignore_empty: treat an empty-string env var as "unset" so it falls
    # back to the field default. docker-compose's `${VAR:-}` idiom injects
    # empty strings for unset vars, which would otherwise fail to parse for
    # Optional[int] fields (e.g. AGENT_DEFAULT_POLL_INTERVAL_SECONDS=).
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="AGENT_", extra="ignore",
        env_ignore_empty=True,
    )


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
