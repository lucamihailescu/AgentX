# CLAUDE.md

Guidance for Claude Code ([claude.ai/code](https://claude.ai/code)) when working in this repository.

## What this is

**AgentX** is a long-running mailbox-triage agent for **consumer** Microsoft
(Outlook.com) and Google (Gmail) accounts. A FastAPI app runs background loops
that periodically (or in near-real-time) audit a user's inbox, classify each
message with a **local Ollama LLM** (with **Rspamd** as a second-opinion
classifier and per-sender priors blended in), apply sender allow/deny rules,
write categories back as Outlook categories / Gmail labels, surface phishing
flags, and offer unsubscribe + reply-draft actions through a web UI and a chat
assistant.

**The agent never sends mail.** It only reads, deletes, labels, and saves
drafts for the user to review and send manually.

## Run it

Everything runs under Docker Compose. There is no separate test suite or
linter wired up — verify changes by running the stack and exercising the UI.

```bash
cp .env.example .env          # then fill in the secrets below
ollama pull llama3.2          # classifier
ollama pull nomic-embed-text  # chat memory + semantic search embeddings
docker compose up -d --build  # agent + rspamd + redis + unbound
# UI at http://localhost:8080  (sign in with Outlook and/or Gmail)
./start.sh                    # same, but with the cloudflared tunnel profile
```

Required `.env` values: at least one provider (`CLIENT_ID`/`CLIENT_SECRET` for
Microsoft **or** `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` for Google), plus a
random `SESSION_SECRET`. See `.env.example` for the full annotated list and the
Entra / Google Cloud Console registration steps. OAuth redirect URIs must match
the console registration exactly (`http://localhost:8080/auth/{provider}/callback`
for local dev).

### Service topology (`docker-compose.yml`)

- **agent** — the FastAPI app (port 8080), the only externally-exposed service.
- **rspamd** — spam scanner (`:11333`) + controller (`:11334`); ports internal only.
- **redis** — backing store for Rspamd per-user Bayes tokens.
- **unbound** — private recursive DNS so Rspamd's DNSBL lookups aren't rate-limited.
- **cloudflared** — optional public tunnel; only runs under the `tunnel` profile when `TUNNEL_TOKEN` is set.

SQLite (`./data/tasks.db`) and ChromaDB (`./data/chroma`) live on a host
bind-mount, so `docker compose down -v` does **not** wipe user data.

## Architecture

### Background loops (`app/worker.py`)

Three asyncio tasks are started in `app/main.py`'s `lifespan`:

- **Worker** — claims one `queued` task at a time, atomically flips it to
  `processing`, and runs the pipeline. On startup `_reap_orphans()` resets any
  `processing` tasks back to `queued` (crash recovery). Assumes a **single
  worker process** — see Gotchas.
- **Scheduler** — inserts `audit` / `digest` tasks per user on their interval.
- **Poller** — watches a `poll_cursor` (received-timestamp watermark) per user
  and enqueues focused `scan` tasks for newly-arrived mail.

Task kinds: `audit` (full scan), `scan` (poll-triggered, incremental),
`purge`, `digest`. All tasks are **idempotent** — re-running is always safe,
which is what makes orphan recovery correct.

### Classification pipeline (`app/tasks.py`)

Per message: **rules** (allow/deny short-circuit, no LLM) → **auto-delete**
(blocklist/deny) → **classify** (Ollama + Rspamd + per-sender prior, blended in
`app/calibration.py`) → **phishing flag** (deterministic, runs even on
rule-matched mail) → **apply category/label** → **generate report**.

Verdict blending (`calibration.blend()`) is a weighted average of probabilities:
Ollama (weight `1.0`) + Rspamd (weight `rspamd_weight`, default 0.6, conditional)
+ per-sender prior (Laplace-smoothed, only for addresses with ≥2 user actions,
weight ramps to a cap of 5). It annotates whether the model's call was
`flipped` / `filled` / `adjusted`. Borderline results (confidence < 0.70) trigger
a **lazy Rspamd escalation** that fetches raw MIME for better URL/DKIM signals.

The system learns from user taste: UI actions (delete/unsubscribe/keep/allow/
deny) update `sender_stats`, which feed both the per-sender prior and
`app/feedback.py`'s few-shot examples injected into the next audit's Ollama
prompts. "Keep" / "not spam" / "allow" train Rspamd's ham side; delete / unsub /
deny train the spam side (`rspamd_client.fire_learn`).

### Provider abstraction (`app/providers/`)

`base.MailboxProvider` is the contract (auth flow, token acquisition, fetch /
delete / label / draft / raw-MIME / body). `microsoft.py` uses MSAL + Graph;
`google.py` uses PKCE OAuth2 + the Gmail REST API. The registry in
`__init__.py` maps names to instances; **always** go through `get_provider()`.
Per-user OAuth token caches are Fernet-encrypted (`app/auth.py`) and stored in
`users.cache_blob`. To add a provider, implement the base class and register it.

### Other features

- **Chat** (`app/chat.py`) — Ollama tool-calling loop (≤5 iterations) over
  audit/cleanup/rules/search tools, augmented with mem0 memories + inbox
  context. Streams replies; persists memory asynchronously after replying.
- **Semantic search** (`app/search_index.py`) — a *separate* ChromaDB
  collection from mem0, indexing audited messages for verbatim recall.
- **Drafts** (`app/drafts.py`) — generates plain-text replies saved to the
  mailbox Drafts folder, never sent.
- **Digest** (`app/digest.py`) — daily summary of audits, actions, phishing
  alerts, and borderline messages needing human review.

### Storage

- **SQLite** (`app/db.py`, WAL mode): `users`, `tasks`, `sender_rules`,
  `sender_stats`, `chat_messages`, suggestion dismissals.
- **Redis**: Rspamd per-user Bayes tokens.
- **ChromaDB**: two paths — `chroma_path` (mem0 memories) and
  `chroma_path + "_search"` (message search). They must be separate clients.

## Conventions

- **Config**: every setting is a field on `Settings` in `app/config.py`, read
  from `AGENT_`-prefixed env vars (`env_ignore_empty=True`, so compose's
  `${VAR:-}` empty strings fall back to defaults). Add new config there, not ad hoc.
- **Async + sync boundary**: blocking Ollama / ChromaDB / mem0 calls are pushed
  off the event loop with `asyncio.to_thread()`. Keep handlers async.
- **Graceful degradation**: mem0, search, and embeddings init lazily and set a
  sticky "unavailable" flag on hard failure; callers treat `None` as a no-op
  rather than raising. Preserve this — a dead ChromaDB must not break audits.
- **CSRF** (`app/csrf.py`): all state-changing form POSTs carry a double-submit
  token; bearer-authenticated (CLI) requests are exempt. Templates include
  `_csrf.html`.
- **Auth two ways**: browser session cookie, or `Authorization: Bearer <token>`
  CLI tokens (short-lived, signed via itsdangerous; mint at `/auth/cli-token`).
- **Rules apply before classification** and audit reports are **immutable
  snapshots** — a new rule does not retroactively change an existing report.
- Match the surrounding style: type hints, module-level docstrings explaining
  *why*, and the existing comment density. The codebase comments rationale heavily.

## Gotchas

- **Single worker only.** `_reap_orphans()` and the claim logic assume one
  worker process. To scale out you'd need Postgres + `SELECT ... FOR UPDATE
  SKIP LOCKED`, not just more containers.
- **MSA refresh tokens** (personal Microsoft accounts) have a ~24h sliding
  window / 90-day max — they expire in days, not weeks.
- **Key rotation**: token caches are encrypted with `AGENT_CACHE_KEY` (or
  `SESSION_SECRET` as fallback). Rotating `SESSION_SECRET` without a separate
  `CACHE_KEY` invalidates every stored token and forces re-sign-in.
- **Rspamd port split**: scanning is on `:11333`, learning on the controller
  `:11334`. The controller URL is derived by swapping the port unless set.
- **Polling baseline**: the first poll (cursor=`None`) returns no messages and
  just records the newest watermark, to avoid backfilling the whole inbox.
  Mail that arrives before polling is enabled is caught by the scheduled audit.
- **Few-shot / feedback** only walks the ~30 most recent audits and dedupes by
  sender; older history is ignored.
- **SQLite on macOS Docker Desktop bind-mounts** can occasionally report
  "database disk image is malformed" under concurrent writes; recover with
  `.recover`.
