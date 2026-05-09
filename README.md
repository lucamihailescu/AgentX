# agentx

A long-running background agent for **consumer Microsoft accounts** (outlook.com / hotmail / live).

The agent signs the user in with MSAL (auth code + PKCE), persists their token cache in SQLite, and runs background tasks against Microsoft Graph using silently-refreshed access tokens — so a queued job can keep working on the user's mailbox even after the original access token expires. Results are rendered in a built-in web UI; nothing is written back to the user's mailbox or OneDrive.

## Why MSAL and not the Entra Agent ID SDK?

The [Microsoft Entra SDK for Agent ID](https://learn.microsoft.com/entra/msidweb/agent-id-sdk/) and its long-running OBO scenario are built around **work/school identities** — single-tenant app registrations, 90-day refresh tokens extended via `TokenLifetimePolicy`, and a confidential-client OBO sidecar. None of that applies to personal Microsoft accounts:

- App registration must allow personal accounts (`consumers` authority).
- OBO with personal accounts is a fragile path that Microsoft's docs and samples don't target.
- `TokenLifetimePolicy` is an Entra-only artifact — MSA refresh-token lifetime is fixed by Microsoft.

So this codebase drops the sidecar and goes straight to MSAL. The "long-running" property comes from caching the user's refresh token and letting MSAL silently mint new access tokens before each Graph call.

## Architecture

```
┌────────────┐   /auth/login   ┌──────────────────┐
│  browser   │ ──────────────▶ │  agent (FastAPI) │
└────────────┘ ◀── session ─── └──────┬───────────┘
                                      │ MSAL silent
                                      ▼
                               ┌──────────────────┐
                               │   SQLite cache   │
                               └──────────────────┘
                                      │
                                      ▼ access token
                               ┌──────────────────┐
                               │  Microsoft Graph │
                               └──────────────────┘
```

| File | Role |
| --- | --- |
| `app/main.py` | FastAPI app: HTML pages (`/`, `/ui/tasks/{id}`), JSON API (`/tasks`, `/tasks/{id}`), auth (`/auth/*`) |
| `app/auth.py` | MSAL `ConfidentialClientApplication` wrapper; per-user `SerializableTokenCache` persisted in SQLite; CLI-token signer (itsdangerous) |
| `app/graph_client.py` | Async Graph wrapper that pulls a fresh token from a `token_provider` callable before every request |
| `app/tasks.py` | Pipeline: fetch messages → classify each via Ollama → build report dict |
| `app/ollama_client.py` | Async client for `POST {OLLAMA_URL}/api/generate` with `format=json`; defensive parsing |
| `app/worker.py` | Asyncio worker that claims `queued` rows, runs the pipeline, persists the JSON report on the row |
| `app/templates/` | Jinja2 templates: `base.html`, `login.html`, `index.html`, `task.html` |
| `app/db.py` | SQLite schema (`users`, `tasks` with `result_data` JSON blob) |
| `app/config.py` | Pydantic settings loaded from `AGENT_*` env vars |

The agent's stable per-user identifier is MSAL's `home_account_id` — used as the FK on `tasks.user_id` and as the payload in the CLI bearer token.

## App registration

In [Microsoft Entra admin center](https://entra.microsoft.com) → **Applications** → **App registrations** → **New registration**:

1. **Supported account types**: *Personal Microsoft accounts only*.
2. **Platform**: Web. **Redirect URI**: `http://localhost:8080/auth/callback`.
3. Under **Certificates & secrets**, create a client secret.
4. Under **API permissions** → **Microsoft Graph** → **Delegated**, add:
   - `Mail.ReadWrite`
   - `offline_access`

   No admin consent is needed — the user grants consent themselves on first sign-in. `Mail.ReadWrite` is needed because the report's per-message **Delete** button calls `DELETE /me/messages/{id}` to move flagged spam to *Deleted Items*. The agent never sends mail or touches OneDrive.

## Run

```bash
cp .env.example .env
# fill in CLIENT_ID, CLIENT_SECRET, and a random SESSION_SECRET
python -c "import secrets; print(secrets.token_urlsafe(32))"

docker compose up --build
```

Then in a browser: <http://localhost:8080> → "Sign in with Microsoft" → land on the task list. Click **Generate new mailbox report**, the page auto-refreshes every 2s while the task is `queued`/`processing`, and renders a table of recent messages once `completed`.

## Endpoints

### Web UI (HTML)

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/` | optional | Sign-in page when signed out; task list when signed in |
| POST | `/ui/tasks` | session | Form action — queues a task and redirects to its detail page |
| GET | `/ui/tasks/{id}` | session / bearer | Task detail page with rendered report (auto-refreshes while pending) |
| POST | `/ui/tasks/{id}/messages/{mid}/delete` | session / bearer | Move the message to Deleted Items via Graph and mark it `deleted` in the cached report |
| POST | `/ui/tasks/{id}/messages/{mid}/unsubscribe` | session / bearer | Hit the message's `List-Unsubscribe` HTTPS URL (POST if one-click, else GET); mark `unsubscribed` |
| POST | `/ui/tasks/{id}/messages/{mid}/unsubscribe-and-delete` | session / bearer | Unsubscribe, then delete |

### JSON API

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| POST | `/tasks` | session / bearer | Queue a task; returns `{task_id, status}` |
| GET | `/tasks/{id}` | session / bearer | Returns `{task_id, status, result, error, …}` (`result` is the parsed JSON report) |

### Auth + ops

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/auth/login` | none | Redirect to Microsoft |
| GET | `/auth/callback` | none | OAuth code exchange |
| POST | `/auth/logout` | any | Clear session |
| GET | `/auth/cli-token` | session | Issue a 1-hour bearer for shell use |
| GET | `/healthz` | none | Liveness |

All `session / bearer`-marked endpoints accept either the browser session cookie *or* `Authorization: Bearer <cli-token>`.

## CLI usage

The browser session cookie can't be used by `curl` directly. Issue a CLI bearer instead:

```bash
# 1. Sign in via browser at /auth/login.
# 2. While signed in, hit /auth/cli-token in the same browser and copy `token`.
TOKEN=<paste>

# 3. Queue a task:
curl -X POST -H "Authorization: Bearer $TOKEN" http://localhost:8080/tasks
# {"task_id":"<uuid>","status":"queued"}

# 4. Poll status:
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/tasks/<uuid>
```

The CLI token is signed with `SESSION_SECRET` (HMAC via itsdangerous), valid for 1 hour, and only carries the user's `home_account_id`. It's a session-equivalent bearer — **not** a Graph access token.

## Task pipeline

Both `POST /tasks` (JSON) and `POST /ui/tasks` (HTML form) insert a `queued` row; the worker:

1. Fetches the user's most recent N Outlook messages (`GET /me/messages`, paginated via `@odata.nextLink`). N defaults to 200, configurable via `AGENT_MAX_MESSAGES_PER_AUDIT`.
2. **Auto-deletes messages from blocked domains** (see `BLOCKED_DOMAINS` below). They stay in the report tagged `auto-deleted` with no action buttons.
3. **Classifies each surviving message via Ollama** (`POST {OLLAMA_URL}/api/generate` with `format=json`), running up to `AGENT_OLLAMA_CONCURRENCY` requests in parallel. The model is asked to return `{spam, confidence, reason}`.
4. Builds the report dict (`message_count`, `spam_count`, `auto_deleted_count`, `unknown_count`, per-message verdicts).
5. Persists the JSON on `tasks.result_data` and marks the row `completed`.

The web UI reads `result_data` and renders it as a table on `/ui/tasks/{id}` — each message row shows `spam` / `ok` / `?`, the confidence percent, and the model's stated reason; the JSON API exposes the parsed dict on the `result` field of `GET /tasks/{id}`.

Each Graph call goes through `GraphClient`, which invokes `acquire_access_token(user_id)` first — MSAL returns the cached access token if still valid, or silently uses the cached refresh token to mint a new one and persists the updated cache back to SQLite.

### Spam classification

`app/ollama_client.py` posts each message's sender / subject / preview to Ollama's `/api/generate` endpoint. The system prompt instructs the model to reply with a single JSON object:

```json
{"spam": true, "confidence": 0.92, "reason": "promotional language and unknown sender"}
```

Per-message failures (Ollama unreachable, invalid JSON, timeout) are caught and recorded as `spam: null` with the failure reason — they show up as `?` in the UI but don't fail the whole task. Replace the prompt or model in `app/ollama_client.py` to tune precision/recall.

### Deleting flagged spam

Each message classified as `spam` gets a **Delete** button on its row. Clicking it (after a browser `confirm()` prompt) `POST`s to `/ui/tasks/{id}/messages/{mid}/delete`, which:

1. Verifies the message belongs to a task owned by the current user.
2. Acquires a fresh access token via MSAL silent flow.
3. Calls `DELETE /me/messages/{id}` on Microsoft Graph — Outlook moves the message to **Deleted Items** (recoverable by the user from there).
4. Updates the cached report row with `deleted: true` and a `deleted_at` timestamp; the row renders dimmed in the UI.

If you previously consented with only `Mail.Read`, sign out and sign in again — MSAL won't silently broaden consent, so the new `Mail.ReadWrite` scope only gets granted on the next interactive sign-in.

### Domain blocklist (auto-delete)

Set `BLOCKED_DOMAINS` to a comma-separated list of sender domains in `.env`, e.g.:

```
BLOCKED_DOMAINS=spam.example.com,marketing.acme.io,promo.foo.com
```

When a task runs, every message whose `from` address matches the blocklist is deleted via `DELETE /me/messages/{id}` *before* classification — saves the Ollama work and keeps the report focused on messages the user might actually want to see.

**Subdomain matching is enabled.** Listing `example.com` also matches `mail.example.com`, `news.example.com`, etc. Listing `mail.example.com` matches only that exact subdomain.

Blocklist matches show up in the report as `auto-deleted` (greyed-out row, no action buttons) and contribute to the `auto_deleted_count` in the summary. If a Graph delete fails (network blip, message already gone), the worker logs a warning and lets the message fall through to normal classification — better to surface a stale match than to fail the whole task.

### Auto-unsubscribe (List-Unsubscribe header)

When fetching messages, the agent expands `$select` to include `internetMessageHeaders`. Per [RFC 2369](https://datatracker.ietf.org/doc/html/rfc2369) and [RFC 8058](https://datatracker.ietf.org/doc/html/rfc8058) it looks for two headers:

- `List-Unsubscribe: <https://...>, <mailto:...>` — the agent extracts the first **HTTPS** URI.
- `List-Unsubscribe-Post: List-Unsubscribe=One-Click` — if present, the agent will `POST` instead of `GET`.

If a spam-flagged message has a usable HTTPS unsubscribe URL, two extra buttons appear on its row in addition to **Delete**:

- **Unsub** — hits the URL and marks the message `unsubscribed: true`. Leaves the message in the inbox.
- **Unsub + Delete** — does the unsubscribe, then deletes (moves to Deleted Items).

Body-link parsing ("find the *Unsubscribe* word in the HTML") is **not** implemented. Only the standardized header is honored — same defensive posture as Apple Mail / Gmail / Outlook.

**Safety caveats**

- For real spam (vs unwanted-but-legitimate marketing), hitting the unsubscribe URL **confirms a real human reads the inbox**, which is what spammers want. Real spammers ignore List-Unsubscribe — only legitimate senders honor it. If the model has flagged something as actual spam, prefer **Delete** over **Unsub + Delete** unless the sender is clearly a legitimate but unwanted newsletter.
- The agent follows redirects from the unsubscribe URL. It does not pass any auth, cookies, or referer; treat unsubscribe URLs as untrusted.
- `mailto:` unsubscribe is not supported (would require re-adding the `Mail.Send` scope). HTTPS only.

### Prerequisites for spam classification

- An Ollama instance reachable from the agent container. On macOS / Windows Docker Desktop, the default `http://host.docker.internal:11434` works for an Ollama that's installed on your machine. On Linux, set `OLLAMA_URL` to the host IP, or run Ollama as a container on the same Docker network.
- Pull the model before queueing a task: `ollama pull llama3.2` (or whatever you set `OLLAMA_MODEL` to).

## Configuration

All settings are read from environment variables prefixed with `AGENT_` (and from `.env`).

| Var | Default | Notes |
| --- | --- | --- |
| `AGENT_CLIENT_ID` | *required* | App registration client ID |
| `AGENT_CLIENT_SECRET` | *required* | App registration secret |
| `AGENT_AUTHORITY` | `https://login.microsoftonline.com/consumers` | Use `/common` for both work + personal |
| `AGENT_REDIRECT_URI` | `http://localhost:8080/auth/callback` | Must exactly match the value registered |
| `AGENT_SESSION_SECRET` | *required* | Signs both browser session cookies and CLI bearer tokens |
| `AGENT_DB_PATH` | `tasks.db` | SQLite file path; the compose volume mounts `/data` |
| `AGENT_WORKER_POLL_INTERVAL_SECONDS` | `2.0` | How often the worker polls for queued rows |
| `AGENT_OLLAMA_URL` | `http://host.docker.internal:11434` | Ollama base URL |
| `AGENT_OLLAMA_MODEL` | `llama3.2` | Model name (must be pulled in the target Ollama instance) |
| `AGENT_OLLAMA_TIMEOUT_SECONDS` | `30.0` | Per-request timeout |
| `AGENT_OLLAMA_CONCURRENCY` | `4` | Max parallel classification requests |
| `AGENT_MAX_MESSAGES_PER_AUDIT` | `200` | Cap on messages fetched per audit. Agent walks `@odata.nextLink` 50 messages at a time up to this number. |
| `AGENT_BLOCKED_DOMAINS` | *(empty)* | Comma-separated sender domains whose mail is auto-deleted at fetch time. Subdomain matching enabled. |

## Limitations

- **Refresh-token lifetime for personal accounts is set by Microsoft**, sliding ~24h with a 90-day cap. There's no `TokenLifetimePolicy` knob — plan tasks for hours-to-low-days, not weeks.
- **Token cache is unencrypted** in SQLite. For production, encrypt the `cache_blob` column or move the cache to a KMS-backed store.
- **Single worker.** `_claim_next` does a non-locking `SELECT … LIMIT 1` followed by an `UPDATE`. To scale out, swap SQLite for Postgres and use `SELECT … FOR UPDATE SKIP LOCKED`.
- **No retry budget** beyond what MSAL/HTTPX do internally — failures mark the task `failed` and stop. Add a retry counter on the `tasks` row if you need it.
- **CLI tokens carry full user authority** for 1 hour. Treat them like passwords; don't paste into chat or log them.
- **No CSRF protection** on `POST /ui/tasks`. For localhost / single-user use this is fine, but if you expose the agent on a real hostname, add a CSRF token to the form (e.g. via `starlette-csrf`) before going further.
- **Reports stored in SQLite** can grow large — there's no retention/cleanup. Add a sweeper if you generate many large reports.

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m compileall -q app/   # syntax check
uvicorn app.main:app --reload  # needs AGENT_* env vars
```
