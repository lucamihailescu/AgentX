"""Mailbox-provider abstraction.

Each concrete provider (Microsoft, Google) implements `MailboxProvider`. The
agent treats them interchangeably — `app/tasks.py`, `app/worker.py`, and the
delete/unsubscribe routes operate on the abstract interface and the
normalized `Message` dataclass.
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass
from typing import Any, ClassVar

import httpx

logger = logging.getLogger(__name__)


class AuthError(Exception):
    """Raised on any token-acquisition / OAuth failure."""


@dataclass
class Message:
    """Normalized mailbox message — provider-agnostic shape used by tasks.py."""

    id: str
    subject: str | None
    from_address: str | None
    received: str | None             # ISO-8601 UTC string
    preview: str | None
    unsubscribe_url: str | None = None
    unsubscribe_one_click: bool = False

    def to_dict(self) -> dict:
        """Convert to the dict shape the pipeline / templates expect.
        ``from_address`` is exposed as ``from`` to match existing UI bindings.
        """
        return {
            "id": self.id,
            "subject": self.subject,
            "from": self.from_address,
            "received": self.received,
            "preview": self.preview,
            "unsubscribe_url": self.unsubscribe_url,
            "unsubscribe_one_click": self.unsubscribe_one_click,
        }


class MailboxProvider:
    """Abstract base. Implementations are classmethod-only — there's no
    per-user instance state; provider state lives in the encrypted users.cache_blob.
    """

    NAME: ClassVar[str] = ""
    DISPLAY_NAME: ClassVar[str] = ""

    # Lazy-initialized per subclass. Each subclass gets its own instance the
    # first time `http_client()` is called (because cls is the subclass and
    # the assignment lands on the subclass attribute).
    _client: ClassVar[httpx.AsyncClient | None] = None

    @classmethod
    def is_configured(cls) -> bool:
        """Return True if the env has the credentials needed to use this provider."""
        return False

    # ── shared http plumbing ──────────────────────────────────────────────
    @classmethod
    def http_client(cls) -> httpx.AsyncClient:
        """Long-lived `httpx.AsyncClient` for this provider.

        Reuses the underlying connection pool across all calls (paginated
        fetches, bulk deletes), which avoids a TLS handshake per request.
        """
        if cls._client is None:
            cls._client = httpx.AsyncClient(
                timeout=30.0,
                limits=httpx.Limits(
                    max_connections=20, max_keepalive_connections=10
                ),
            )
        return cls._client

    @classmethod
    async def aclose(cls) -> None:
        if cls._client is not None:
            await cls._client.aclose()
            cls._client = None

    @classmethod
    async def request_with_retry(
        cls,
        method: str,
        url: str,
        *,
        headers: dict | None = None,
        params: Any = None,
        data: Any = None,
        json: Any = None,
        content: Any = None,
        max_attempts: int = 5,
    ) -> httpx.Response:
        """HTTP request that retries on 429 / 503 with exponential backoff.

        Honors `Retry-After` when the server provides it; otherwise uses
        `1 → 2 → 4 → 8 → 16` seconds with up-to-500ms jitter, capped at 60s.
        Pass `content=` for raw bytes (e.g. multipart/mixed batch bodies);
        `data=` for form-encoded; `json=` for JSON bodies.
        """
        client = cls.http_client()
        delay = 1.0
        last_resp: httpx.Response | None = None
        for attempt in range(1, max_attempts + 1):
            resp = await client.request(
                method,
                url,
                headers=headers,
                params=params,
                data=data,
                json=json,
                content=content,
            )
            if resp.status_code not in (429, 503):
                return resp
            last_resp = resp
            if attempt == max_attempts:
                return resp
            retry_after = resp.headers.get("Retry-After")
            wait_s: float | None = None
            if retry_after:
                try:
                    wait_s = float(retry_after)
                except ValueError:
                    wait_s = None
            if wait_s is None:
                wait_s = delay + random.uniform(0, 0.5)
            wait_s = min(wait_s, 60.0)
            logger.info(
                "%s %s → %s, retrying in %.1fs (attempt %d/%d)",
                method,
                url,
                resp.status_code,
                wait_s,
                attempt,
                max_attempts,
            )
            await asyncio.sleep(wait_s)
            delay = min(delay * 2, 30.0)
        # Loop only ends via return; this satisfies the type checker.
        assert last_resp is not None
        return last_resp

    # ── auth ──────────────────────────────────────────────────────────────
    @classmethod
    async def build_auth_flow(cls) -> dict:
        """Start an OAuth flow; returns a dict containing 'auth_uri' and any
        flow state (PKCE verifier, nonce, redirect_uri) the callback needs."""
        raise NotImplementedError

    @classmethod
    async def complete_auth_flow(cls, flow: dict, query_params: dict) -> tuple[str, str | None]:
        """Exchange the authorization code, persist the (encrypted) cache row,
        and return ``(user_id, username)``."""
        raise NotImplementedError

    @classmethod
    async def acquire_access_token(cls, user_id: str) -> str:
        """Return a valid bearer token, refreshing silently if needed."""
        raise NotImplementedError

    # ── mailbox ───────────────────────────────────────────────────────────
    @classmethod
    async def fetch_messages(
        cls, user_id: str, *, limit: int, cursor_before: str | None = None
    ) -> list[Message]:
        """Fetch up to `limit` messages, walking provider-specific pagination
        internally. `cursor_before` is an ISO-8601 timestamp; only messages
        strictly older are returned."""
        raise NotImplementedError

    @classmethod
    async def delete_message(cls, user_id: str, message_id: str) -> None:
        """Soft-delete (Trash / Deleted Items)."""
        raise NotImplementedError

    @classmethod
    async def fetch_message_body(cls, user_id: str, message_id: str) -> dict:
        """Fetch the full body of a single message. Returns:
            {"subject": str|None, "from": str|None, "received": str|None,
             "html": str|None, "text": str|None}
        Either `html` or `text` (or both) will be populated when available.
        """
        raise NotImplementedError
