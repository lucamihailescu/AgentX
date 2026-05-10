"""Mailbox-provider abstraction.

Each concrete provider (Microsoft, Google) implements `MailboxProvider`. The
agent treats them interchangeably — `app/tasks.py`, `app/worker.py`, and the
delete/unsubscribe routes operate on the abstract interface and the
normalized `Message` dataclass.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar


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

    @classmethod
    def is_configured(cls) -> bool:
        """Return True if the env has the credentials needed to use this provider."""
        return False

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
