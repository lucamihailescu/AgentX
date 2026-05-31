"""Microsoft / Outlook.com provider — MSAL + Microsoft Graph."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import ClassVar
from urllib.parse import quote

import aiosqlite
import msal

import logging

from ..auth import CacheKeyError, _decrypt_blob, _encrypt_blob, _now
from ..config import redirect_uri_for, settings
from ..unsubscribe import find_unsubscribe
from .base import AuthError, MailboxProvider, Message

logger = logging.getLogger(__name__)

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_PAGE_SIZE = 50

# Headers the phishing heuristics care about (lowercased).
_AUTH_HEADER_NAMES = frozenset(
    {"reply-to", "return-path", "authentication-results", "received-spf"}
)


def _compose_from_header(from_obj: dict) -> str | None:
    """Rebuild a raw `From:`-style value ("Name <addr>") from Graph's
    structured emailAddress object, so the phishing layer can compare the
    display name against the address."""
    name = (from_obj or {}).get("name")
    addr = (from_obj or {}).get("address")
    if name and addr and name.strip().lower() != addr.strip().lower():
        return f"{name} <{addr}>"
    return addr or None


def _select_auth_headers(headers: list[dict]) -> dict[str, str] | None:
    """Pull the subset of internetMessageHeaders the phishing heuristics use."""
    out: dict[str, str] = {}
    for h in headers:
        name = (h.get("name") or "").strip().lower()
        if name in _AUTH_HEADER_NAMES and h.get("value"):
            # Keep the first occurrence of each header.
            out.setdefault(name, h["value"])
    return out or None


class MicrosoftProvider(MailboxProvider):
    NAME: ClassVar[str] = "microsoft"
    DISPLAY_NAME: ClassVar[str] = "Microsoft (Outlook.com)"

    # ── configuration ─────────────────────────────────────────────────────
    @classmethod
    def is_configured(cls) -> bool:
        return bool(settings.client_id and settings.client_secret)

    @classmethod
    def _msal_app(cls, cache: msal.SerializableTokenCache | None = None) -> msal.ConfidentialClientApplication:
        return msal.ConfidentialClientApplication(
            client_id=settings.client_id,
            client_credential=settings.client_secret,
            authority=settings.authority,
            token_cache=cache,
        )

    # ── persistence helpers ───────────────────────────────────────────────
    @classmethod
    async def _load_cache(cls, user_id: str) -> msal.SerializableTokenCache:
        cache = msal.SerializableTokenCache()
        async with aiosqlite.connect(settings.db_path) as db:
            cur = await db.execute(
                "SELECT cache_blob FROM users WHERE user_id = ?", (user_id,)
            )
            row = await cur.fetchone()
        if not row:
            return cache
        try:
            cache.deserialize(_decrypt_blob(row[0]))
        except CacheKeyError as exc:
            # Cache key rotated; the blob is unrecoverable. Wipe so future
            # sign-ins start clean and we don't keep logging this.
            logger.warning(
                "Microsoft cache for %s unrecoverable (%s); clearing blob",
                user_id, exc,
            )
            async with aiosqlite.connect(settings.db_path) as db:
                await db.execute(
                    "UPDATE users SET cache_blob = '', updated_at = ? "
                    "WHERE user_id = ?",
                    (_now(), user_id),
                )
                await db.commit()
        return cache

    @classmethod
    async def _save_cache(
        cls,
        user_id: str,
        username: str | None,
        cache: msal.SerializableTokenCache,
    ) -> None:
        if not cache.has_state_changed:
            return
        now = _now()
        async with aiosqlite.connect(settings.db_path) as db:
            await db.execute(
                """INSERT INTO users
                   (user_id, username, provider, cache_blob, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(user_id) DO UPDATE SET
                     cache_blob = excluded.cache_blob,
                     username = COALESCE(excluded.username, users.username),
                     provider = excluded.provider,
                     updated_at = excluded.updated_at""",
                (user_id, username, cls.NAME, _encrypt_blob(cache.serialize()), now, now),
            )
            await db.commit()

    # ── auth ──────────────────────────────────────────────────────────────
    @classmethod
    async def build_auth_flow(cls) -> dict:
        if not cls.is_configured():
            raise AuthError("Microsoft provider not configured")
        return cls._msal_app().initiate_auth_code_flow(
            scopes=settings.scopes,
            redirect_uri=redirect_uri_for("microsoft"),
        )

    @classmethod
    async def complete_auth_flow(
        cls, flow: dict, query_params: dict
    ) -> tuple[str, str | None]:
        cache = msal.SerializableTokenCache()
        app = cls._msal_app(cache)
        result = await asyncio.to_thread(
            app.acquire_token_by_auth_code_flow, flow, query_params
        )
        if "error" in result:
            raise AuthError(
                f"{result.get('error')}: {result.get('error_description', '')}"
            )
        accounts = app.get_accounts()
        if not accounts:
            raise AuthError("Token cache empty after authorization-code exchange")
        account = accounts[0]
        user_id = account["home_account_id"]
        username = (
            result.get("id_token_claims", {}).get("preferred_username")
            or account.get("username")
        )
        await cls._save_cache(user_id, username, cache)
        return user_id, username

    @classmethod
    async def acquire_access_token(cls, user_id: str) -> str:
        cache = await cls._load_cache(user_id)
        app = cls._msal_app(cache)
        accounts = app.get_accounts()
        if not accounts:
            raise AuthError(f"No cached Microsoft account for {user_id}")
        account = accounts[0]
        result = await asyncio.to_thread(
            app.acquire_token_silent, settings.scopes, account
        )
        await cls._save_cache(user_id, account.get("username"), cache)
        if not result or "access_token" not in result:
            err = (result or {}).get("error_description") or "silent token acquisition returned None"
            raise AuthError(err)
        return result["access_token"]

    # ── mailbox ops ───────────────────────────────────────────────────────
    @classmethod
    async def fetch_messages(
        cls, user_id: str, *, limit: int, cursor_before: str | None = None
    ) -> list[Message]:
        page_size = min(_PAGE_SIZE, limit)
        qs = [
            f"$top={page_size}",
            "$select=id,subject,from,receivedDateTime,bodyPreview,categories,internetMessageHeaders",
            "$orderby=receivedDateTime desc",
        ]
        if cursor_before:
            qs.append(
                f"$filter={quote(f'receivedDateTime lt {cursor_before}')}"
            )
        url: str | None = f"{_GRAPH_BASE}/me/messages?{'&'.join(qs)}"

        out: list[Message] = []
        while url and len(out) < limit:
            token = await cls.acquire_access_token(user_id)
            resp = await cls.request_with_retry(
                "GET", url, headers={"Authorization": f"Bearer {token}"}
            )
            if resp.status_code >= 400:
                raise AuthError(
                    f"Graph GET returned {resp.status_code}: {resp.text[:200]}"
                )
            body = resp.json()
            for m in body.get("value", []):
                headers = m.get("internetMessageHeaders") or []
                unsub = find_unsubscribe(headers)
                from_obj = (m.get("from") or {}).get("emailAddress", {})
                out.append(
                    Message(
                        id=m.get("id"),
                        subject=m.get("subject"),
                        from_address=from_obj.get("address"),
                        received=m.get("receivedDateTime"),
                        preview=m.get("bodyPreview"),
                        unsubscribe_url=unsub["url"] if unsub else None,
                        unsubscribe_one_click=unsub["one_click"] if unsub else False,
                        categories=m.get("categories") or None,
                        from_header=_compose_from_header(from_obj),
                        auth_headers=_select_auth_headers(headers),
                    )
                )
                if len(out) >= limit:
                    break
            url = body.get("@odata.nextLink") if len(out) < limit else None
        return out

    @classmethod
    async def delete_message(cls, user_id: str, message_id: str) -> None:
        token = await cls.acquire_access_token(user_id)
        resp = await cls.request_with_retry(
            "DELETE",
            f"{_GRAPH_BASE}/me/messages/{message_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code >= 400:
            raise AuthError(
                f"Graph DELETE returned {resp.status_code}: {resp.text[:200]}"
            )

    @classmethod
    async def apply_labels(
        cls,
        user_id: str,
        message_id: str,
        add_labels: list[str],
        *,
        existing_categories: list[str] | None = None,
    ) -> None:
        """Merge `add_labels` into the message's Outlook categories.

        Graph's PATCH replaces the whole `categories` array, so we union with
        the categories captured at fetch time to avoid clobbering any the user
        set themselves. No-op when every label is already present.
        """
        if not add_labels:
            return
        existing = list(existing_categories or [])
        existing_lower = {c.strip().lower() for c in existing}
        merged = list(existing)
        for label in add_labels:
            if label.strip().lower() not in existing_lower:
                merged.append(label)
                existing_lower.add(label.strip().lower())
        if len(merged) == len(existing):
            return  # nothing new to add
        token = await cls.acquire_access_token(user_id)
        resp = await cls.request_with_retry(
            "PATCH",
            f"{_GRAPH_BASE}/me/messages/{message_id}",
            headers={"Authorization": f"Bearer {token}"},
            json={"categories": merged},
        )
        if resp.status_code >= 400:
            raise AuthError(
                f"Graph PATCH (categories) returned {resp.status_code}: {resp.text[:200]}"
            )

    @classmethod
    async def create_draft(
        cls,
        user_id: str,
        *,
        to: str,
        subject: str,
        body: str,
        in_reply_to_id: str | None = None,
    ) -> str:
        """Save a reply draft via Graph. With `in_reply_to_id`, use
        `createReply` so the draft threads onto the original conversation and
        quotes it; our generated text goes in as the reply `comment`. Without
        it, create a standalone draft. Never sent."""
        token = await cls.acquire_access_token(user_id)
        headers = {"Authorization": f"Bearer {token}"}
        if in_reply_to_id:
            resp = await cls.request_with_retry(
                "POST",
                f"{_GRAPH_BASE}/me/messages/{in_reply_to_id}/createReply",
                headers=headers,
                json={"comment": body},
            )
        else:
            resp = await cls.request_with_retry(
                "POST",
                f"{_GRAPH_BASE}/me/messages",
                headers=headers,
                json={
                    "subject": subject,
                    "body": {"contentType": "Text", "content": body},
                    "toRecipients": [{"emailAddress": {"address": to}}],
                    "isDraft": True,
                },
            )
        if resp.status_code >= 400:
            raise AuthError(
                f"Graph create draft returned {resp.status_code}: {resp.text[:200]}"
            )
        return (resp.json() or {}).get("id") or ""

    @classmethod
    async def fetch_raw(cls, user_id: str, message_id: str) -> bytes:
        """Fetch the full RFC 822 / EML bytes via Graph's $value endpoint.
        Used for lazy-escalation Rspamd re-checks on borderline verdicts."""
        token = await cls.acquire_access_token(user_id)
        resp = await cls.request_with_retry(
            "GET",
            f"{_GRAPH_BASE}/me/messages/{message_id}/$value",
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code >= 400:
            raise AuthError(
                f"Graph GET ($value) returned {resp.status_code}: {resp.text[:200]}"
            )
        return resp.content

    @classmethod
    async def fetch_message_body(cls, user_id: str, message_id: str) -> dict:
        token = await cls.acquire_access_token(user_id)
        resp = await cls.request_with_retry(
            "GET",
            f"{_GRAPH_BASE}/me/messages/{message_id}",
            headers={"Authorization": f"Bearer {token}"},
            params={"$select": "id,subject,from,receivedDateTime,body"},
        )
        if resp.status_code >= 400:
            raise AuthError(
                f"Graph GET (body) returned {resp.status_code}: {resp.text[:200]}"
            )
        data = resp.json()
        body = data.get("body") or {}
        ctype = (body.get("contentType") or "").lower()
        content = body.get("content") or ""
        return {
            "subject": data.get("subject"),
            "from": (data.get("from") or {}).get("emailAddress", {}).get("address"),
            "received": data.get("receivedDateTime"),
            "html": content if ctype == "html" else None,
            "text": content if ctype != "html" else None,
        }
