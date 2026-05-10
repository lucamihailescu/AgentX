"""Microsoft / Outlook.com provider — MSAL + Microsoft Graph."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import ClassVar
from urllib.parse import quote

import aiosqlite
import msal

from ..auth import _decrypt_blob, _encrypt_blob, _now
from ..config import settings
from ..unsubscribe import find_unsubscribe
from .base import AuthError, MailboxProvider, Message

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_PAGE_SIZE = 50


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
        if row:
            cache.deserialize(_decrypt_blob(row[0]))
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
            redirect_uri=settings.redirect_uri,
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
            "$select=id,subject,from,receivedDateTime,bodyPreview,internetMessageHeaders",
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
                unsub = find_unsubscribe(m.get("internetMessageHeaders") or [])
                out.append(
                    Message(
                        id=m.get("id"),
                        subject=m.get("subject"),
                        from_address=(m.get("from") or {})
                            .get("emailAddress", {})
                            .get("address"),
                        received=m.get("receivedDateTime"),
                        preview=m.get("bodyPreview"),
                        unsubscribe_url=unsub["url"] if unsub else None,
                        unsubscribe_one_click=unsub["one_click"] if unsub else False,
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
