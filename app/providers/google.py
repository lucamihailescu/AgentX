"""Google / Gmail provider — OAuth 2.0 (with PKCE) + Gmail REST API."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr, parsedate_to_datetime
from typing import ClassVar
from urllib.parse import urlencode

import aiosqlite
import httpx

from ..auth import _decrypt_blob, _encrypt_blob, _now
from ..config import settings
from ..unsubscribe import find_unsubscribe
from .base import AuthError, MailboxProvider, Message

_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
_GMAIL_BASE = "https://gmail.googleapis.com/gmail/v1"
_PAGE_SIZE = 50
_TOKEN_REFRESH_LEEWAY_S = 60
_FETCH_CONCURRENCY = 5

# Headers we ask Gmail to surface on the metadata-format `messages.get` call.
_METADATA_HEADERS = (
    "From",
    "Subject",
    "Date",
    "List-Unsubscribe",
    "List-Unsubscribe-Post",
)


def _make_pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:64]
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def _decode_id_token_payload(id_token: str) -> dict:
    try:
        parts = id_token.split(".")
        if len(parts) != 3:
            raise ValueError("not a JWT")
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, json.JSONDecodeError) as exc:
        raise AuthError(f"could not decode Google id_token: {exc}") from exc


def _gmail_internaldate_to_iso(internal_date_ms: str | None) -> str | None:
    if not internal_date_ms:
        return None
    try:
        ms = int(internal_date_ms)
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()


def _iso_to_epoch_seconds(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        # Gmail's `before:` filter accepts unix timestamps.
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except ValueError:
        return None


class GoogleProvider(MailboxProvider):
    NAME: ClassVar[str] = "google"
    DISPLAY_NAME: ClassVar[str] = "Google (Gmail)"

    @classmethod
    def is_configured(cls) -> bool:
        return bool(settings.google_client_id and settings.google_client_secret)

    # ── persistence (cache_blob = encrypted JSON of refresh+access+expiry) ─
    @classmethod
    async def _load_blob(cls, user_id: str) -> dict:
        async with aiosqlite.connect(settings.db_path) as db:
            cur = await db.execute(
                "SELECT cache_blob FROM users WHERE user_id = ?", (user_id,)
            )
            row = await cur.fetchone()
        if not row:
            raise AuthError(f"No cached Google account for {user_id}")
        try:
            return json.loads(_decrypt_blob(row[0]))
        except json.JSONDecodeError as exc:
            raise AuthError(f"corrupt Google cache for {user_id}: {exc}") from exc

    @classmethod
    async def _save_blob(
        cls, user_id: str, username: str | None, blob: dict
    ) -> None:
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
                (user_id, username, cls.NAME, _encrypt_blob(json.dumps(blob)), now, now),
            )
            await db.commit()

    # ── auth ──────────────────────────────────────────────────────────────
    @classmethod
    async def build_auth_flow(cls) -> dict:
        if not cls.is_configured():
            raise AuthError("Google provider not configured")
        verifier, challenge = _make_pkce_pair()
        state = secrets.token_urlsafe(16)
        params = {
            "client_id": settings.google_client_id,
            "redirect_uri": settings.google_redirect_uri,
            "response_type": "code",
            "scope": " ".join(settings.google_scopes + ["openid", "email", "profile"]),
            "access_type": "offline",
            "prompt": "consent",  # ensure refresh_token always returned
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        return {
            "auth_uri": f"{_AUTH_ENDPOINT}?{urlencode(params)}",
            "state": state,
            "code_verifier": verifier,
            "redirect_uri": settings.google_redirect_uri,
        }

    @classmethod
    async def complete_auth_flow(
        cls, flow: dict, query_params: dict
    ) -> tuple[str, str | None]:
        if query_params.get("state") != flow.get("state"):
            raise AuthError("OAuth state mismatch")
        if "error" in query_params:
            raise AuthError(
                f"{query_params.get('error')}: {query_params.get('error_description', '')}"
            )
        code = query_params.get("code")
        if not code:
            raise AuthError("authorization code missing from callback")

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                _TOKEN_ENDPOINT,
                data={
                    "code": code,
                    "client_id": settings.google_client_id,
                    "client_secret": settings.google_client_secret,
                    "redirect_uri": flow["redirect_uri"],
                    "grant_type": "authorization_code",
                    "code_verifier": flow["code_verifier"],
                },
            )
        if resp.status_code >= 400:
            raise AuthError(f"token exchange failed: {resp.text[:200]}")
        token = resp.json()
        if "access_token" not in token or "refresh_token" not in token:
            raise AuthError("token response missing access_token/refresh_token")

        claims = _decode_id_token_payload(token.get("id_token", "")) if token.get("id_token") else {}
        user_id = claims.get("sub")
        if not user_id:
            raise AuthError("id_token did not include 'sub'")
        username = claims.get("email") or claims.get("preferred_username")

        expires_at = (
            datetime.now(timezone.utc)
            + timedelta(seconds=int(token.get("expires_in", 3600)))
        ).isoformat()
        blob = {
            "refresh_token": token["refresh_token"],
            "access_token": token["access_token"],
            "expires_at": expires_at,
            "scope": token.get("scope", ""),
        }
        await cls._save_blob(user_id, username, blob)
        return user_id, username

    @classmethod
    async def acquire_access_token(cls, user_id: str) -> str:
        blob = await cls._load_blob(user_id)
        try:
            expires_at = datetime.fromisoformat(blob["expires_at"])
        except (KeyError, ValueError):
            expires_at = datetime.min.replace(tzinfo=timezone.utc)

        if (
            blob.get("access_token")
            and expires_at - timedelta(seconds=_TOKEN_REFRESH_LEEWAY_S)
            > datetime.now(timezone.utc)
        ):
            return blob["access_token"]

        # Refresh
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                _TOKEN_ENDPOINT,
                data={
                    "client_id": settings.google_client_id,
                    "client_secret": settings.google_client_secret,
                    "refresh_token": blob["refresh_token"],
                    "grant_type": "refresh_token",
                },
            )
        if resp.status_code >= 400:
            raise AuthError(f"refresh failed: {resp.text[:200]}")
        refreshed = resp.json()
        new_access = refreshed.get("access_token")
        if not new_access:
            raise AuthError("refresh response missing access_token")
        blob["access_token"] = new_access
        blob["expires_at"] = (
            datetime.now(timezone.utc)
            + timedelta(seconds=int(refreshed.get("expires_in", 3600)))
        ).isoformat()
        if "refresh_token" in refreshed:
            blob["refresh_token"] = refreshed["refresh_token"]

        # Read username so we can persist it on the upsert
        async with aiosqlite.connect(settings.db_path) as db:
            cur = await db.execute(
                "SELECT username FROM users WHERE user_id = ?", (user_id,)
            )
            row = await cur.fetchone()
        username = row[0] if row else None
        await cls._save_blob(user_id, username, blob)
        return new_access

    # ── mailbox ops ───────────────────────────────────────────────────────
    @classmethod
    async def fetch_messages(
        cls, user_id: str, *, limit: int, cursor_before: str | None = None
    ) -> list[Message]:
        token = await cls.acquire_access_token(user_id)
        headers = {"Authorization": f"Bearer {token}"}

        # 1) list IDs (with optional date filter)
        ids: list[str] = []
        page_token: str | None = None
        async with httpx.AsyncClient(timeout=30.0) as client:
            while len(ids) < limit:
                params: dict[str, str | int] = {
                    "maxResults": min(_PAGE_SIZE, limit - len(ids)),
                    "labelIds": "INBOX",
                }
                if cursor_before:
                    epoch = _iso_to_epoch_seconds(cursor_before)
                    if epoch is not None:
                        params["q"] = f"before:{epoch}"
                if page_token:
                    params["pageToken"] = page_token
                resp = await client.get(
                    f"{_GMAIL_BASE}/users/me/messages",
                    headers=headers,
                    params=params,
                )
                if resp.status_code >= 400:
                    raise AuthError(
                        f"Gmail list returned {resp.status_code}: {resp.text[:200]}"
                    )
                body = resp.json()
                for m in body.get("messages", []):
                    ids.append(m["id"])
                    if len(ids) >= limit:
                        break
                page_token = body.get("nextPageToken")
                if not page_token:
                    break

        if not ids:
            return []

        # 2) hydrate metadata for each id with bounded concurrency
        sem = asyncio.Semaphore(_FETCH_CONCURRENCY)

        async def _fetch_one(client: httpx.AsyncClient, mid: str) -> Message | None:
            params = [("format", "metadata")]
            for h in _METADATA_HEADERS:
                params.append(("metadataHeaders", h))
            async with sem:
                resp = await client.get(
                    f"{_GMAIL_BASE}/users/me/messages/{mid}",
                    headers=headers,
                    params=params,
                )
            if resp.status_code == 404:
                return None
            if resp.status_code >= 400:
                raise AuthError(
                    f"Gmail get returned {resp.status_code}: {resp.text[:200]}"
                )
            data = resp.json()
            payload_headers = (data.get("payload") or {}).get("headers") or []
            by_name = {h["name"].lower(): h.get("value", "") for h in payload_headers}

            from_raw = by_name.get("from") or ""
            _, addr = parseaddr(from_raw)
            received_iso = _gmail_internaldate_to_iso(data.get("internalDate"))
            if not received_iso and by_name.get("date"):
                try:
                    received_iso = parsedate_to_datetime(by_name["date"]).isoformat()
                except (TypeError, ValueError):
                    received_iso = None

            unsub = find_unsubscribe(
                [{"name": h["name"], "value": h.get("value", "")} for h in payload_headers]
            )
            return Message(
                id=mid,
                subject=by_name.get("subject"),
                from_address=addr or None,
                received=received_iso,
                preview=data.get("snippet"),
                unsubscribe_url=unsub["url"] if unsub else None,
                unsubscribe_one_click=unsub["one_click"] if unsub else False,
            )

        async with httpx.AsyncClient(timeout=30.0) as client:
            results = await asyncio.gather(
                *(_fetch_one(client, mid) for mid in ids)
            )
        return [m for m in results if m is not None]

    @classmethod
    async def delete_message(cls, user_id: str, message_id: str) -> None:
        # Gmail equivalent of "move to Deleted Items" is messages.trash.
        # `messages.delete` is permanent; we want recoverable.
        token = await cls.acquire_access_token(user_id)
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{_GMAIL_BASE}/users/me/messages/{message_id}/trash",
                headers={"Authorization": f"Bearer {token}"},
            )
            if resp.status_code >= 400:
                raise AuthError(
                    f"Gmail trash returned {resp.status_code}: {resp.text[:200]}"
                )
