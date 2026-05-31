"""Google / Gmail provider — OAuth 2.0 (with PKCE) + Gmail REST API."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.parser import BytesParser
from email.policy import default as default_policy
from email.utils import parseaddr, parsedate_to_datetime
from typing import ClassVar
from urllib.parse import urlencode

import aiosqlite

import logging

from ..auth import CacheKeyError, _decrypt_blob, _encrypt_blob, _now
from ..config import redirect_uri_for, settings
from ..unsubscribe import find_unsubscribe
from .base import AuthError, MailboxProvider, Message

logger = logging.getLogger(__name__)

_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
_GMAIL_BASE = "https://gmail.googleapis.com/gmail/v1"
_BATCH_ENDPOINT = "https://gmail.googleapis.com/batch/gmail/v1"
_PAGE_SIZE = 50
_BATCH_SIZE = 100  # Gmail caps batch requests at 100 sub-requests
_TOKEN_REFRESH_LEEWAY_S = 60

# Headers we ask Gmail to surface on the metadata-format `messages.get` call.
_METADATA_HEADERS = (
    "From",
    "Subject",
    "Date",
    "List-Unsubscribe",
    "List-Unsubscribe-Post",
    "Reply-To",
    "Return-Path",
    "Authentication-Results",
    "Received-SPF",
)

# Subset of the above the phishing heuristics consume (lowercased).
_AUTH_HEADER_NAMES = frozenset(
    {"reply-to", "return-path", "authentication-results", "received-spf"}
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


def _build_batch_body(ids: list[str], boundary: str) -> bytes:
    """Build a multipart/mixed body for Gmail's /batch endpoint — one
    sub-request per message id, asking for `format=metadata` with the
    headers we care about.
    """
    qs = "&".join(f"metadataHeaders={h}" for h in _METADATA_HEADERS)
    parts: list[bytes] = []
    for mid in ids:
        sub = (
            f"--{boundary}\r\n"
            f"Content-Type: application/http\r\n"
            f"Content-ID: <item-{mid}>\r\n"
            f"\r\n"
            f"GET /gmail/v1/users/me/messages/{mid}?format=metadata&{qs}\r\n"
            f"\r\n"
        )
        parts.append(sub.encode())
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts)


def _parse_inner_http(inner: bytes) -> tuple[int, bytes]:
    """Pull (status_code, body) out of one batch sub-response's payload.
    Returns (0, b"") on parse failure.
    """
    try:
        status_line, rest = inner.split(b"\r\n", 1)
        _headers, body = rest.split(b"\r\n\r\n", 1)
        return int(status_line.split()[1]), body
    except (ValueError, IndexError):
        return 0, b""


def _parse_batch_response(content_type: str, body: bytes) -> dict[str, dict]:
    """Parse Gmail's multipart/mixed batch response into a {message_id: data} map.

    Each sub-response carries a `Content-ID: <response-item-<mid>>` header
    that mirrors the request's `<item-<mid>>` Content-ID with a `response-`
    prefix added by Gmail.
    """
    full = (b"Content-Type: " + content_type.encode() + b"\r\n\r\n" + body)
    msg = BytesParser(policy=default_policy).parsebytes(full)
    out: dict[str, dict] = {}
    if not msg.is_multipart():
        return out
    for part in msg.iter_parts():
        cid = (part.get("Content-ID") or "").strip().strip("<>")
        if cid.startswith("response-item-"):
            mid = cid[len("response-item-"):]
        elif cid.startswith("item-"):
            mid = cid[len("item-"):]
        else:
            continue
        inner = part.get_payload(decode=True)
        if not isinstance(inner, bytes):
            continue
        status, body_bytes = _parse_inner_http(inner)
        if status != 200:
            continue
        try:
            out[mid] = json.loads(body_bytes)
        except json.JSONDecodeError:
            continue
    return out


def _message_from_metadata(mid: str, data: dict) -> Message:
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
    auth_headers = {
        name: by_name[name]
        for name in _AUTH_HEADER_NAMES
        if by_name.get(name)
    } or None
    return Message(
        id=mid,
        subject=by_name.get("subject"),
        from_address=addr or None,
        received=received_iso,
        preview=data.get("snippet"),
        unsubscribe_url=unsub["url"] if unsub else None,
        unsubscribe_one_click=unsub["one_click"] if unsub else False,
        from_header=from_raw or None,
        auth_headers=auth_headers,
    )


def _chunks(items: list[str], size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def _b64url_decode(data: str) -> str:
    pad = "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(data + pad).decode("utf-8", errors="replace")
    except (ValueError, TypeError):
        return ""


def _find_part_body(payload: dict, mime_type: str) -> str | None:
    """Walk the recursive Gmail payload tree, returning the first body that
    matches `mime_type` (decoded from base64url)."""
    if not isinstance(payload, dict):
        return None
    if (payload.get("mimeType") or "").lower() == mime_type:
        body = payload.get("body") or {}
        data = body.get("data")
        if data:
            return _b64url_decode(data)
    for part in payload.get("parts") or []:
        found = _find_part_body(part, mime_type)
        if found:
            return found
    return None


class GoogleProvider(MailboxProvider):
    NAME: ClassVar[str] = "google"
    DISPLAY_NAME: ClassVar[str] = "Google (Gmail)"

    # Per-user {label_name: label_id} cache. Gmail's modify API takes label
    # IDs, not names, so we resolve (and lazily create) them once per process.
    _label_cache: ClassVar[dict[str, dict[str, str]]] = {}
    _label_lock: ClassVar[asyncio.Lock | None] = None

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
        except CacheKeyError as exc:
            logger.warning(
                "Google cache for %s unrecoverable (%s); clearing blob",
                user_id, exc,
            )
            async with aiosqlite.connect(settings.db_path) as db:
                await db.execute(
                    "UPDATE users SET cache_blob = '', updated_at = ? "
                    "WHERE user_id = ?",
                    (_now(), user_id),
                )
                await db.commit()
            raise AuthError(
                f"Google cache for {user_id} requires re-sign-in (key rotated)"
            ) from exc
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
        redirect_uri = redirect_uri_for("google")
        params = {
            "client_id": settings.google_client_id,
            "redirect_uri": redirect_uri,
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
            "redirect_uri": redirect_uri,
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

        resp = await cls.request_with_retry(
            "POST",
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
        resp = await cls.request_with_retry(
            "POST",
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
            resp = await cls.request_with_retry(
                "GET",
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

        # 2) hydrate metadata via Gmail's /batch endpoint — one HTTP round-trip
        #    per chunk of <= _BATCH_SIZE message ids instead of one per id.
        out: list[Message] = []
        for chunk in _chunks(ids, _BATCH_SIZE):
            data_by_id = await cls._batch_fetch_metadata(token, chunk)
            for mid in chunk:
                data = data_by_id.get(mid)
                if data is None:
                    continue  # 404, parse failure, or sub-response error
                out.append(_message_from_metadata(mid, data))
        return out

    @classmethod
    async def _batch_fetch_metadata(
        cls, token: str, ids: list[str]
    ) -> dict[str, dict]:
        """POST a multipart/mixed batch to Gmail and return {id: response_json}.

        Sub-responses with non-200 status are silently dropped so the caller
        sees a partial result rather than a hard failure.
        """
        if not ids:
            return {}
        boundary = f"batch_{secrets.token_hex(8)}"
        body = _build_batch_body(ids, boundary)
        resp = await cls.request_with_retry(
            "POST",
            _BATCH_ENDPOINT,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": f"multipart/mixed; boundary={boundary}",
            },
            content=body,
        )
        if resp.status_code >= 400:
            raise AuthError(
                f"Gmail batch returned {resp.status_code}: {resp.text[:200]}"
            )
        return _parse_batch_response(
            resp.headers.get("content-type", ""), resp.content
        )

    @classmethod
    async def delete_message(cls, user_id: str, message_id: str) -> None:
        # Gmail equivalent of "move to Deleted Items" is messages.trash.
        # `messages.delete` is permanent; we want recoverable.
        token = await cls.acquire_access_token(user_id)
        resp = await cls.request_with_retry(
            "POST",
            f"{_GMAIL_BASE}/users/me/messages/{message_id}/trash",
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code >= 400:
            raise AuthError(
                f"Gmail trash returned {resp.status_code}: {resp.text[:200]}"
            )

    # ── labels ────────────────────────────────────────────────────────────
    @classmethod
    def _get_label_lock(cls) -> asyncio.Lock:
        if cls._label_lock is None:
            cls._label_lock = asyncio.Lock()
        return cls._label_lock

    @classmethod
    async def _load_labels(cls, token: str) -> dict[str, str]:
        resp = await cls.request_with_retry(
            "GET",
            f"{_GMAIL_BASE}/users/me/labels",
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code >= 400:
            raise AuthError(
                f"Gmail labels.list returned {resp.status_code}: {resp.text[:200]}"
            )
        return {
            lab["name"]: lab["id"]
            for lab in (resp.json() or {}).get("labels", [])
            if lab.get("name") and lab.get("id")
        }

    @classmethod
    async def _create_label(cls, token: str, name: str) -> str:
        resp = await cls.request_with_retry(
            "POST",
            f"{_GMAIL_BASE}/users/me/labels",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "name": name,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show",
            },
        )
        if resp.status_code == 409:
            # Raced another create (or it pre-existed) — re-list and use it.
            labels = await cls._load_labels(token)
            if name in labels:
                return labels[name]
        if resp.status_code >= 400:
            raise AuthError(
                f"Gmail labels.create returned {resp.status_code}: {resp.text[:200]}"
            )
        return (resp.json() or {})["id"]

    @classmethod
    async def _resolve_label_ids(
        cls, user_id: str, token: str, names: list[str]
    ) -> list[str]:
        """Return label IDs for `names`, creating any that don't yet exist.
        Serialized per process so concurrent audits don't double-create."""
        async with cls._get_label_lock():
            cache = cls._label_cache.get(user_id)
            if cache is None or any(n not in cache for n in names):
                cache = await cls._load_labels(token)
                cls._label_cache[user_id] = cache
            for name in names:
                if name not in cache:
                    cache[name] = await cls._create_label(token, name)
            return [cache[n] for n in names]

    @classmethod
    async def apply_labels(
        cls,
        user_id: str,
        message_id: str,
        add_labels: list[str],
        *,
        existing_categories: list[str] | None = None,
    ) -> None:
        """Add Gmail labels (by name) to a message. Gmail's modify API is
        natively additive + idempotent, so `existing_categories` is unused."""
        if not add_labels:
            return
        token = await cls.acquire_access_token(user_id)
        label_ids = await cls._resolve_label_ids(user_id, token, add_labels)
        resp = await cls.request_with_retry(
            "POST",
            f"{_GMAIL_BASE}/users/me/messages/{message_id}/modify",
            headers={"Authorization": f"Bearer {token}"},
            json={"addLabelIds": label_ids},
        )
        if resp.status_code >= 400:
            raise AuthError(
                f"Gmail messages.modify returned {resp.status_code}: {resp.text[:200]}"
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
        """Save a reply draft via Gmail's drafts.create. When `in_reply_to_id`
        is given, look up the original's threadId + Message-ID so the draft
        threads correctly (In-Reply-To / References + threadId). Never sent."""
        token = await cls.acquire_access_token(user_id)
        headers = {"Authorization": f"Bearer {token}"}

        thread_id: str | None = None
        if in_reply_to_id:
            resp = await cls.request_with_retry(
                "GET",
                f"{_GMAIL_BASE}/users/me/messages/{in_reply_to_id}",
                headers=headers,
                params={"format": "metadata", "metadataHeaders": "Message-ID"},
            )
            if resp.status_code < 400:
                data = resp.json() or {}
                thread_id = data.get("threadId")
                orig_headers = {
                    (h.get("name") or "").lower(): h.get("value", "")
                    for h in (data.get("payload") or {}).get("headers", [])
                }
                msgid = orig_headers.get("message-id")
            else:
                msgid = None
        else:
            msgid = None

        mime = EmailMessage()
        mime["To"] = to
        mime["Subject"] = subject
        if msgid:
            mime["In-Reply-To"] = msgid
            mime["References"] = msgid
        mime.set_content(body)
        raw = base64.urlsafe_b64encode(mime.as_bytes()).decode()

        draft_msg: dict = {"raw": raw}
        if thread_id:
            draft_msg["threadId"] = thread_id
        resp = await cls.request_with_retry(
            "POST",
            f"{_GMAIL_BASE}/users/me/drafts",
            headers=headers,
            json={"message": draft_msg},
        )
        if resp.status_code >= 400:
            raise AuthError(
                f"Gmail drafts.create returned {resp.status_code}: {resp.text[:200]}"
            )
        return (resp.json() or {}).get("id") or ""

    @classmethod
    async def fetch_raw(cls, user_id: str, message_id: str) -> bytes:
        """Fetch the full RFC 822 bytes via Gmail's `format=raw` endpoint.
        Used for lazy-escalation Rspamd re-checks on borderline verdicts."""
        token = await cls.acquire_access_token(user_id)
        resp = await cls.request_with_retry(
            "GET",
            f"{_GMAIL_BASE}/users/me/messages/{message_id}",
            headers={"Authorization": f"Bearer {token}"},
            params={"format": "raw"},
        )
        if resp.status_code >= 400:
            raise AuthError(
                f"Gmail GET (raw) returned {resp.status_code}: {resp.text[:200]}"
            )
        raw_b64 = (resp.json() or {}).get("raw") or ""
        if not raw_b64:
            return b""
        # Gmail returns URL-safe base64; pad before decoding.
        pad = "=" * (-len(raw_b64) % 4)
        return base64.urlsafe_b64decode(raw_b64 + pad)

    @classmethod
    async def fetch_message_body(cls, user_id: str, message_id: str) -> dict:
        token = await cls.acquire_access_token(user_id)
        resp = await cls.request_with_retry(
            "GET",
            f"{_GMAIL_BASE}/users/me/messages/{message_id}",
            headers={"Authorization": f"Bearer {token}"},
            params={"format": "full"},
        )
        if resp.status_code >= 400:
            raise AuthError(
                f"Gmail GET (body) returned {resp.status_code}: {resp.text[:200]}"
            )
        data = resp.json()
        payload = data.get("payload") or {}
        headers = payload.get("headers") or []
        by_name = {h["name"].lower(): h.get("value", "") for h in headers}
        from_raw = by_name.get("from") or ""
        _, addr = parseaddr(from_raw)
        return {
            "subject": by_name.get("subject"),
            "from": addr or None,
            "received": _gmail_internaldate_to_iso(data.get("internalDate")),
            "html": _find_part_body(payload, "text/html"),
            "text": _find_part_body(payload, "text/plain"),
        }
