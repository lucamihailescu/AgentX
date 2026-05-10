"""Auth utilities shared across providers.

The Microsoft- and Google-specific OAuth flows live in `app/providers/`. What
remains here is provider-agnostic infrastructure:

- ``_encrypt_blob`` / ``_decrypt_blob`` — Fernet encryption used to wrap each
  provider's serialized cache before persisting to ``users.cache_blob``.
- ``acquire_access_token`` — looks up the user's provider and delegates.
- ``CLI token`` — itsdangerous-signed bearer for shell use.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
from functools import lru_cache

import aiosqlite
from cryptography.fernet import Fernet, InvalidToken
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .config import settings

CLI_TOKEN_TTL_SECONDS = 60 * 60
_CLI_TOKEN_SALT = "agentx.cli-token"


class TokenAcquisitionError(Exception):
    pass


class CLITokenError(Exception):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── cache encryption ──────────────────────────────────────────────────────
@lru_cache(maxsize=1)
def _cache_cipher() -> Fernet:
    """Derive the Fernet key for the encrypted token cache.

    Prefers `AGENT_CACHE_KEY` (when set) so it can be rotated independently
    from the session-cookie signing secret. Falls back to deriving from
    `SESSION_SECRET` for backward compatibility — but that path means
    rotating session_secret invalidates every user's stored tokens.
    """
    secret = settings.cache_key or settings.session_secret
    digest = hashlib.sha256(("cache:" + secret).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def _encrypt_blob(plaintext: str) -> str:
    return _cache_cipher().encrypt(plaintext.encode()).decode()


def _decrypt_blob(stored: str) -> str:
    """Decrypt; fall back to raw text so legacy unencrypted rows still work."""
    try:
        return _cache_cipher().decrypt(stored.encode()).decode()
    except InvalidToken:
        return stored


# ── provider lookup ───────────────────────────────────────────────────────
async def get_user_provider_name(user_id: str) -> str | None:
    async with aiosqlite.connect(settings.db_path) as db:
        cur = await db.execute(
            "SELECT provider FROM users WHERE user_id = ?", (user_id,)
        )
        row = await cur.fetchone()
    return row[0] if row else None


async def acquire_access_token(user_id: str) -> str:
    """Provider-agnostic facade — used by the worker / main.py routes that
    don't care which mailbox backend a user is on."""
    from .providers import get_provider  # local import to avoid cycle

    name = await get_user_provider_name(user_id)
    if not name:
        raise TokenAcquisitionError(f"unknown user {user_id}")
    try:
        return await get_provider(name).acquire_access_token(user_id)
    except Exception as exc:
        raise TokenAcquisitionError(str(exc)) from exc


# ── CLI bearer token (itsdangerous) ───────────────────────────────────────
def _cli_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.session_secret, salt=_CLI_TOKEN_SALT)


def issue_cli_token(user_id: str) -> tuple[str, int]:
    return _cli_serializer().dumps(user_id), CLI_TOKEN_TTL_SECONDS


def verify_cli_token(token: str) -> str:
    try:
        return _cli_serializer().loads(token, max_age=CLI_TOKEN_TTL_SECONDS)
    except SignatureExpired as exc:
        raise CLITokenError("CLI token expired") from exc
    except BadSignature as exc:
        raise CLITokenError("Invalid CLI token") from exc
