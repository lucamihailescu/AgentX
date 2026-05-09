import asyncio
from datetime import datetime, timezone

import aiosqlite
import msal
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .config import settings

CLI_TOKEN_TTL_SECONDS = 60 * 60
_CLI_TOKEN_SALT = "agentx.cli-token"


class TokenAcquisitionError(Exception):
    pass


class CLITokenError(Exception):
    pass


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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_app(cache: msal.SerializableTokenCache | None = None) -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        client_id=settings.client_id,
        client_credential=settings.client_secret,
        authority=settings.authority,
        token_cache=cache,
    )


async def _load_cache(user_id: str) -> msal.SerializableTokenCache:
    cache = msal.SerializableTokenCache()
    async with aiosqlite.connect(settings.db_path) as db:
        cur = await db.execute("SELECT cache_blob FROM users WHERE user_id = ?", (user_id,))
        row = await cur.fetchone()
    if row:
        cache.deserialize(row[0])
    return cache


async def _save_cache(
    user_id: str, username: str | None, cache: msal.SerializableTokenCache
) -> None:
    if not cache.has_state_changed:
        return
    now = _now()
    async with aiosqlite.connect(settings.db_path) as db:
        await db.execute(
            """INSERT INTO users (user_id, username, cache_blob, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(user_id) DO UPDATE SET
                 cache_blob = excluded.cache_blob,
                 username = COALESCE(excluded.username, users.username),
                 updated_at = excluded.updated_at""",
            (user_id, username, cache.serialize(), now, now),
        )
        await db.commit()


def build_auth_code_flow() -> dict:
    """Returns the MSAL flow dict containing the auth URL plus PKCE state.
    Caller stores the dict in the user's session and redirects to flow['auth_uri'].
    """
    return _build_app().initiate_auth_code_flow(
        scopes=settings.scopes,
        redirect_uri=settings.redirect_uri,
    )


async def complete_auth_code_flow(flow: dict, query_params: dict) -> tuple[str, str | None]:
    """Exchange the authorization code for tokens, persist the resulting cache,
    and return (user_id, username)."""
    cache = msal.SerializableTokenCache()
    app = _build_app(cache)
    result = await asyncio.to_thread(app.acquire_token_by_auth_code_flow, flow, query_params)
    if "error" in result:
        raise TokenAcquisitionError(
            f"{result.get('error')}: {result.get('error_description', '')}"
        )
    accounts = app.get_accounts()
    if not accounts:
        raise TokenAcquisitionError("Token cache empty after authorization-code exchange")
    account = accounts[0]
    user_id = account["home_account_id"]
    username = (
        result.get("id_token_claims", {}).get("preferred_username") or account.get("username")
    )
    await _save_cache(user_id, username, cache)
    return user_id, username


async def acquire_access_token(user_id: str) -> str:
    """Silently acquire a fresh access token for the given user.

    MSAL returns the cached token if still valid; otherwise it uses the cached
    refresh token to mint a new one. Any cache mutations are persisted back.
    """
    cache = await _load_cache(user_id)
    app = _build_app(cache)
    accounts = app.get_accounts()
    if not accounts:
        raise TokenAcquisitionError(f"No cached account for user {user_id}")
    account = accounts[0]
    result = await asyncio.to_thread(app.acquire_token_silent, settings.scopes, account)
    await _save_cache(user_id, account.get("username"), cache)
    if not result or "access_token" not in result:
        err = (result or {}).get("error_description") or "silent token acquisition returned None"
        raise TokenAcquisitionError(err)
    return result["access_token"]
