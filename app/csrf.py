"""Minimal double-submit CSRF middleware (pure ASGI).

Implemented as a pure ASGI middleware rather than via BaseHTTPMiddleware
because the latter pattern consumes the request body when validating the
form CSRF field — which silently breaks every downstream handler that
reads the form. Here we read the body once, validate, then replay it to
the wrapped app through a synthetic `receive` callable.

Validation:
  - Safe methods (GET/HEAD/OPTIONS): never checked. Cookie is set if
    missing so the next state-changing request can succeed.
  - Bearer-authenticated requests: exempt. CSRF attacks rely on
    browser-managed cookies; an `Authorization: Bearer ...` request is
    by definition coming from a non-browser caller (curl, scripts, CLI).
  - Everything else: cookie `csrftoken` must equal either header
    `X-CSRF-Token` or form field `csrftoken`.

The token is stashed on `request.state.csrftoken` so Jinja templates can
emit it via the `_csrf.html` include — no extra dependency, no
per-handler boilerplate.
"""

from __future__ import annotations

import hmac
import logging
import re
import secrets
from http.cookies import SimpleCookie
from urllib.parse import parse_qsl

from starlette.datastructures import State

logger = logging.getLogger(__name__)

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_COOKIE_NAME = "csrftoken"
_FORM_FIELD = "csrftoken"
_BOUNDARY_RE = re.compile(r"boundary=([^;]+)")


def _header(scope, name: bytes) -> str | None:
    for k, v in scope.get("headers", []):
        if k == name:
            return v.decode("latin-1")
    return None


def _cookie_value(scope, name: str) -> str | None:
    raw = _header(scope, b"cookie")
    if not raw:
        return None
    jar = SimpleCookie()
    try:
        jar.load(raw)
    except Exception:
        return None
    morsel = jar.get(name)
    return morsel.value if morsel else None


async def _read_body(receive) -> bytes:
    chunks: list[bytes] = []
    while True:
        msg = await receive()
        t = msg.get("type")
        if t == "http.request":
            chunks.append(msg.get("body", b""))
            if not msg.get("more_body"):
                return b"".join(chunks)
        elif t == "http.disconnect":
            return b"".join(chunks)


def _replay_receive(body: bytes):
    """Return a receive() callable that emits the buffered body once,
    then signals disconnect on subsequent calls. Downstream handlers
    parse the body the same way they would from a fresh request."""
    sent = False

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}
    return receive


def _extract_multipart_field(body: bytes, ctype: str, field: str) -> str | None:
    """Fish a simple text form field out of a multipart body. Good enough
    for the CSRF token without depending on a full multipart parser."""
    m = _BOUNDARY_RE.search(ctype)
    if not m:
        return None
    boundary = ("--" + m.group(1).strip().strip('"')).encode("latin-1")
    needle = f'name="{field}"'.encode("latin-1")
    for part in body.split(boundary):
        if needle not in part:
            continue
        sep = part.find(b"\r\n\r\n")
        if sep == -1:
            continue
        value = part[sep + 4 :].rstrip(b"\r\n-")
        try:
            return value.decode("utf-8").strip()
        except UnicodeDecodeError:
            return None
    return None


def _wrap_send_with_cookie(send, token: str, secure: bool):
    cookie = f"{_COOKIE_NAME}={token}; Path=/; Max-Age=2592000; SameSite=Lax"
    if secure:
        cookie += "; Secure"
    cookie_bytes = cookie.encode("latin-1")

    async def wrapped(message):
        if message.get("type") == "http.response.start":
            headers = list(message.get("headers", []))
            headers.append((b"set-cookie", cookie_bytes))
            message = {**message, "headers": headers}
        await send(message)
    return wrapped


async def _send_text(send, status: int, body: str) -> None:
    payload = body.encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", str(len(payload)).encode("latin-1")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})


class CSRFMiddleware:
    def __init__(self, app, *, secure: bool) -> None:
        self.app = app
        self.secure = secure

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        cookie_val = _cookie_value(scope, _COOKIE_NAME)
        token = cookie_val or secrets.token_urlsafe(32)

        # Make request.state.csrftoken work in templates. Starlette uses
        # a State object on scope["state"]; mirror that contract.
        state = scope.get("state")
        if not isinstance(state, State):
            state = State()
            scope["state"] = state
        state.csrftoken = token

        method = scope["method"]
        receive_for_app = receive

        if method not in _SAFE_METHODS:
            authz = _header(scope, b"authorization") or ""
            if not authz.lower().startswith("bearer "):
                if not cookie_val:
                    await _send_text(send, 403, "CSRF cookie missing")
                    return

                sent = _header(scope, b"x-csrf-token")
                if not sent:
                    ctype = (_header(scope, b"content-type") or "").lower()
                    is_urlencoded = "application/x-www-form-urlencoded" in ctype
                    is_multipart = "multipart/form-data" in ctype
                    if is_urlencoded or is_multipart:
                        body = await _read_body(receive)
                        receive_for_app = _replay_receive(body)
                        if is_urlencoded:
                            try:
                                pairs = parse_qsl(
                                    body.decode("utf-8"), keep_blank_values=True
                                )
                            except UnicodeDecodeError:
                                pairs = []
                            for k, v in pairs:
                                if k == _FORM_FIELD:
                                    sent = v
                                    break
                        else:
                            sent = _extract_multipart_field(
                                body, ctype, _FORM_FIELD
                            )

                if not sent or not hmac.compare_digest(str(sent), cookie_val):
                    logger.warning(
                        "CSRF reject: %s %s", method, scope["path"]
                    )
                    await _send_text(send, 403, "CSRF token mismatch")
                    return

        send_for_app = (
            send if cookie_val else _wrap_send_with_cookie(send, token, self.secure)
        )
        await self.app(scope, receive_for_app, send_for_app)
