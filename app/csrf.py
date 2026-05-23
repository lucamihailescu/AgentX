"""Minimal double-submit CSRF middleware.

Issues a random `csrftoken` cookie on every response; on any unsafe-method
request (POST/PUT/PATCH/DELETE) requires the same value to be presented
either as the `X-CSRF-Token` header or as a `csrftoken` form field.

Exemptions:
  - Safe methods (GET / HEAD / OPTIONS) — never checked, but always set
    the cookie if missing so the next state-changing request can succeed.
  - Bearer-authenticated requests — CSRF attacks rely on browser-managed
    cookies; an `Authorization: Bearer ...` request is by definition
    coming from a non-browser caller (curl, scripts, CLI tokens).

The token is stashed on `request.state.csrftoken` so Jinja templates can
emit `<input type="hidden" name="csrftoken" value="...">` via the
`_csrf.html` include — no new dependency, no third-party middleware.
"""

from __future__ import annotations

import hmac
import logging
import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

logger = logging.getLogger(__name__)

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_COOKIE_NAME = "csrftoken"
_HEADER_NAME = "x-csrf-token"
_FORM_FIELD = "csrftoken"


class CSRFMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, secure: bool) -> None:
        super().__init__(app)
        self._secure = secure

    async def dispatch(self, request: Request, call_next) -> Response:
        cookie_val = request.cookies.get(_COOKIE_NAME)
        token = cookie_val or secrets.token_urlsafe(32)
        request.state.csrftoken = token

        if request.method not in _SAFE_METHODS:
            # Bearer auth bypass — see module docstring.
            auth_header = request.headers.get("authorization", "")
            if not auth_header.lower().startswith("bearer "):
                if not cookie_val:
                    return PlainTextResponse(
                        "CSRF cookie missing", status_code=403
                    )
                sent = request.headers.get(_HEADER_NAME)
                if not sent:
                    ctype = request.headers.get("content-type", "").lower()
                    if (
                        "application/x-www-form-urlencoded" in ctype
                        or "multipart/form-data" in ctype
                    ):
                        # request.form() caches the parsed body so the
                        # downstream handler can still read it.
                        form = await request.form()
                        sent = form.get(_FORM_FIELD)
                if not sent or not hmac.compare_digest(str(sent), cookie_val):
                    logger.warning(
                        "CSRF reject: %s %s", request.method, request.url.path
                    )
                    return PlainTextResponse(
                        "CSRF token mismatch", status_code=403
                    )

        response = await call_next(request)
        if not cookie_val:
            response.set_cookie(
                _COOKIE_NAME,
                token,
                httponly=False,  # JS must be able to read for XHR
                samesite="lax",
                secure=self._secure,
                max_age=60 * 60 * 24 * 30,
                path="/",
            )
        return response
