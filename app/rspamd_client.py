"""Async Rspamd client.

Posts synthesized RFC 822 messages to Rspamd's HTTP API for spam scoring
and Bayesian training. Per-user Bayes is scoped via the `Deliver-To`
header (Rspamd reads it to key its per-user filter when
`classifier-bayes.conf` has `per_user = true`).

Synthesized MIME is built from the metadata + body preview we already
have on each Message — we deliberately avoid fetching raw MIME from the
provider to keep audits fast (a 200-message audit would otherwise add
200 extra round-trips to Graph/Gmail). Rspamd loses URL/MIME-structure
signal but its Bayes still trains on subject + preview tokens, which is
where most of the discriminative signal lives for personal mailbox spam.
"""

from __future__ import annotations

import asyncio
import logging
import math
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid

import httpx

from .config import settings

logger = logging.getLogger(__name__)

# Strong refs to in-flight fire-and-forget learn tasks so they don't get
# garbage-collected mid-await. Tasks remove themselves on completion.
_pending: set[asyncio.Task] = set()


_PSEUDO_USER_DOMAIN = "agentx.local"


def is_enabled() -> bool:
    return bool(settings.rspamd_url)


def _deliver_to(user_id: str) -> str:
    """Per-user Bayes scoping key — Rspamd uses this header as the user
    identifier for storage. Stable per user_id.
    """
    safe = user_id.replace("@", "_at_").replace(" ", "_")
    return f"{safe}@{_PSEUDO_USER_DOMAIN}"


def synthesize_mime(message: dict) -> bytes:
    """Build a minimal RFC 822 message from a Message-shaped dict."""
    msg = EmailMessage()
    msg["From"] = message.get("from") or "unknown@unknown.example"
    msg["To"] = f"agent@{_PSEUDO_USER_DOMAIN}"
    msg["Subject"] = message.get("subject") or "(no subject)"

    received = message.get("received")
    if received:
        try:
            dt = datetime.fromisoformat(str(received).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            msg["Date"] = format_datetime(dt)
        except ValueError:
            pass

    mid = message.get("id")
    if mid:
        msg["Message-ID"] = f"<{mid}@{_PSEUDO_USER_DOMAIN}>"
    else:
        msg["Message-ID"] = make_msgid(domain=_PSEUDO_USER_DOMAIN)

    # Include the List-Unsubscribe header when available — Rspamd uses it
    # as a hint that this is bulk-but-legitimate-ish.
    unsub = message.get("unsubscribe_url")
    if unsub:
        msg["List-Unsubscribe"] = f"<{unsub}>"

    msg.set_content(message.get("preview") or "")
    return bytes(msg)


def _score_to_p_spam(score: float, required: float) -> float:
    """Map Rspamd's additive score to a [0, 1] spam probability via sigmoid
    centered on `required_score`."""
    spread = 3.0  # softness — lower = sharper transition
    try:
        return 1.0 / (1.0 + math.exp(-(score - required) / spread))
    except OverflowError:
        return 0.0 if score < required else 1.0


async def _check_mime(
    mime: bytes, sender: str | None, message_id: str | None, user_id: str
) -> dict | None:
    url = f"{settings.rspamd_url.rstrip('/')}/checkv2"
    headers = {
        "Deliver-To": _deliver_to(user_id),
        "From": sender or "unknown@unknown.example",
        "Content-Type": "message/rfc822",
        "Pass": "all",  # bypass rate-limit / greylisting modules
    }
    try:
        async with httpx.AsyncClient(timeout=settings.rspamd_timeout_seconds) as client:
            resp = await client.post(url, content=mime, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("rspamd check failed for %s: %s", message_id, exc)
        return None

    score = float(data.get("score") or 0.0)
    required = float(data.get("required_score") or 5.0)
    action = data.get("action") or "no action"
    return {
        "p_spam": _score_to_p_spam(score, required),
        "score": score,
        "required": required,
        "action": action,
        "symbols": list((data.get("symbols") or {}).keys()),
    }


async def check(message: dict, user_id: str) -> dict | None:
    """Synthesize MIME from the message metadata + preview and check it."""
    if not is_enabled():
        return None
    return await _check_mime(
        synthesize_mime(message), message.get("from"), message.get("id"), user_id
    )


async def check_raw(mime: bytes, message: dict, user_id: str) -> dict | None:
    """Check pre-fetched raw RFC 822 bytes. Used by the lazy-escalation
    path on borderline verdicts so Rspamd can analyze real headers, URLs,
    and attachment metadata."""
    if not is_enabled() or not mime:
        return None
    return await _check_mime(mime, message.get("from"), message.get("id"), user_id)


def _controller_url() -> str | None:
    """Resolve the Rspamd CONTROLLER base URL, where /learnspam // /learnham
    live (a different worker from the /checkv2 scanner).

    Precedence: explicit ``rspamd_controller_url`` → derive from ``rspamd_url``
    by swapping the default scanner port ``:11333`` for the controller port
    ``:11334`` → ``None`` (can't determine; learning is skipped).
    """
    if settings.rspamd_controller_url:
        return settings.rspamd_controller_url.rstrip("/")
    if settings.rspamd_url:
        base = settings.rspamd_url.rstrip("/")
        if base.endswith(":11333"):
            return base[: -len(":11333")] + ":11334"
        # Non-default scanner port and no explicit controller URL — we can't
        # safely guess the controller endpoint.
        logger.warning(
            "rspamd: can't derive controller URL from %s; set "
            "AGENT_RSPAMD_CONTROLLER_URL so learning works", base,
        )
    return None


async def learn(message: dict, user_id: str, label: str) -> None:
    """Fire-and-forget Bayes training. `label` is "spam" or "ham".

    Trains via the Rspamd CONTROLLER (/learnspam, /learnham) — NOT the scanner
    worker, which rejects learn with "invalid command". Best-effort: silent
    success, warns on real failure, never breaks a user-facing action.
    """
    if not is_enabled():
        return
    if label not in ("spam", "ham"):
        return
    url = _controller_url()
    if not url:
        return
    mime = synthesize_mime(message)
    headers = {
        "Deliver-To": _deliver_to(user_id),
        "From": message.get("from") or "unknown@unknown.example",
        "Content-Type": "message/rfc822",
    }
    if settings.rspamd_password:
        headers["Password"] = settings.rspamd_password
    try:
        async with httpx.AsyncClient(timeout=settings.rspamd_timeout_seconds) as client:
            resp = await client.post(f"{url}/learn{label}", content=mime, headers=headers)
            if resp.status_code >= 400:
                # 208 "already learned" is < 400 and fine; surface real failures
                # (e.g. 401 → controller needs a password / secure_ip).
                body = resp.text[:200] if resp.text else ""
                logger.warning(
                    "rspamd learn%s for %s returned %s: %s",
                    label, message.get("id"), resp.status_code, body,
                )
    except httpx.HTTPError as exc:
        logger.warning("rspamd learn%s failed for %s: %s", label, message.get("id"), exc)


def fire_learn(message: dict, user_id: str, label: str) -> None:
    """Best-effort, non-blocking Bayes training. Safe to call from a request
    handler — schedules the learn() coroutine and returns immediately."""
    if not is_enabled() or label not in ("spam", "ham"):
        return
    try:
        task = asyncio.create_task(learn(message, user_id, label))
    except RuntimeError:
        return  # no running loop (rare in our async app)
    _pending.add(task)
    task.add_done_callback(_pending.discard)
