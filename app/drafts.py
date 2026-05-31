"""Reply-draft generation.

The agent's standing guarantee is that it never sends mail on the user's
behalf — it only reads and trashes. Drafts respect that line exactly: this
module asks the local LLM to write a reply, and the provider saves it to the
mailbox's Drafts folder. Sending stays a deliberate, human action in the
user's real mail client.

Plain-text generation (no JSON envelope) via Ollama's /api/generate, using the
draft model (falls back to the chat model, then the classifier model).
"""

from __future__ import annotations

import logging
import re

import httpx

from .config import settings

logger = logging.getLogger(__name__)


class DraftError(Exception):
    """Raised when reply generation fails."""


_SYSTEM = (
    "You are the user's email assistant. Write a concise, polite reply to the "
    "email below, in the user's voice (first person). Reply only with the body "
    "text — no subject line, no 'Subject:', no quoted original, no placeholders "
    "like [Your Name]. Keep it short and to the point. If the email asks a "
    "question you can't answer on the user's behalf, write a brief holding "
    "reply acknowledging it. Do not invent specific facts, dates, or commitments."
)

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"[ \t]*\n[ \t]*")


def _html_to_text(html: str) -> str:
    """Crude HTML→text for feeding the model context (not for display)."""
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html)
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</p>", "\n\n", text)
    text = _TAG_RE.sub(" ", text)
    text = _WS_RE.sub("\n", text)
    return re.sub(r"[ \t]{2,}", " ", text).strip()


def _model() -> str:
    return settings.draft_model or settings.chat_model or settings.ollama_model


def _build_prompt(subject: str | None, from_addr: str | None, body_text: str) -> str:
    snippet = (body_text or "").strip()
    if len(snippet) > 4000:
        snippet = snippet[:4000] + "…"
    return (
        f"{_SYSTEM}\n\n"
        f"--- Email to reply to ---\n"
        f"From: {from_addr or '(unknown)'}\n"
        f"Subject: {subject or '(no subject)'}\n\n"
        f"{snippet or '(no body available)'}\n"
        f"--- End email ---\n\n"
        f"Your reply:"
    )


async def generate_reply(
    *,
    subject: str | None,
    from_addr: str | None,
    html: str | None = None,
    text: str | None = None,
) -> str:
    """Generate a plain-text reply body for the given message. Raises
    DraftError on any LLM failure so the caller can surface it."""
    body_text = (text or "").strip() or (_html_to_text(html) if html else "")
    payload = {
        "model": _model(),
        "prompt": _build_prompt(subject, from_addr, body_text),
        "stream": False,
        "options": {
            "temperature": 0.3,
            "num_predict": settings.draft_num_predict,
        },
    }
    try:
        async with httpx.AsyncClient(base_url=settings.ollama_url) as client:
            resp = await client.post(
                "/api/generate", json=payload, timeout=settings.ollama_timeout_seconds
            )
            resp.raise_for_status()
            reply = (resp.json().get("response") or "").strip()
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        raise DraftError(f"reply generation failed: {exc}") from exc
    if not reply:
        raise DraftError("model returned an empty reply")
    return reply
