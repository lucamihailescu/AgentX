import json

import httpx

from .config import settings

_SYSTEM_PROMPT = (
    "You are an email spam classifier. Given the sender, subject and preview of "
    "an email, decide if it is unsolicited marketing, phishing, or other spam. "
    "Reply with ONLY a JSON object: "
    '{"spam": <boolean>, "confidence": <0..1>, "reason": "<short explanation>"}'
)


def _build_prompt(sender: str | None, subject: str | None, preview: str | None) -> str:
    return (
        f"{_SYSTEM_PROMPT}\n\n"
        f"From: {sender or '(unknown)'}\n"
        f"Subject: {subject or '(no subject)'}\n"
        f"Preview: {(preview or '').strip()}"
    )


def _coerce_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "spam", "1")
    return None


def _coerce_confidence(value: object) -> float | None:
    if isinstance(value, (int, float)) and 0 <= float(value) <= 1:
        return float(value)
    return None


async def classify(client: httpx.AsyncClient, message: dict) -> dict:
    """Return {spam, confidence, reason}. On any failure return spam=None with
    the failure reason — the per-message verdict is best-effort."""
    payload = {
        "model": settings.ollama_model,
        "prompt": _build_prompt(
            message.get("from"), message.get("subject"), message.get("preview")
        ),
        "format": "json",
        "stream": False,
    }
    try:
        resp = await client.post(
            "/api/generate", json=payload, timeout=settings.ollama_timeout_seconds
        )
        resp.raise_for_status()
        verdict = json.loads(resp.json()["response"])
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        return {"spam": None, "confidence": None, "reason": f"classification failed: {exc}"[:200]}
    return {
        "spam": _coerce_bool(verdict.get("spam")),
        "confidence": _coerce_confidence(verdict.get("confidence")),
        "reason": verdict.get("reason"),
    }
