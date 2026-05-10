import json

import httpx

from .config import settings

_SYSTEM_PROMPT = (
    "You are an email spam classifier. Given the sender, subject and preview of "
    "an email, decide if it is unsolicited marketing, phishing, or other spam. "
    "Reply with ONLY a JSON object: "
    '{"spam": <boolean>, "confidence": <0..1>, "reason": "<short explanation>"}'
)


def _format_example(label: str, ex: dict) -> str:
    return (
        f"\n\n[{label}]\n"
        f"  From: {ex.get('from') or '(unknown)'}\n"
        f"  Subject: {ex.get('subject') or '(no subject)'}\n"
        f"  Preview: {ex.get('preview') or ''}"
    )


def _build_prompt(
    sender: str | None,
    subject: str | None,
    preview: str | None,
    *,
    ham_examples: list[dict] | None = None,
    spam_examples: list[dict] | None = None,
) -> str:
    parts: list[str] = [_SYSTEM_PROMPT]
    if ham_examples or spam_examples:
        parts.append(
            "\n\nUse these previously-classified examples from this user's "
            "history as guidance — calibrate the verdict to match their taste:"
        )
        for ex in spam_examples or []:
            parts.append(_format_example("SPAM", ex))
        for ex in ham_examples or []:
            parts.append(_format_example("NOT SPAM", ex))
        parts.append("\n\nNow classify this new email:")
    parts.append(
        f"\n\nFrom: {sender or '(unknown)'}\n"
        f"Subject: {subject or '(no subject)'}\n"
        f"Preview: {(preview or '').strip()}"
    )
    return "".join(parts)


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


async def classify(
    client: httpx.AsyncClient,
    message: dict,
    *,
    ham_examples: list[dict] | None = None,
    spam_examples: list[dict] | None = None,
) -> dict:
    """Return {spam, confidence, reason}. On any failure return spam=None with
    the failure reason — the per-message verdict is best-effort.

    Pass `ham_examples` / `spam_examples` to inject few-shot context drawn
    from the user's prior verdicts.
    """
    payload = {
        "model": settings.ollama_model,
        "prompt": _build_prompt(
            message.get("from"),
            message.get("subject"),
            message.get("preview"),
            ham_examples=ham_examples,
            spam_examples=spam_examples,
        ),
        "format": "json",
        "stream": False,
        "options": {
            "num_ctx": settings.ollama_num_ctx,
            "temperature": settings.ollama_temperature,
            "num_predict": settings.ollama_num_predict,
        },
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
