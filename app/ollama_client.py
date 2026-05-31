import json
import logging

import httpx

from .categories import CATEGORIES, normalize_category
from .config import settings

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are an email spam classifier. Given the sender, subject and preview "
    "of an email, decide if it is unsolicited marketing, phishing, or other "
    "spam.\n\n"
    "Respond with ONLY a JSON object with EXACTLY these three keys:\n"
    '  - "spam": boolean — true or false. MUST be present and MUST be named '
    '"spam" (not "is_spam", "verdict", "label", "category", or anything else).\n'
    '  - "confidence": number between 0 and 1.\n'
    '  - "reason": short string explaining the verdict.\n\n'
    'Example: {"spam": true, "confidence": 0.92, "reason": "promotional '
    'language and unknown sender"}'
)

# Appended to the system prompt when triage is enabled — asks for two extra
# keys (`category`, `needs_reply`) in the same round-trip so categorization
# costs no additional LLM call. Kept separate so disabling categorization
# returns the prompt to its original, spam-only shape.
_CATEGORIZE_ADDENDUM = (
    "\n\nAlso include these TWO additional keys in the same JSON object:\n"
    '  - "category": one of EXACTLY these values — '
    + ", ".join(f'"{c}"' for c in CATEGORIES)
    + ". Pick the single best fit; use \"Other\" when unsure.\n"
    '  - "needs_reply": boolean — true ONLY when a real person is writing '
    "directly to the recipient and is waiting for a personal answer (a "
    "colleague, friend, customer, or vendor who asked something). Judge this "
    "by WHO is writing and whether they await a reply — NOT by punctuation. A "
    "question mark or a rhetorical/clickbait headline question in the SUBJECT "
    "of a newsletter, article, advice column, promotion, digest, or automated "
    "notification does NOT make it needs_reply. Newsletters, promotions, "
    "receipts, notifications, and mail from no-reply/automated senders are "
    "ALWAYS false.\n\n"
    'Full example: {"spam": false, "confidence": 0.88, "reason": "personal '
    'note from a colleague", "category": "Personal", "needs_reply": true}'
)

# Appended (after the categorize addendum) when action extraction is on.
_ACTIONS_ADDENDUM = (
    "\n\nIf — and only if — the email asks the recipient to DO something "
    "(reply, pay, confirm, review, schedule, submit), also include:\n"
    '  - "action": a short imperative summary (max ~10 words) of what is '
    "being asked, or null if nothing is requested.\n"
    '  - "due": the deadline as an ISO date (YYYY-MM-DD) if one is stated, '
    "else null.\n"
    "Omit both (or set them null) for newsletters, receipts, and "
    "notifications that need no action."
)

# Keys we'll accept when the model picks a near-synonym instead of "spam".
_SPAM_KEY_VARIANTS = (
    "spam",
    "is_spam",
    "isSpam",
    "spam_flag",
    "verdict",
    "label",
    "classification",
    "category",
)

# Values we'll map to True / False when the model returns a string instead
# of a bool.
_TRUE_STRINGS = frozenset({
    "true", "yes", "1", "spam", "is_spam", "isspam",
    "junk", "promotional", "marketing", "phishing",
})
_FALSE_STRINGS = frozenset({
    "false", "no", "0", "ham", "not_spam", "not spam",
    "ok", "clean", "legitimate", "important", "personal",
})


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
    categorize: bool = False,
    extract_actions: bool = False,
) -> str:
    parts: list[str] = [_SYSTEM_PROMPT]
    if categorize:
        parts.append(_CATEGORIZE_ADDENDUM)
        if extract_actions:
            parts.append(_ACTIONS_ADDENDUM)
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


# Local-parts that mark an automated / unattended sender — mail from these is
# never something a human is "waiting to reply to".
_NOREPLY_HINTS = (
    "noreply", "no-reply", "no_reply",
    "donotreply", "do-not-reply", "do_not_reply",
)
# Categories that are, by definition, broadcast — not interpersonal mail.
_BULK_CATEGORIES = frozenset({"Newsletter/Promotions", "Notifications/Updates"})


def _is_bulk_mail(message: dict, category: str | None) -> bool:
    """Deterministic 'this is broadcast/automated, not a personal message'
    check, used to veto a model `needs_reply=true` on bulk mail.

    The classic false positive is a newsletter / advice column whose subject is
    phrased as a question ("Will I get canceled for ...?"); the model reads the
    question mark as "awaiting a reply". These signals don't depend on the LLM:

      * a `List-Unsubscribe` header (captured as `unsubscribe_url`) — only bulk
        senders ship one;
      * a no-reply / do-not-reply local-part;
      * a category that is inherently broadcast (newsletter / notification).
    """
    if message.get("unsubscribe_url"):
        return True
    local = (message.get("from") or "").split("@", 1)[0].lower()
    if any(hint in local for hint in _NOREPLY_HINTS):
        return True
    return category in _BULK_CATEGORIES


def _coerce_bool(value: object) -> bool | None:
    """Best-effort coercion of common value shapes to a boolean spam verdict.
    Accepts bools directly, ints (0/1), and strings (true/yes/spam/false/...).
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int):  # also covers True/False since bool ⊂ int,
        if value in (0, 1):     # but the bool branch above runs first.
            return bool(value)
        return None
    if isinstance(value, float):
        if value in (0.0, 1.0):
            return bool(value)
        return None
    if isinstance(value, str):
        v = value.strip().lower()
        if v in _TRUE_STRINGS:
            return True
        if v in _FALSE_STRINGS:
            return False
    return None


def _extract_spam(verdict: dict) -> bool | None:
    """Try the documented key first, then known synonyms. Returns the first
    key whose value coerces to a boolean."""
    for key in _SPAM_KEY_VARIANTS:
        if key in verdict:
            result = _coerce_bool(verdict[key])
            if result is not None:
                return result
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
    categorize = settings.categorize_enabled
    extract_actions = categorize and settings.extract_actions_enabled
    payload = {
        "model": settings.ollama_model,
        "prompt": _build_prompt(
            message.get("from"),
            message.get("subject"),
            message.get("preview"),
            ham_examples=ham_examples,
            spam_examples=spam_examples,
            categorize=categorize,
            extract_actions=extract_actions,
        ),
        "format": "json",
        "stream": False,
        "options": {
            "num_ctx": settings.ollama_num_ctx,
            "temperature": settings.ollama_temperature,
            "num_predict": settings.ollama_num_predict,
        },
    }
    raw_response: str = ""
    try:
        resp = await client.post(
            "/api/generate", json=payload, timeout=settings.ollama_timeout_seconds
        )
        resp.raise_for_status()
        raw_response = resp.json().get("response", "")
        verdict = json.loads(raw_response)
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        out = {
            "spam": None,
            "confidence": None,
            "reason": f"classification failed: {exc}"[:200],
        }
        if categorize:
            out["category"] = None
            out["needs_reply"] = None
        return out

    spam_val = _extract_spam(verdict) if isinstance(verdict, dict) else None
    if spam_val is None:
        # Diagnostic: the model returned valid JSON but in a shape we didn't
        # recognize. Surface what we got so the prompt / extractor can be
        # tuned. Truncated to keep logs readable.
        keys = list(verdict.keys()) if isinstance(verdict, dict) else type(verdict).__name__
        logger.warning(
            "classify: no spam verdict in %r (keys=%s) — raw=%r",
            (message.get("from") or "")[:60],
            keys,
            raw_response[:200],
        )
    result = {
        "spam": spam_val,
        "confidence": _coerce_confidence(verdict.get("confidence")) if isinstance(verdict, dict) else None,
        "reason": verdict.get("reason") if isinstance(verdict, dict) else None,
    }
    if categorize:
        vd = verdict if isinstance(verdict, dict) else {}
        result["category"] = normalize_category(vd.get("category"))
        result["needs_reply"] = bool(_coerce_bool(vd.get("needs_reply")))
        # Veto needs_reply on broadcast/automated mail regardless of how the
        # subject is phrased — the model over-triggers on question headlines.
        if result["needs_reply"] and _is_bulk_mail(message, result["category"]):
            result["needs_reply"] = False
        if extract_actions:
            action = vd.get("action")
            result["action"] = action.strip()[:160] if isinstance(action, str) and action.strip() else None
            due = vd.get("due")
            result["due"] = due.strip()[:32] if isinstance(due, str) and due.strip() and due.strip().lower() != "null" else None
    return result
