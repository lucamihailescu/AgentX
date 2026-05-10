"""Pulls (subject, from, preview, verdict) examples from the user's past
audit history to use as few-shot context when prompting Ollama.

Only *explicit* user feedback counts as a label — messages the user simply
left alone don't teach the model anything (they could be unread, ignored,
or about-to-be-deleted). The signals we treat as authoritative:

- ``rule_applied == "allow"``        → ham
- ``rule_applied == "deny"``         → spam
- ``auto_deleted``                   → spam (matched a blocklist or deny rule
                                       the user installed; same intent)
- ``deleted`` AND ``spam is True``   → spam (user agreed with the model and
                                       acted on it)
- ``unsubscribed``                   → spam (active "get me out" signal)
"""

from __future__ import annotations

import json

import aiosqlite

from .config import settings

_RECENT_AUDIT_LIMIT = 30


def _label_for(m: dict) -> str | None:
    if m.get("rule_applied") == "deny":
        return "spam"
    if m.get("rule_applied") == "allow":
        return "ham"
    if m.get("auto_deleted"):
        return "spam"
    if m.get("deleted") and m.get("spam") is True:
        return "spam"
    if m.get("unsubscribed"):
        return "spam"
    return None


async def collect_examples(
    user_id: str, max_per_class: int
) -> tuple[list[dict], list[dict]]:
    """Walk recent completed audits for a balanced sample of labeled messages.

    Returns ``(ham_examples, spam_examples)``. Each example is a dict with
    ``from``, ``subject``, ``preview`` (truncated). Senders are deduped across
    audits — one example per unique sender, biased toward most-recent.
    """
    if max_per_class <= 0:
        return [], []

    ham: list[dict] = []
    spam: list[dict] = []
    seen: set[str] = set()

    async with aiosqlite.connect(settings.db_path) as db:
        cur = await db.execute(
            """SELECT result_data FROM tasks
               WHERE user_id = ? AND status = 'completed'
                     AND result_data IS NOT NULL
               ORDER BY created_at DESC
               LIMIT ?""",
            (user_id, _RECENT_AUDIT_LIMIT),
        )
        rows = await cur.fetchall()

    for (raw,) in rows:
        if len(ham) >= max_per_class and len(spam) >= max_per_class:
            break
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        for m in data.get("messages", []):
            if len(ham) >= max_per_class and len(spam) >= max_per_class:
                break
            sender = (m.get("from") or "").strip().lower()
            if not sender or sender in seen:
                continue
            label = _label_for(m)
            if label is None:
                continue
            example = {
                "from": sender,
                "subject": (m.get("subject") or "")[:120].strip(),
                "preview": (m.get("preview") or "")[:160].replace("\n", " ").strip(),
            }
            if label == "spam" and len(spam) < max_per_class:
                spam.append(example)
                seen.add(sender)
            elif label == "ham" and len(ham) < max_per_class:
                ham.append(example)
                seen.add(sender)

    return ham, spam
