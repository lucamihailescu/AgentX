"""Periodic digest aggregator.

Walks completed audit + purge tasks in a user's window and builds a summary
of cleanup activity, top spammy senders, new rules added, and a "needs your
eye" list of borderline messages still worth a human glance.

The output is shaped to be stored on `tasks.result_data` (same plumbing as
audits/purges), so the rest of the system — claim loop, status pills,
listing — works unchanged for `kind='digest'`.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import aiosqlite

from .config import settings


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# Confidence range that means "model leaned spam but isn't certain" — the
# rows worth surfacing for explicit confirmation.
_BORDERLINE_LOW = 0.40
_BORDERLINE_HIGH = 0.75
_NEEDS_EYE_CAP = 30
_TOP_SENDERS_CAP = 5
_ACTION_ITEMS_CAP = 30
_PHISHING_CAP = 30


def _is_borderline(m: dict) -> bool:
    if m.get("deleted") or m.get("auto_deleted") or m.get("unsubscribed"):
        return False
    if m.get("rule_applied"):
        return False
    if not m.get("id"):
        return False
    if m.get("spam") is None:
        return True  # Ollama failed — surface it for review
    if m.get("spam") is True:
        conf = m.get("confidence")
        if isinstance(conf, (int, float)) and _BORDERLINE_LOW <= conf <= _BORDERLINE_HIGH:
            return True
    return False


async def generate_digest(user_id: str, window_hours: int) -> dict:
    now = datetime.now(timezone.utc)
    since = (now - timedelta(hours=window_hours)).isoformat()

    async with aiosqlite.connect(settings.db_path) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """SELECT task_id, kind, result_data
               FROM tasks
               WHERE user_id = ? AND status = 'completed'
                 AND kind IN ('audit', 'purge')
                 AND created_at >= ?
               ORDER BY created_at""",
            (user_id, since),
        )
        task_rows = await cur.fetchall()

        cur = await db.execute(
            """SELECT target, target_type, verdict, created_at
               FROM sender_rules
               WHERE user_id = ? AND created_at >= ?
               ORDER BY created_at DESC""",
            (user_id, since),
        )
        new_rules = [dict(r) for r in await cur.fetchall()]

    counts = {
        "audits_completed": 0,
        "purges_completed": 0,
        "messages_scanned": 0,
        "auto_deleted": 0,        # blocklist + deny-rule deletions during audits
        "spam_flagged": 0,        # Ollama verdict == spam
        "user_deleted": 0,        # manual deletes recorded against audit rows
        "user_unsubscribed": 0,   # manual unsubs against audit rows
        "purge_deleted": 0,       # cleanup-pass deletions
        "phishing_flagged": 0,    # phishing/BEC heuristics flagged
        "needs_reply": 0,         # messages the model thinks want a reply
    }
    sender_spam: dict[str, int] = {}
    needs_eye: list[dict] = []
    seen_eye_senders: set[str] = set()
    action_items: list[dict] = []
    phishing: list[dict] = []

    for row in task_rows:
        if not row["result_data"]:
            continue
        try:
            result = json.loads(row["result_data"])
        except json.JSONDecodeError:
            continue

        if row["kind"] == "purge":
            counts["purges_completed"] += 1
            counts["purge_deleted"] += int(result.get("messages_deleted") or 0)
            continue

        counts["audits_completed"] += 1
        for m in result.get("messages", []):
            counts["messages_scanned"] += 1
            sender = (m.get("from") or "").strip().lower()
            if m.get("auto_deleted"):
                counts["auto_deleted"] += 1
            if m.get("spam") is True:
                counts["spam_flagged"] += 1
                if sender:
                    sender_spam[sender] = sender_spam.get(sender, 0) + 1
            if m.get("deleted") and not m.get("auto_deleted"):
                counts["user_deleted"] += 1
            if m.get("unsubscribed"):
                counts["user_unsubscribed"] += 1
            if m.get("needs_reply"):
                counts["needs_reply"] += 1

            # Action items: a requested action and/or a needs-reply message
            # still sitting in the inbox (not deleted / unsubscribed).
            if (
                (m.get("action") or m.get("needs_reply"))
                and not m.get("deleted")
                and not m.get("auto_deleted")
                and not m.get("unsubscribed")
                and len(action_items) < _ACTION_ITEMS_CAP
            ):
                action_items.append({
                    "audit_task_id": row["task_id"],
                    "message_id": m.get("id"),
                    "from": m.get("from"),
                    "subject": m.get("subject"),
                    "action": m.get("action"),
                    "due": m.get("due"),
                    "needs_reply": bool(m.get("needs_reply")),
                    "received": m.get("received"),
                })

            if m.get("phishing"):
                counts["phishing_flagged"] += 1
                if len(phishing) < _PHISHING_CAP:
                    phishing.append({
                        "audit_task_id": row["task_id"],
                        "message_id": m.get("id"),
                        "from": m.get("from"),
                        "subject": m.get("subject"),
                        "received": m.get("received"),
                        "phishing_reasons": m.get("phishing_reasons") or [],
                    })

            if (
                _is_borderline(m)
                and sender
                and sender not in seen_eye_senders
                and len(needs_eye) < _NEEDS_EYE_CAP
            ):
                seen_eye_senders.add(sender)
                needs_eye.append({
                    "audit_task_id": row["task_id"],
                    "message_id": m.get("id"),
                    "from": m.get("from"),
                    "subject": m.get("subject"),
                    "received": m.get("received"),
                    "confidence": m.get("confidence"),
                    "spam": m.get("spam"),
                    "reason": m.get("reason"),
                })

    top_spam_senders = sorted(
        sender_spam.items(), key=lambda kv: kv[1], reverse=True
    )[:_TOP_SENDERS_CAP]

    return {
        "kind": "digest",
        "generated_at": _now(),
        "window_hours": window_hours,
        "window_start": since,
        "window_end": now.isoformat(),
        "counts": counts,
        "top_spam_senders": [
            {"from": s, "spam": n} for s, n in top_spam_senders
        ],
        "new_rules": new_rules,
        "needs_eye": needs_eye,
        "action_items": action_items,
        "phishing": phishing,
    }
