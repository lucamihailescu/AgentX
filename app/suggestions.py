"""Proactive rule suggestions.

Watches `sender_stats` for senders the user has *manually* acted against
repeatedly (delete + unsubscribe via the UI) and surfaces them as candidates
for an `address`-level deny rule. Auto-deletes (blocklist / existing deny
rule) don't count toward the signal — only user-initiated actions do.

Senders that already have any rule, or have been dismissed, are excluded.
"""

from __future__ import annotations

from datetime import datetime, timezone

import aiosqlite

from .config import settings


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def list_block_suggestions(
    user_id: str,
    *,
    threshold: int | None = None,
    limit: int | None = None,
) -> list[dict]:
    """Return the top senders the user keeps deleting/unsubscribing from
    that don't yet have a rule and haven't been dismissed."""
    threshold = threshold if threshold is not None else settings.suggest_block_threshold
    limit = limit if limit is not None else settings.suggest_max_items
    async with aiosqlite.connect(settings.db_path) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """SELECT s.target, s.deleted, s.unsubscribed, s.seen
               FROM sender_stats s
               WHERE s.user_id = ?
                 AND s.target_type = 'address'
                 AND (s.deleted + s.unsubscribed) >= ?
                 AND NOT EXISTS (
                   SELECT 1 FROM sender_rules r
                   WHERE r.user_id = s.user_id
                     AND r.target_type = 'address'
                     AND r.target = s.target
                 )
                 AND NOT EXISTS (
                   SELECT 1 FROM suggestion_dismissals d
                   WHERE d.user_id = s.user_id
                     AND d.target_type = 'address'
                     AND d.target = s.target
                     AND d.suggestion_kind = 'block'
                 )
               ORDER BY (s.deleted + s.unsubscribed) DESC,
                        s.deleted DESC
               LIMIT ?""",
            (user_id, threshold, limit),
        )
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def dismiss(
    user_id: str,
    target: str,
    target_type: str = "address",
    kind: str = "block",
) -> None:
    target = (target or "").strip().lower()
    if not target:
        return
    async with aiosqlite.connect(settings.db_path) as db:
        await db.execute(
            """INSERT OR IGNORE INTO suggestion_dismissals
               (user_id, target, target_type, suggestion_kind, dismissed_at)
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, target, target_type, kind, _now()),
        )
        await db.commit()
