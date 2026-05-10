"""Precomputed per-sender / per-domain aggregates.

Replaces the on-the-fly aggregation that used to scan every audit's
`result_data` JSON on each `/ui/senders` page load. The worker calls
``record_audit_completion`` once per finished audit; user-facing actions
(delete, unsubscribe, rule changes) call ``bump_action`` so post-audit
mutations stay visible.
"""

from __future__ import annotations

from datetime import datetime, timezone

import aiosqlite

from .config import settings


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _targets_for(sender: str) -> list[tuple[str, str]]:
    """Return the (target_type, target) pairs to update for a sender address.

    An address `foo@bar.com` updates both the address row and the domain row.
    """
    s = (sender or "").strip().lower()
    if not s:
        return []
    out: list[tuple[str, str]] = [("address", s)]
    if "@" in s:
        out.append(("domain", s.split("@", 1)[-1]))
    return out


_UPSERT_SQL = """
INSERT INTO sender_stats
    (user_id, target, target_type, seen, spam, deleted, unsubscribed,
     auto_deleted, last_seen, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(user_id, target_type, target) DO UPDATE SET
    seen          = sender_stats.seen          + excluded.seen,
    spam          = sender_stats.spam          + excluded.spam,
    deleted       = sender_stats.deleted       + excluded.deleted,
    unsubscribed  = sender_stats.unsubscribed  + excluded.unsubscribed,
    auto_deleted  = sender_stats.auto_deleted  + excluded.auto_deleted,
    last_seen     = CASE
        WHEN excluded.last_seen IS NOT NULL AND
             (sender_stats.last_seen IS NULL OR
              excluded.last_seen > sender_stats.last_seen)
        THEN excluded.last_seen
        ELSE sender_stats.last_seen
    END,
    updated_at    = excluded.updated_at
"""


async def record_audit_completion(user_id: str, report: dict) -> None:
    """Increment stats from a freshly-completed audit's report."""
    increments: dict[tuple[str, str], dict] = {}
    for m in report.get("messages", []):
        sender = (m.get("from") or "").strip().lower()
        if not sender:
            continue
        bump = {
            "seen": 1,
            "spam": 1 if m.get("spam") is True else 0,
            "deleted": 1 if m.get("deleted") else 0,
            "unsubscribed": 1 if m.get("unsubscribed") else 0,
            "auto_deleted": 1 if m.get("auto_deleted") else 0,
            "last_seen": m.get("received"),
        }
        for key in _targets_for(sender):
            cur = increments.setdefault(
                key,
                {"seen": 0, "spam": 0, "deleted": 0, "unsubscribed": 0,
                 "auto_deleted": 0, "last_seen": None},
            )
            for k in ("seen", "spam", "deleted", "unsubscribed", "auto_deleted"):
                cur[k] += bump[k]
            if bump["last_seen"] and (
                cur["last_seen"] is None or bump["last_seen"] > cur["last_seen"]
            ):
                cur["last_seen"] = bump["last_seen"]

    if not increments:
        return
    now = _now()
    async with aiosqlite.connect(settings.db_path) as db:
        for (target_type, target), s in increments.items():
            await db.execute(
                _UPSERT_SQL,
                (
                    user_id, target, target_type,
                    s["seen"], s["spam"], s["deleted"],
                    s["unsubscribed"], s["auto_deleted"],
                    s["last_seen"], now,
                ),
            )
        await db.commit()


async def bump_action(
    user_id: str,
    sender: str | None,
    *,
    deleted: int = 0,
    unsubscribed: int = 0,
) -> None:
    """Bump per-action counters (called from main.py on UI-driven actions).

    Uses the same UPSERT as `record_audit_completion` so the row gets created
    when this is the first time we see the sender (which can happen if the
    user runs a cleanup before any audit has aggregated them).
    """
    targets = _targets_for(sender or "")
    if not targets or (deleted == 0 and unsubscribed == 0):
        return
    now = _now()
    async with aiosqlite.connect(settings.db_path) as db:
        for target_type, target in targets:
            await db.execute(
                _UPSERT_SQL,
                (
                    user_id, target, target_type,
                    0,           # seen
                    0,           # spam
                    deleted,
                    unsubscribed,
                    0,           # auto_deleted
                    None,        # last_seen
                    now,
                ),
            )
        await db.commit()


async def list_top(
    user_id: str, target_type: str, *, limit: int = 100
) -> list[dict]:
    """Return the top-N sender or domain rows for the user, sorted by spam
    count then seen count."""
    async with aiosqlite.connect(settings.db_path) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """SELECT target, seen, spam, deleted, unsubscribed,
                      auto_deleted, last_seen
               FROM sender_stats
               WHERE user_id = ? AND target_type = ?
               ORDER BY spam DESC, auto_deleted DESC, seen DESC
               LIMIT ?""",
            (user_id, target_type, limit),
        )
        return [dict(r) for r in await cur.fetchall()]
