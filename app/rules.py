"""Per-user sender allow/deny rules.

Four target types, evaluated in priority order (first match wins):

1. ``address``           — exact email-address match (case-insensitive).
2. ``domain``            — exact domain or any parent domain.
3. ``address_contains``  — case-insensitive substring of the email address.
                           Useful for addresses with stable substrings inside
                           rotating wrappers (e.g. iCloud forwarding aliases
                           that embed the original sender as
                           ``hello_at_mail_<sender>_com_<rotating>@icloud.com``).
4. ``subject_contains``  — case-insensitive substring of the subject. Catches
                           senders that rotate addresses but reuse subject
                           lines like "Tomorrow's Menu on …".

Within each tier a deny overrides an allow only if both happen to share the
same target — but in practice each (target_type, target) pair carries one
verdict. Tier-1 (exact address) overrides tier-2 (domain) by virtue of order.
"""

_VALID_TARGET_TYPES = frozenset({
    "address", "domain", "address_contains", "subject_contains",
})

from datetime import datetime, timezone

import aiosqlite

from .config import settings


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _split_address(address: str) -> tuple[str, str | None]:
    addr = (address or "").strip().lower()
    if "@" not in addr:
        return addr, None
    return addr, addr.split("@", 1)[-1]


async def list_rules(user_id: str) -> list[dict]:
    async with aiosqlite.connect(settings.db_path) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM sender_rules WHERE user_id = ? ORDER BY target_type, target",
            (user_id,),
        )
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def load_rule_index(user_id: str) -> dict[tuple[str, str], str]:
    """Return {(target_type, target): verdict} for fast lookup."""
    rules = await list_rules(user_id)
    return {(r["target_type"], r["target"]): r["verdict"] for r in rules}


async def upsert_rule(
    user_id: str, target: str, target_type: str, verdict: str
) -> None:
    if target_type not in _VALID_TARGET_TYPES:
        raise ValueError(f"invalid target_type: {target_type}")
    if verdict not in {"allow", "deny"}:
        raise ValueError(f"invalid verdict: {verdict}")
    target_norm = target.strip().lower()
    if not target_norm:
        raise ValueError("target cannot be empty")
    async with aiosqlite.connect(settings.db_path) as db:
        await db.execute(
            """INSERT INTO sender_rules (user_id, target, target_type, verdict, created_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(user_id, target, target_type) DO UPDATE SET
                 verdict = excluded.verdict""",
            (user_id, target_norm, target_type, verdict, _now()),
        )
        await db.commit()


async def delete_rule(user_id: str, target: str, target_type: str) -> None:
    async with aiosqlite.connect(settings.db_path) as db:
        await db.execute(
            "DELETE FROM sender_rules WHERE user_id = ? AND target = ? AND target_type = ?",
            (user_id, target.strip().lower(), target_type),
        )
        await db.commit()


def lookup(
    rules: dict[tuple[str, str], str],
    address: str | None,
    subject: str | None = None,
) -> str | None:
    """Return 'allow' / 'deny' / None for a message based on its sender
    address and (optionally) subject. Tiers evaluated in priority order:
    exact address → exact domain → address substring → subject substring.
    """
    addr_lower = (address or "").strip().lower()

    # Tier 1 — exact address.
    if addr_lower:
        v = rules.get(("address", addr_lower))
        if v:
            return v

    # Tier 2 — exact domain (and any parent domain).
    if addr_lower and "@" in addr_lower:
        domain = addr_lower.split("@", 1)[-1]
        if domain:
            parts = domain.split(".")
            for i in range(len(parts)):
                v = rules.get(("domain", ".".join(parts[i:])))
                if v:
                    return v

    # Tier 3 — address substring (catches rotating-suffix wrappers).
    if addr_lower:
        for (tt, t), verdict in rules.items():
            if tt == "address_contains" and t in addr_lower:
                return verdict

    # Tier 4 — subject substring (catches rotating-sender campaigns).
    subj_lower = (subject or "").strip().lower()
    if subj_lower:
        for (tt, t), verdict in rules.items():
            if tt == "subject_contains" and t in subj_lower:
                return verdict

    return None
