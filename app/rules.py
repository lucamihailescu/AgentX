"""Per-user sender allow/deny rules.

`address` rules match exact email addresses (case-insensitive).
`domain`  rules match the domain part and any subdomain.
Address rules take precedence over domain rules; a `deny` address overrides
an `allow` for its parent domain.
"""

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
    if target_type not in {"address", "domain"}:
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


def lookup(rules: dict[tuple[str, str], str], address: str | None) -> str | None:
    """Return 'allow' / 'deny' / None for the given sender address.

    Exact-address match wins over domain match.
    """
    if not address:
        return None
    addr, domain = _split_address(address)
    v = rules.get(("address", addr))
    if v:
        return v
    if domain:
        parts = domain.split(".")
        for i in range(len(parts)):
            v = rules.get(("domain", ".".join(parts[i:])))
            if v:
                return v
    return None
