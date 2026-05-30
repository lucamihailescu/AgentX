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


# Shared / freemail / per-recipient relay domains: every user has unrelated
# senders here, so a domain block would catch far more than intended. These
# are never offered for address-rule collapse (e.g. blocking three iCloud
# Hide-My-Email aliases must NOT suggest blocking all of icloud.com).
_PUBLIC_EMAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "ymail.com", "yahoo.co.uk",
    "icloud.com", "me.com", "mac.com", "privaterelay.appleid.com",
    "aol.com", "proton.me", "protonmail.com", "pm.me",
    "gmx.com", "gmx.net", "mail.com", "zoho.com", "fastmail.com",
    "hey.com", "yandex.com", "qq.com", "163.com",
})


async def list_rule_optimizations(
    user_id: str,
    *,
    threshold: int | None = None,
) -> list[dict]:
    """Suggest collapsing many address-level deny rules into one domain rule.

    When `threshold`+ distinct `address`/`deny` rules share the same domain
    (e.g. 1@foo.com, 2@foo.com, 3@foo.com), surface foo.com as a collapse
    candidate. Skips public/freemail/relay domains, domains that already have
    any `domain` rule (an existing deny is handled by `list_redundant_rules`;
    an existing allow would be clobbered), and dismissed domains.
    """
    threshold = (
        threshold if threshold is not None else settings.optimize_rules_threshold
    )
    async with aiosqlite.connect(settings.db_path) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """SELECT target FROM sender_rules
               WHERE user_id = ? AND target_type = 'address' AND verdict = 'deny'
                 AND target LIKE '%@%'""",
            (user_id,),
        )
        addresses = [r["target"] for r in await cur.fetchall()]
        cur = await db.execute(
            """SELECT target, verdict FROM sender_rules
               WHERE user_id = ? AND target_type = 'domain'""",
            (user_id,),
        )
        domain_verdicts = {r["target"]: r["verdict"] for r in await cur.fetchall()}
        cur = await db.execute(
            """SELECT target FROM suggestion_dismissals
               WHERE user_id = ? AND target_type = 'domain'
                 AND suggestion_kind = 'optimize'""",
            (user_id,),
        )
        dismissed = {r["target"] for r in await cur.fetchall()}

    groups: dict[str, list[str]] = {}
    for addr in addresses:
        domain = addr.split("@", 1)[-1].strip().lower()
        if not domain or domain in _PUBLIC_EMAIL_DOMAINS:
            continue
        groups.setdefault(domain, []).append(addr)

    out: list[dict] = []
    for domain, addrs in groups.items():
        if len(addrs) < threshold:
            continue
        if domain in dismissed:
            continue
        if domain in domain_verdicts:
            continue  # a domain rule already exists (deny → redundancy; allow → conflict)
        out.append({
            "domain": domain,
            "addresses": sorted(addrs),
            "count": len(addrs),
        })
    out.sort(key=lambda g: g["count"], reverse=True)
    return out


def _most_specific_domain_rule(
    domain: str, domain_verdicts: dict[str, str]
) -> tuple[str, str] | None:
    """Return (matched_domain, verdict) of the most-specific domain rule on
    `domain`'s parent chain, mirroring lookup()'s tier-2 walk, or None."""
    parts = domain.split(".")
    for i in range(len(parts)):
        d = ".".join(parts[i:])
        if d in domain_verdicts:
            return d, domain_verdicts[d]
    return None


async def list_redundant_rules(user_id: str) -> list[dict]:
    """Group rules that are already covered by a broader, same-verdict rule.

    Removing a redundant rule never changes any classification outcome — the
    broader rule produces the same verdict. Only safe, outcome-preserving
    cases are surfaced:

      * an `address` rule whose most-specific matching `domain` rule has the
        same verdict (the domain rule already decides it);
      * a `domain` rule whose nearest parent `domain` rule has the same verdict.

    Differing-verdict pairs (e.g. `domain` allow + `address` deny) are
    intentional exceptions and are left untouched. Results are grouped by the
    covering rule; dismissed groups are excluded.
    """
    async with aiosqlite.connect(settings.db_path) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT target, target_type, verdict FROM sender_rules WHERE user_id = ?",
            (user_id,),
        )
        rules = [dict(r) for r in await cur.fetchall()]
        cur = await db.execute(
            """SELECT target, target_type FROM suggestion_dismissals
               WHERE user_id = ? AND suggestion_kind = 'redundant'""",
            (user_id,),
        )
        dismissed = {(r["target_type"], r["target"]) for r in await cur.fetchall()}

    domain_verdicts = {
        r["target"]: r["verdict"] for r in rules if r["target_type"] == "domain"
    }

    groups: dict[tuple[str, str], dict] = {}
    for r in rules:
        target, ttype, verdict = r["target"], r["target_type"], r["verdict"]
        cover: tuple[str, str, str] | None = None  # (type, target, verdict)

        if ttype == "address" and "@" in target:
            match = _most_specific_domain_rule(target.split("@", 1)[-1], domain_verdicts)
            if match and match[1] == verdict:
                cover = ("domain", match[0], verdict)
        elif ttype == "domain":
            parts = target.split(".")
            for i in range(1, len(parts)):  # strict parents only
                parent = ".".join(parts[i:])
                if parent in domain_verdicts:
                    if domain_verdicts[parent] == verdict:
                        cover = ("domain", parent, verdict)
                    break  # nearest parent decides; differing verdict = exception

        if cover is None:
            continue
        ctype, ctarget, cverdict = cover
        group = groups.setdefault(
            (ctype, ctarget),
            {
                "covered_by": {
                    "target": ctarget, "target_type": ctype, "verdict": cverdict
                },
                "rules": [],
            },
        )
        group["rules"].append({"target": target, "target_type": ttype})

    out: list[dict] = []
    for (ctype, ctarget), group in groups.items():
        if (ctype, ctarget) in dismissed:
            continue
        group["rules"].sort(key=lambda x: (x["target_type"], x["target"]))
        group["count"] = len(group["rules"])
        out.append(group)
    out.sort(key=lambda g: g["count"], reverse=True)
    return out


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
