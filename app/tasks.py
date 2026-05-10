import asyncio
import logging
from datetime import datetime, timezone

import httpx

from .config import BLOCKED_DOMAINS, settings
from .ollama_client import classify
from .providers import MailboxProvider
from .providers.base import AuthError
from .rules import lookup as lookup_rule

logger = logging.getLogger(__name__)


def is_blocked(address: str | None, blocked: frozenset[str] | set[str]) -> bool:
    """Match the address's domain (or any parent domain) against the blocklist."""
    if not address or "@" not in address or not blocked:
        return False
    domain = address.split("@", 1)[-1].strip().lower()
    if not domain:
        return False
    parts = domain.split(".")
    return any(".".join(parts[i:]) in blocked for i in range(len(parts)))


async def fetch_messages(
    provider: type[MailboxProvider],
    user_id: str,
    *,
    limit: int | None = None,
    cursor_before: str | None = None,
) -> list[dict]:
    target = limit if limit is not None else settings.max_messages_per_audit
    messages = await provider.fetch_messages(
        user_id, limit=target, cursor_before=cursor_before
    )
    return [m.to_dict() for m in messages]


async def auto_delete(
    provider: type[MailboxProvider],
    user_id: str,
    messages: list[dict],
    rules: dict[tuple[str, str], str] | None = None,
) -> list[dict]:
    """Delete messages whose sender is either in `BLOCKED_DOMAINS` or has a
    `deny` rule. Runs before classification, so the user's explicit "always
    block" choices are honored on every future audit (not just the click that
    created the rule).

    Per-message failures are logged and the message stays in the list so it
    falls through to normal classification — better to surface a stale match
    than to fail the whole task.
    """
    rules = rules or {}
    if not BLOCKED_DOMAINS and not rules:
        return messages

    semaphore = asyncio.Semaphore(4)

    async def _maybe_delete(m: dict) -> dict:
        if not m.get("id"):
            return m
        from_addr = m.get("from")
        if not from_addr:
            return m
        domain_blocked = is_blocked(from_addr, BLOCKED_DOMAINS)
        rule_denied = lookup_rule(rules, from_addr) == "deny"
        if not (domain_blocked or rule_denied):
            return m
        async with semaphore:
            try:
                await provider.delete_message(user_id, m["id"])
            except AuthError as exc:
                logger.warning(
                    "auto-delete failed for %s (from=%s, source=%s): %s",
                    m["id"],
                    from_addr,
                    "rule" if rule_denied else "blocklist",
                    exc,
                )
                return m
        out = {
            **m,
            "auto_deleted": True,
            "auto_deleted_at": datetime.now(timezone.utc).isoformat(),
        }
        if rule_denied:
            out["rule_applied"] = "deny"
            out["reason"] = "denylisted sender"
        return out

    return await asyncio.gather(*(_maybe_delete(m) for m in messages))


async def classify_messages(
    messages: list[dict],
    rules: dict[tuple[str, str], str] | None = None,
) -> list[dict]:
    rules = rules or {}
    semaphore = asyncio.Semaphore(settings.ollama_concurrency)
    async with httpx.AsyncClient(base_url=settings.ollama_url) as client:

        async def _one(message: dict) -> dict:
            if message.get("auto_deleted"):
                return message
            ruled = lookup_rule(rules, message.get("from"))
            if ruled == "allow":
                return {
                    **message,
                    "spam": False,
                    "confidence": 1.0,
                    "reason": "allowlisted sender",
                    "rule_applied": "allow",
                }
            if ruled == "deny":
                return {
                    **message,
                    "spam": True,
                    "confidence": 1.0,
                    "reason": "denylisted sender",
                    "rule_applied": "deny",
                }
            async with semaphore:
                verdict = await classify(client, message)
            return {**message, **verdict}

        return await asyncio.gather(*(_one(m) for m in messages))


async def generate_report(classified: list[dict]) -> dict:
    spam_count = sum(1 for m in classified if m.get("spam") is True)
    auto_deleted_count = sum(1 for m in classified if m.get("auto_deleted"))
    unknown_count = sum(
        1
        for m in classified
        if m.get("spam") is None and not m.get("auto_deleted")
    )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "message_count": len(classified),
        "spam_count": spam_count,
        "auto_deleted_count": auto_deleted_count,
        "unknown_count": unknown_count,
        "messages": classified,
    }
