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


async def purge_mailbox(
    provider: type[MailboxProvider],
    user_id: str,
    rules: dict[tuple[str, str], str] | None,
    *,
    on_progress=None,
    on_page=None,
) -> dict:
    """Walk the entire mailbox in cursor-paginated batches and auto-delete
    every message that matches `BLOCKED_DOMAINS` or a `deny` rule.

    No Ollama, no per-message classification — this is the "I just want my
    rules applied to everything" pass. Calls `on_progress(snapshot)` after
    each page so the worker can stream incremental progress to the UI.
    """
    rules = rules or {}
    summary: dict = {
        "kind": "purge",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "pages_walked": 0,
        "messages_seen": 0,
        "messages_deleted": 0,
        "deleted_messages": [],
        "in_progress": True,
    }

    cursor: str | None = None
    last_cursor: object = object()  # sentinel

    while True:
        if cursor == last_cursor:
            # No progress (boundary collision on identical timestamps).
            break
        last_cursor = cursor

        messages = await fetch_messages(provider, user_id, cursor_before=cursor)
        if not messages:
            break

        summary["pages_walked"] += 1
        summary["messages_seen"] += len(messages)

        processed = await auto_delete(provider, user_id, messages, rules)
        for m in processed:
            if m.get("auto_deleted"):
                summary["messages_deleted"] += 1
                # Cap the captured list to keep result_data manageable for huge
                # mailboxes; the count is still authoritative.
                if len(summary["deleted_messages"]) < 1000:
                    summary["deleted_messages"].append({
                        "from": m.get("from"),
                        "subject": m.get("subject"),
                        "received": m.get("received"),
                        "rule_applied": m.get("rule_applied") or "blocklist",
                    })

        if on_page is not None:
            await on_page(processed)
        if on_progress is not None:
            await on_progress(summary)

        receiveds = [m["received"] for m in processed if m.get("received")]
        if not receiveds:
            break
        cursor = min(receiveds)

    summary["in_progress"] = False
    summary["finished_at"] = datetime.now(timezone.utc).isoformat()
    if on_progress is not None:
        await on_progress(summary)
    return summary


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
