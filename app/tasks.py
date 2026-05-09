import asyncio
import logging
from datetime import datetime, timezone
from urllib.parse import quote

import httpx

from .config import BLOCKED_DOMAINS, settings
from .graph_client import GraphClient, GraphError
from .ollama_client import classify
from .unsubscribe import find_unsubscribe

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


_GRAPH_PAGE_SIZE = 50  # Graph's preferred page size; we walk @odata.nextLink for more.


async def fetch_messages(
    graph: GraphClient,
    limit: int | None = None,
    cursor_before: str | None = None,
) -> list[dict]:
    """Fetch up to `limit` messages (default `settings.max_messages_per_audit`)
    by walking Microsoft Graph's `@odata.nextLink` pagination.

    If `cursor_before` (an ISO 8601 timestamp) is provided, only messages
    received strictly before that time are returned — the basis for the
    "Next page" flow that walks back through the mailbox in batches.
    """
    target = limit if limit is not None else settings.max_messages_per_audit
    page_size = min(_GRAPH_PAGE_SIZE, target)

    qs = [
        f"$top={page_size}",
        "$select=id,subject,from,receivedDateTime,bodyPreview,internetMessageHeaders",
        "$orderby=receivedDateTime desc",
    ]
    if cursor_before:
        qs.append(f"$filter={quote(f'receivedDateTime lt {cursor_before}')}")
    url: str | None = f"/me/messages?{'&'.join(qs)}"
    out: list[dict] = []

    while url and len(out) < target:
        resp = await graph.request("GET", url)
        body = resp.json()
        for m in body.get("value", []):
            unsub = find_unsubscribe(m.get("internetMessageHeaders") or [])
            out.append(
                {
                    "id": m.get("id"),
                    "subject": m.get("subject"),
                    "from": (m.get("from") or {}).get("emailAddress", {}).get("address"),
                    "received": m.get("receivedDateTime"),
                    "preview": m.get("bodyPreview"),
                    "unsubscribe_url": unsub["url"] if unsub else None,
                    "unsubscribe_one_click": unsub["one_click"] if unsub else False,
                }
            )
            if len(out) >= target:
                break
        url = body.get("@odata.nextLink") if len(out) < target else None

    return out


async def auto_delete_blocked(graph: GraphClient, messages: list[dict]) -> list[dict]:
    """Delete messages whose sender domain is in `settings.blocked_domains`.

    Failures are logged and the message stays in the list so it falls through
    to normal classification — better to surface a stale block-list match in
    the report than to fail the whole task.
    """
    if not BLOCKED_DOMAINS:
        return messages

    semaphore = asyncio.Semaphore(4)

    async def _maybe_delete(m: dict) -> dict:
        if not m.get("id") or not is_blocked(m.get("from"), BLOCKED_DOMAINS):
            return m
        async with semaphore:
            try:
                await graph.request("DELETE", f"/me/messages/{m['id']}")
            except GraphError as exc:
                logger.warning(
                    "auto-delete failed for %s (from=%s): %s", m["id"], m.get("from"), exc
                )
                return m
        return {
            **m,
            "auto_deleted": True,
            "auto_deleted_at": datetime.now(timezone.utc).isoformat(),
        }

    return await asyncio.gather(*(_maybe_delete(m) for m in messages))


async def classify_messages(messages: list[dict]) -> list[dict]:
    """Run each non-auto-deleted message through Ollama in parallel.

    Per-message failures degrade gracefully (spam=None, reason=...) so a
    flaky/unreachable Ollama doesn't fail the whole task.
    """
    semaphore = asyncio.Semaphore(settings.ollama_concurrency)
    async with httpx.AsyncClient(base_url=settings.ollama_url) as client:

        async def _one(message: dict) -> dict:
            if message.get("auto_deleted"):
                return message
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
