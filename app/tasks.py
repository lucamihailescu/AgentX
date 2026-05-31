import asyncio
import logging
from datetime import datetime, timezone

import httpx

from . import calibration
from . import phishing
from . import rspamd_client
from .categories import category_label, needs_reply_label, phishing_label
from .config import BLOCKED_DOMAINS, settings
from .ollama_client import classify
from .providers import MailboxProvider
from .providers.base import AuthError
from .rules import lookup as lookup_rule

# Transient mailbox plumbing carried on each message dict for the
# categorization / phishing passes, but not worth persisting on the report.
_TRANSIENT_FIELDS = ("categories", "from_header", "auth_headers")

logger = logging.getLogger(__name__)

# Confidence below this triggers a lazy-escalation Rspamd recheck against
# the full raw MIME (fetched from the provider) instead of the synthesized
# envelope. Rough rule: anything where blended p_spam ∈ [0.30, 0.70].
_ESCALATION_CONFIDENCE = 0.70


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
        rule_denied = lookup_rule(rules, from_addr, m.get("subject")) == "deny"
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
        # Strong "spam" signal — train Rspamd's per-user Bayes on it.
        rspamd_client.fire_learn(out, user_id, "spam")
        return out

    return await asyncio.gather(*(_maybe_delete(m) for m in messages))


async def classify_messages(
    messages: list[dict],
    rules: dict[tuple[str, str], str] | None = None,
    examples: tuple[list[dict], list[dict]] | None = None,
    priors: dict[str, dict] | None = None,
    user_id: str | None = None,
    provider: type[MailboxProvider] | None = None,
) -> list[dict]:
    """Run each non-auto-deleted message through Ollama (and optionally
    Rspamd) in parallel, then blend the verdicts with the per-sender prior.

    Signals combined per message (see `calibration.blend`):
      - Ollama: textual LLM verdict, with few-shot examples for taste.
      - Rspamd: email-tuned heuristics + per-user Bayes, when configured.
      - Per-sender prior: accumulated delete/unsub actions from sender_stats.

    When `provider` is given and a message's blended confidence is below
    `_ESCALATION_CONFIDENCE`, the raw RFC 822 is fetched and Rspamd is
    re-run — recovering the URL / DKIM / attachment signal that the
    synthesized envelope misses. The escalation re-blends with the same
    Ollama verdict + prior; only the Rspamd input changes.

    Each Ollama + Rspamd pair runs concurrently for a single message;
    cross-message parallelism is bounded by `ollama_concurrency`.
    """
    rules = rules or {}
    priors = priors or {}
    ham_examples, spam_examples = examples or ([], [])
    semaphore = asyncio.Semaphore(settings.ollama_concurrency)
    rspamd_on = rspamd_client.is_enabled() and user_id is not None
    escalation_on = rspamd_on and provider is not None
    escalations = 0
    async with httpx.AsyncClient(base_url=settings.ollama_url) as client:

        async def _one(message: dict) -> dict:
            nonlocal escalations
            if message.get("auto_deleted"):
                return message
            ruled = lookup_rule(rules, message.get("from"), message.get("subject"))
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
                ollama_coro = classify(
                    client,
                    message,
                    ham_examples=ham_examples,
                    spam_examples=spam_examples,
                )
                if rspamd_on:
                    ollama_verdict, rspamd_verdict = await asyncio.gather(
                        ollama_coro,
                        rspamd_client.check(message, user_id),
                    )
                else:
                    ollama_verdict = await ollama_coro
                    rspamd_verdict = None
            sender = (message.get("from") or "").strip().lower()
            prior = priors.get(sender) if sender else None
            blended = calibration.blend(
                ollama_verdict, rspamd=rspamd_verdict, prior=prior
            )

            # Lazy escalation: borderline blended verdict → fetch the
            # raw MIME and re-run Rspamd on it. Skips messages we already
            # short-circuited (rule/auto_deleted), and skips when there's
            # no provider to fetch from.
            if (
                escalation_on
                and message.get("id")
                and (blended.get("confidence") or 1.0) < _ESCALATION_CONFIDENCE
            ):
                raw = None
                async with semaphore:
                    try:
                        raw = await provider.fetch_raw(user_id, message["id"])
                    except Exception as exc:
                        logger.warning(
                            "rspamd-escalation fetch_raw failed for %s: %s",
                            message["id"], exc,
                        )
                if raw:
                    rspamd_raw = await rspamd_client.check_raw(
                        raw, message, user_id
                    )
                    if rspamd_raw is not None:
                        blended = calibration.blend(
                            ollama_verdict, rspamd=rspamd_raw, prior=prior
                        )
                        blended["rspamd_escalated"] = True
                        escalations += 1
            return {**message, **blended}

        result = await asyncio.gather(*(_one(m) for m in messages))
        if escalation_on and escalations:
            logger.info(
                "rspamd lazy-escalation: re-checked %d borderline message(s) with raw MIME",
                escalations,
            )
        return result


async def apply_categories(
    provider: type[MailboxProvider],
    user_id: str,
    messages: list[dict],
) -> int:
    """Write each classified message's category (a needs-reply marker, and a
    phishing marker) back to the mailbox as an Outlook category / Gmail label.

    Best-effort and idempotent: skips auto-deleted messages, runs
    bounded-concurrent, and logs (never raises) per-message failures so a
    single label write can't fail the audit. Sets `category_applied` on each
    message it successfully labels.
    """
    if not settings.apply_labels_enabled:
        return 0
    semaphore = asyncio.Semaphore(4)
    applied = 0

    async def _one(m: dict) -> None:
        nonlocal applied
        if not m.get("id") or m.get("auto_deleted"):
            return
        labels: list[str] = []
        # Category labels only for messages that went through the classifier
        # (rule-short-circuited rows carry no category).
        category = m.get("category")
        if category and not m.get("rule_applied"):
            labels.append(category_label(category))
            if m.get("needs_reply"):
                labels.append(needs_reply_label())
        # Phishing label applies regardless of rule/spam verdict.
        if m.get("phishing"):
            labels.append(phishing_label())
        if not labels:
            return
        async with semaphore:
            try:
                await provider.apply_labels(
                    user_id,
                    m["id"],
                    labels,
                    existing_categories=m.get("categories"),
                )
                m["category_applied"] = True
                applied += 1
            except Exception as exc:  # best-effort; never fail the audit
                logger.warning(
                    "apply_labels failed for %s (labels=%s): %s",
                    m["id"], labels, exc,
                )

    await asyncio.gather(*(_one(m) for m in messages))
    if applied:
        logger.info("categorization: labeled %d message(s)", applied)
    return applied


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


async def run_pipeline(
    provider: type[MailboxProvider],
    user_id: str,
    messages: list[dict],
    *,
    rules: dict[tuple[str, str], str],
    examples: tuple[list[dict], list[dict]],
    priors: dict[str, dict],
) -> dict:
    """The full per-message treatment shared by scheduled audits and
    real-time scans: auto-delete blocked senders, classify (+ categorize +
    extract actions), flag phishing, write category/phishing labels back, and
    build the report dict. Callers supply the already-loaded rules / few-shot
    examples / priors so they're fetched once per run."""
    messages = await auto_delete(provider, user_id, messages, rules)
    classified = await classify_messages(
        messages,
        rules,
        examples=examples,
        priors=priors,
        user_id=user_id,
        provider=provider,
    )
    # Flag phishing/BEC from header metadata (must run before generate_report
    # strips the raw headers it reads).
    phishing.flag_messages(classified)
    # Write categories + phishing marker back to the mailbox before building
    # the report, which also strips the transient label plumbing.
    await apply_categories(provider, user_id, classified)
    return await generate_report(classified)


async def fetch_new_messages(
    provider: type[MailboxProvider],
    user_id: str,
    *,
    cursor: str | None,
    limit: int,
) -> tuple[list[dict], str | None]:
    """Poll for newly-arrived mail. Fetch the newest `limit` headers and return
    ``(new_messages, new_cursor)``.

    `cursor` is an ISO received-timestamp watermark; only messages strictly
    newer are returned. `new_cursor` is the newest received seen this poll.
    When `cursor` is None this is a *baseline* call — returns ``([], newest)``
    so only mail arriving AFTER polling was enabled gets scanned (no backfill
    storm on first enable).
    """
    recent = await fetch_messages(provider, user_id, limit=limit)
    receiveds = [m["received"] for m in recent if m.get("received")]
    newest = max(receiveds) if receiveds else cursor
    if cursor is None:
        return [], newest
    new = [m for m in recent if m.get("received") and m["received"] > cursor]
    return new, (newest or cursor)


async def generate_report(classified: list[dict]) -> dict:
    spam_count = sum(1 for m in classified if m.get("spam") is True)
    auto_deleted_count = sum(1 for m in classified if m.get("auto_deleted"))
    unknown_count = sum(
        1
        for m in classified
        if m.get("spam") is None and not m.get("auto_deleted")
    )

    # Category breakdown over messages that survived to classification (not
    # auto-deleted) and actually got a category.
    category_counts: dict[str, int] = {}
    needs_reply_count = 0
    phishing_count = 0
    for m in classified:
        if not m.get("auto_deleted"):
            cat = m.get("category")
            if cat:
                category_counts[cat] = category_counts.get(cat, 0) + 1
            if m.get("needs_reply"):
                needs_reply_count += 1
            if m.get("phishing"):
                phishing_count += 1
        # Drop transient mailbox plumbing before persisting the report.
        for field in _TRANSIENT_FIELDS:
            m.pop(field, None)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "message_count": len(classified),
        "spam_count": spam_count,
        "auto_deleted_count": auto_deleted_count,
        "unknown_count": unknown_count,
        "category_counts": category_counts,
        "needs_reply_count": needs_reply_count,
        "phishing_count": phishing_count,
        "messages": classified,
    }
