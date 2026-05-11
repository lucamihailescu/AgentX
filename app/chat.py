"""Chat interface for agentx — Ollama LLM + mem0 (Qdrant + Ollama embeddings).

Design:
- mem0 is loaded lazily on first use; failure is logged and degrades to a
  stateless chatbot (no persistent memory across sessions, but everything
  else still works).
- Each chat turn pulls (a) recent inbox-state context from SQLite and
  (b) up to N relevant memories from mem0, then asks Ollama.
- Memory updates run in the background after the reply is sent — keeps the
  user-perceived response fast.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

import aiosqlite
import httpx

from . import rules as rules_module
from . import sender_stats
from .config import settings

logger = logging.getLogger(__name__)

# mem0 instance + a single asyncio.Lock guarding lazy init.
_memory: Any = None
_memory_init_lock = asyncio.Lock()
_memory_unavailable = False  # sticky flag so we stop retrying after a hard failure


def _effective_chat_model() -> str:
    return settings.chat_model or settings.ollama_model


def _build_mem0_config() -> dict:
    return {
        "llm": {
            "provider": "ollama",
            "config": {
                "model": _effective_chat_model(),
                "ollama_base_url": settings.ollama_url,
                "temperature": 0.2,
            },
        },
        "embedder": {
            "provider": "ollama",
            "config": {
                "model": settings.embed_model,
                "ollama_base_url": settings.ollama_url,
            },
        },
        "vector_store": {
            "provider": "qdrant",
            "config": {
                "collection_name": "agentx_memories",
                "host": settings.qdrant_host,
                "port": settings.qdrant_port,
                "embedding_model_dims": settings.embed_dims,
            },
        },
    }


async def _get_memory():
    """Lazy mem0 init. Returns None on failure (caller treats as no memory)."""
    global _memory, _memory_unavailable
    if _memory is not None:
        return _memory
    if _memory_unavailable:
        return None
    async with _memory_init_lock:
        if _memory is not None:
            return _memory
        if _memory_unavailable:
            return None
        try:
            # mem0's Memory.from_config is sync and can do network I/O
            # (creating the Qdrant collection); push to a thread.
            from mem0 import Memory  # noqa: PLC0415 — defer import cost
            _memory = await asyncio.to_thread(Memory.from_config, _build_mem0_config())
            logger.info("mem0 initialized (qdrant=%s:%d)",
                        settings.qdrant_host, settings.qdrant_port)
        except Exception as exc:
            logger.warning(
                "mem0 init failed (%s); chat will run without persistent memory",
                exc,
            )
            _memory_unavailable = True
            return None
        return _memory


async def search_memories(user_id: str, query: str) -> list[str]:
    mem = await _get_memory()
    if mem is None:
        return []
    try:
        result = await asyncio.to_thread(
            mem.search, query=query, user_id=user_id, limit=settings.chat_memory_top_k
        )
    except Exception as exc:
        logger.warning("mem0 search failed: %s", exc)
        return []
    # mem0 returns either a dict {"results": [...]} or a list, depending on
    # version. Normalize.
    items = result.get("results", result) if isinstance(result, dict) else result
    out: list[str] = []
    for it in items or []:
        text = it.get("memory") if isinstance(it, dict) else None
        if text:
            out.append(text)
    return out


async def remember(user_id: str, user_msg: str, assistant_msg: str) -> None:
    """Background-update mem0 with this conversation turn. Failures are logged."""
    mem = await _get_memory()
    if mem is None:
        return
    messages = [
        {"role": "user", "content": user_msg},
        {"role": "assistant", "content": assistant_msg},
    ]
    try:
        await asyncio.to_thread(mem.add, messages, user_id=user_id)
    except Exception as exc:
        logger.warning("mem0 add failed: %s", exc)


async def _load_inbox_context(user_id: str) -> str:
    """Build a short, factual snapshot of the user's mailbox state to prepend
    as system context. Pure SQLite reads — no LLM cost. Recent audits are
    listed with their full UUID in `[audit:<uuid>]` form so the model can
    cite them inline (the UI renders citations as clickable links)."""
    import json
    parts: list[str] = []
    async with aiosqlite.connect(settings.db_path) as db:
        db.row_factory = aiosqlite.Row
        # Up to 5 recent completed audits — gives the model a small palette
        # of audits it can cite by UUID.
        cur = await db.execute(
            """SELECT task_id, created_at, result_data FROM tasks
               WHERE user_id = ? AND status = 'completed'
                 AND result_data IS NOT NULL
               ORDER BY created_at DESC LIMIT 5""",
            (user_id,),
        )
        recent = await cur.fetchall()
        if recent:
            parts.append("Recent audits (cite as [audit:<uuid>]):")
            for row in recent:
                try:
                    data = json.loads(row["result_data"])
                except json.JSONDecodeError:
                    continue
                parts.append(
                    f"  - {row['created_at']} [audit:{row['task_id']}] — "
                    f"scanned {data.get('message_count', 0)}, "
                    f"spam {data.get('spam_count', 0)}, "
                    f"auto-deleted {data.get('auto_deleted_count', 0)}"
                )

        cur = await db.execute(
            "SELECT verdict, COUNT(*) AS n FROM sender_rules "
            "WHERE user_id = ? GROUP BY verdict",
            (user_id,),
        )
        for row in await cur.fetchall():
            parts.append(f"{row['n']} {row['verdict']} rule(s) configured.")

    top = await sender_stats.list_top(user_id, "address", limit=5)
    if top:
        parts.append("Top senders by spam count:")
        for s in top:
            if s["spam"] > 0 or s["auto_deleted"] > 0:
                parts.append(
                    f"  - {s['target']}: seen={s['seen']}, "
                    f"spam={s['spam']}, auto-del={s['auto_deleted']}"
                )

    return "\n".join(parts) if parts else "No audits run yet."


_SYSTEM_PROMPT = (
    "You are agentx, a helpful personal assistant for the user's email inbox. "
    "You have access to: a snapshot of inbox state (including IDs of recent "
    "audits), a list of relevant past memories about the user, and the "
    "recent conversation. Answer concisely and factually. Only reference "
    "data shown to you — never invent message counts, sender names, rules, "
    "or memories. If you don't have the data to answer a question, say so "
    "and suggest what the user could check instead.\n\n"
    "When you reference a specific audit, cite it inline as `[audit:<uuid>]` "
    "using the full UUID from the inbox snapshot. The UI will render this as "
    "a clickable link to the audit's page. Example: \"Your most recent audit "
    "[audit:a7e24585-fbeb-40fa-87df-cea87a0b5f07] flagged 12 spam messages.\""
)


def _build_chat_messages(
    inbox_context: str,
    memories: list[str],
    history: list[dict],
    user_message: str,
) -> list[dict]:
    sys_parts = [_SYSTEM_PROMPT, "\n\nInbox snapshot:\n", inbox_context]
    if memories:
        sys_parts.append("\n\nRelevant memories about the user:")
        for m in memories:
            sys_parts.append(f"\n  - {m}")
    return (
        [{"role": "system", "content": "".join(sys_parts)}]
        + history
        + [{"role": "user", "content": user_message}]
    )


class OllamaChatError(Exception):
    pass


async def _call_ollama_chat(messages: list[dict]) -> str:
    model = _effective_chat_model()
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": 0.2,
            "num_ctx": 4096,
            "num_predict": 600,
        },
    }
    async with httpx.AsyncClient(base_url=settings.ollama_url, timeout=60.0) as client:
        try:
            resp = await client.post("/api/chat", json=payload)
        except httpx.HTTPError as exc:
            raise OllamaChatError(
                f"can't reach Ollama at {settings.ollama_url}: {exc}"
            ) from exc

    if resp.status_code == 404:
        # Ollama returns 404 from /api/chat when the model isn't installed.
        # Surface that as actionable, not as a raw URL.
        raise OllamaChatError(
            f"Ollama doesn't have the chat model `{model}`. "
            f"Run `ollama pull {model}` on the host serving "
            f"{settings.ollama_url} and try again."
        )
    if resp.status_code >= 400:
        raise OllamaChatError(
            f"Ollama /api/chat returned {resp.status_code}: {resp.text[:300]}"
        )
    body = resp.json()
    return ((body.get("message") or {}).get("content") or "").strip()


async def chat(user_id: str, history: list[dict], user_message: str) -> str:
    """Synchronously produce an assistant reply for a user turn.

    `history` is the prior conversation — list of {"role", "content"} dicts.
    """
    inbox_context, memories = await asyncio.gather(
        _load_inbox_context(user_id),
        search_memories(user_id, user_message),
    )
    messages = _build_chat_messages(
        inbox_context, memories, history, user_message
    )
    return await _call_ollama_chat(messages)


# ─────────────────────────── tool calling ───────────────────────────
# Wired with Ollama's /api/chat tools support. Note: tool calls require
# stream=False, so we lose token-by-token streaming for the LLM reply
# itself. We make up for it by streaming the agent loop's *progress*
# (one line per tool call) so the user sees what's happening.

_MAX_TOOL_ITERATIONS = 5

_TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "start_audit",
            "description": (
                "Start a new mailbox audit covering the most recent N "
                "messages. Each message is classified via Ollama and rules "
                "are applied. Returns the new audit's UUID, which can be "
                "cited as [audit:<uuid>]."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_cleanup",
            "description": (
                "Walk the entire mailbox and auto-delete every message that "
                "matches a blocked domain or a deny rule. Does NOT run "
                "Ollama classification. Use this when the user wants to "
                "purge known-bad senders without going through audits."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "next_page",
            "description": (
                "Continue an existing audit by generating a follow-up audit "
                "covering older messages. The cursor is set to the parent's "
                "oldest message timestamp."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "parent_audit_uuid": {
                        "type": "string",
                        "description": (
                            "Full UUID of the parent audit to continue. "
                            "Use a value from the inbox snapshot."
                        ),
                    },
                },
                "required": ["parent_audit_uuid"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_rule",
            "description": (
                "Add a per-user sender rule. Verdict 'deny' auto-deletes "
                "matching mail on every future audit; 'allow' marks it as "
                "ok and skips classification. target_type 'address' is an "
                "exact email match; 'domain' matches a domain plus its "
                "subdomains; 'address_contains' is a case-insensitive "
                "substring of the email address; 'subject_contains' is a "
                "substring of the subject line."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The string to match against.",
                    },
                    "target_type": {
                        "type": "string",
                        "enum": [
                            "address", "domain",
                            "address_contains", "subject_contains",
                        ],
                    },
                    "verdict": {
                        "type": "string",
                        "enum": ["allow", "deny"],
                    },
                },
                "required": ["target", "target_type", "verdict"],
            },
        },
    },
]


# ── tool implementations ──────────────────────────────────────────────
async def _insert_task_row(
    user_id: str, kind: str, cursor_before: str | None = None
) -> str:
    task_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(settings.db_path) as db:
        await db.execute(
            """INSERT INTO tasks
               (task_id, user_id, kind, status, cursor_before, created_at, updated_at)
               VALUES (?, ?, ?, 'queued', ?, ?, ?)""",
            (task_id, user_id, kind, cursor_before, now, now),
        )
        await db.commit()
    return task_id


async def _tool_start_audit(user_id: str, args: dict) -> dict:
    task_id = await _insert_task_row(user_id, "audit")
    return {"ok": True, "task_id": task_id, "kind": "audit", "status": "queued"}


async def _tool_run_cleanup(user_id: str, args: dict) -> dict:
    task_id = await _insert_task_row(user_id, "purge")
    return {"ok": True, "task_id": task_id, "kind": "purge", "status": "queued"}


async def _tool_next_page(user_id: str, args: dict) -> dict:
    parent_uuid = (args.get("parent_audit_uuid") or "").strip()
    if not parent_uuid:
        return {"ok": False, "error": "parent_audit_uuid required"}
    async with aiosqlite.connect(settings.db_path) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT user_id, result_data FROM tasks WHERE task_id = ?",
            (parent_uuid,),
        )
        row = await cur.fetchone()
    if not row or row["user_id"] != user_id:
        return {"ok": False, "error": f"audit {parent_uuid} not found"}
    if not row["result_data"]:
        return {"ok": False, "error": "parent audit has no result yet"}
    try:
        data = json.loads(row["result_data"])
    except json.JSONDecodeError:
        return {"ok": False, "error": "parent audit data unreadable"}
    received = [
        m["received"] for m in data.get("messages", []) if m.get("received")
    ]
    if not received:
        return {"ok": False, "error": "parent audit has no message timestamps"}
    cursor = min(received)
    new_id = await _insert_task_row(user_id, "audit", cursor_before=cursor)
    return {
        "ok": True, "task_id": new_id, "kind": "audit",
        "cursor_before": cursor, "status": "queued",
    }


async def _tool_add_rule(user_id: str, args: dict) -> dict:
    target = (args.get("target") or "").strip().lower()
    target_type = args.get("target_type") or "address"
    verdict = args.get("verdict") or "deny"
    if not target:
        return {"ok": False, "error": "target is required"}
    try:
        await rules_module.upsert_rule(user_id, target, target_type, verdict)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    return {
        "ok": True,
        "message": f"Added {verdict} rule on {target_type}: {target}",
    }


_TOOL_DISPATCH = {
    "start_audit": _tool_start_audit,
    "run_cleanup": _tool_run_cleanup,
    "next_page": _tool_next_page,
    "add_rule": _tool_add_rule,
}


_WORD_RE = re.compile(r"[a-z0-9]+")


def _word_set(s: str) -> set[str]:
    return set(_WORD_RE.findall(s.lower()))


def _extract_tool_call_from_text(content: str) -> tuple[str, dict] | None:
    """Recover a tool call from the model's `content` when `tool_calls` is
    empty.

    Some models (Gemma, older Llama, anything not trained on Ollama's tool
    protocol) emit the tool call as a JSON string in the content field
    instead of via the structured `tool_calls` array. We try to parse that,
    fuzzy-match the claimed `name` (often the description, not the function
    name) back to a registered tool, and execute it.

    Returns (resolved_function_name, arguments) or None if no recovery
    is possible. Best-effort — the user is warned to switch models when
    this fires, since parameterized tools may have hallucinated args.
    """
    if not content:
        return None
    text = content.strip()
    # Strip ```json fences if present
    if text.startswith("```"):
        first_nl = text.find("\n")
        if first_nl > 0:
            text = text[first_nl + 1:]
        if text.endswith("```"):
            text = text[: -3]
        text = text.strip()
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None

    claimed_name = obj.get("name") or obj.get("tool") or obj.get("function")
    if not isinstance(claimed_name, str) or not claimed_name.strip():
        return None
    args = obj.get("parameters") or obj.get("arguments") or {}
    if not isinstance(args, dict):
        args = {}

    # Resolve to a registered tool — exact, then by description-word subset.
    if claimed_name in _TOOL_DISPATCH:
        return claimed_name, args
    claim_words = _word_set(claimed_name)
    for tool in _TOOLS:
        fn = tool["function"]
        tool_name = fn["name"]
        tool_words = set(tool_name.split("_"))
        # Tool name's component words must all appear in the claimed name.
        if tool_words.issubset(claim_words):
            return tool_name, args
    return None


async def _execute_tool(user_id: str, name: str, arguments: dict) -> dict:
    fn = _TOOL_DISPATCH.get(name)
    if fn is None:
        return {"ok": False, "error": f"unknown tool: {name}"}
    try:
        return await fn(user_id, arguments or {})
    except Exception as exc:
        logger.exception("tool %s failed", name)
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


async def _call_ollama_chat_with_tools(messages: list[dict]) -> dict:
    """Single non-streaming call to Ollama with the tool schema attached.
    Returns the parsed JSON response (caller inspects message.tool_calls)."""
    model = _effective_chat_model()
    payload = {
        "model": model,
        "messages": messages,
        "tools": _TOOLS,
        "stream": False,
        "options": {
            "temperature": 0.2,
            "num_ctx": 8192,
            "num_predict": 600,
        },
    }
    async with httpx.AsyncClient(base_url=settings.ollama_url, timeout=120.0) as client:
        try:
            resp = await client.post("/api/chat", json=payload)
        except httpx.HTTPError as exc:
            raise OllamaChatError(
                f"can't reach Ollama at {settings.ollama_url}: {exc}"
            ) from exc
    if resp.status_code == 404:
        raise OllamaChatError(
            f"Ollama doesn't have the chat model `{model}`. "
            f"Run `ollama pull {model}` on the host serving "
            f"{settings.ollama_url} and try again."
        )
    if resp.status_code >= 400:
        raise OllamaChatError(
            f"Ollama /api/chat returned {resp.status_code}: {resp.text[:300]}"
        )
    return resp.json()


async def chat_with_tools(
    user_id: str, history: list[dict], user_message: str
) -> str:
    """Blocking variant of the agent loop — used by the no-JS form fallback.
    Returns the final assistant text (tool progress is dropped)."""
    chunks: list[str] = []
    async for fragment in chat_with_tools_stream(user_id, history, user_message):
        chunks.append(fragment)
    return "".join(chunks).strip()


async def chat_with_tools_stream(
    user_id: str, history: list[dict], user_message: str
):
    """Tool-using agent loop. Streams *progress lines* per tool call, then
    yields the final assistant content as one chunk.

    Why progress lines: Ollama's tools require stream=False, so we can't
    stream the LLM's words — but the user can still see what the agent is
    *doing* (each tool call → result) as it happens, which is more useful
    information than token-by-token text would be for action-driven chat.
    """
    inbox_context, memories = await asyncio.gather(
        _load_inbox_context(user_id),
        search_memories(user_id, user_message),
    )
    messages = _build_chat_messages(
        inbox_context, memories, history, user_message
    )

    for iteration in range(_MAX_TOOL_ITERATIONS):
        try:
            response = await _call_ollama_chat_with_tools(messages)
        except OllamaChatError as exc:
            yield f"\n\n⚠ {exc}"
            return

        msg = response.get("message") or {}
        tool_calls = msg.get("tool_calls") or []
        raw_content = msg.get("content") or ""

        # Fallback: model didn't use the structured tool_calls field but may
        # have emitted a tool call as JSON in content (Gemma, older Llama).
        if not tool_calls:
            recovered = _extract_tool_call_from_text(raw_content)
            if recovered:
                resolved_name, recovered_args = recovered
                yield (
                    f"_(your chat model emitted a tool call as text instead "
                    f"of using Ollama's native tool API — extracting "
                    f"`{resolved_name}` and continuing. For reliable tool "
                    f"calling switch `OLLAMA_MODEL` to `llama3.2`, "
                    f"`qwen2.5`, or `mistral-nemo`.)_\n"
                )
                tool_calls = [{
                    "function": {
                        "name": resolved_name,
                        "arguments": recovered_args,
                    },
                }]
                # Don't echo raw_content — it's the JSON payload, not a reply.
                raw_content = ""

        if not tool_calls:
            content = raw_content.strip()
            if content:
                yield content
            return

        # Echo any text the model produced alongside the tool calls (rare).
        narration = (msg.get("content") or "").strip()
        if narration:
            yield narration + "\n"

        # Append the assistant's tool-calling message verbatim so Ollama
        # has the right context on the next iteration.
        messages.append({
            "role": "assistant",
            "content": msg.get("content") or "",
            "tool_calls": tool_calls,
        })

        for tc in tool_calls:
            fn = (tc.get("function") or {})
            tool_name = fn.get("name", "<unknown>")
            tool_args = fn.get("arguments") or {}
            yield f"\n→ calling **{tool_name}**({json.dumps(tool_args)})\n"
            result = await _execute_tool(user_id, tool_name, tool_args)
            yield f"  ↳ {json.dumps(result)}\n"
            messages.append({
                "role": "tool",
                "name": tool_name,
                "content": json.dumps(result),
            })

    yield "\n\n⚠ tool loop limit reached"


async def chat_stream(user_id: str, history: list[dict], user_message: str):
    """Yield reply tokens from Ollama as they arrive. Mirrors `chat()`'s
    context-assembly path, then opens a streaming POST to `/api/chat` and
    parses Ollama's NDJSON stream into raw text fragments.
    """
    import json
    inbox_context, memories = await asyncio.gather(
        _load_inbox_context(user_id),
        search_memories(user_id, user_message),
    )
    messages = _build_chat_messages(
        inbox_context, memories, history, user_message
    )
    model = _effective_chat_model()
    payload = {
        "model": model,
        "messages": messages,
        "stream": True,
        "options": {
            "temperature": 0.2,
            "num_ctx": 4096,
            "num_predict": 600,
        },
    }
    async with httpx.AsyncClient(base_url=settings.ollama_url, timeout=120.0) as client:
        try:
            async with client.stream("POST", "/api/chat", json=payload) as resp:
                if resp.status_code == 404:
                    raise OllamaChatError(
                        f"Ollama doesn't have the chat model `{model}`. "
                        f"Run `ollama pull {model}` on the host serving "
                        f"{settings.ollama_url} and try again."
                    )
                if resp.status_code >= 400:
                    body = await resp.aread()
                    raise OllamaChatError(
                        f"Ollama /api/chat returned {resp.status_code}: "
                        f"{body[:300]!r}"
                    )
                async for line in resp.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    fragment = (obj.get("message") or {}).get("content")
                    if fragment:
                        yield fragment
                    if obj.get("done"):
                        break
        except httpx.HTTPError as exc:
            raise OllamaChatError(
                f"can't reach Ollama at {settings.ollama_url}: {exc}"
            ) from exc
