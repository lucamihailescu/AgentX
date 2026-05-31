"""Semantic mailbox search.

The chat assistant already runs an embedding model (`nomic-embed-text`) and a
persisted ChromaDB — but only for distilled *memories*. This module reuses the
same embeddings + Chroma infrastructure for a different job: a vector index of
the actual messages the agent has audited, so the user can ask "find the
receipt from the plumber in March" and get semantic hits rather than keyword
matches.

It deliberately does NOT go through mem0 — mem0 distills/merges facts, which is
wrong for verbatim message recall. Instead we keep a dedicated collection
(`agentx_messages`), embed each message's sender/subject/preview directly via
Ollama, and store enough metadata to deep-link back to the source audit row.

Everything degrades gracefully: if Chroma or the embed model is unavailable,
indexing and search both no-op (logged once) and the rest of the app is
unaffected — exactly like the chat memory layer.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from .config import settings

logger = logging.getLogger(__name__)

_COLLECTION = "agentx_messages"

# Embed in chunks so one transient Ollama hiccup only costs that chunk (the
# rest still index) and peak request size stays bounded on memory-constrained
# hosts that are also juggling the classifier + chat models.
_EMBED_CHUNK = 64
_EMBED_ATTEMPTS = 3

_collection: Any = None
_init_lock = asyncio.Lock()
_unavailable = False  # sticky after a hard init failure


def _search_chroma_path() -> str:
    """Dedicated Chroma directory for the message index — a sibling of mem0's
    store, NOT the same path.

    ChromaDB allows only one client instance per path within a process, and
    rejects a second one whose Settings differ ("instance already exists ...
    with different settings"). mem0 (chat memory) and this search index are
    two independent clients, so they must live at different paths or one will
    block the other's init. Sits under the same /data bind mount, so it
    persists across `docker compose down`.
    """
    base = settings.chroma_path.rstrip("/\\")
    return f"{base}_search"


async def _get_collection():
    """Lazy Chroma collection init. Returns None on failure (caller no-ops)."""
    global _collection, _unavailable
    if _collection is not None:
        return _collection
    if _unavailable or not settings.search_enabled:
        return None
    async with _init_lock:
        if _collection is not None:
            return _collection
        if _unavailable:
            return None
        path = _search_chroma_path()
        try:
            import chromadb  # noqa: PLC0415 — defer heavy import
            from chromadb.config import Settings  # noqa: PLC0415

            def _open():
                client = chromadb.PersistentClient(
                    path=path,
                    # Telemetry is off because the bundled posthog client
                    # version raises on capture(); it only spams the logs.
                    settings=Settings(anonymized_telemetry=False),
                )
                # We always pass embeddings explicitly, so no embedding
                # function is needed (avoids Chroma loading a default model).
                return client.get_or_create_collection(
                    _COLLECTION, metadata={"hnsw:space": "cosine"}
                )

            _collection = await asyncio.to_thread(_open)
            logger.info(
                "search index ready (chroma path=%s, collection=%s)",
                path, _COLLECTION,
            )
        except Exception as exc:
            logger.warning(
                "search index init failed (%s); semantic search disabled", exc
            )
            _unavailable = True
            return None
        return _collection


def _doc_text(m: dict) -> str:
    """The text we embed for a message — sender, subject, preview."""
    parts = [
        m.get("from") or "",
        m.get("subject") or "",
        (m.get("preview") or "").strip(),
    ]
    return "\n".join(p for p in parts if p).strip()


async def _embed(texts: list[str]) -> list[list[float]] | None:
    """Batch-embed via Ollama's /api/embed. Returns None on failure."""
    if not texts:
        return []
    data: dict | None = None
    async with httpx.AsyncClient(base_url=settings.ollama_url) as client:
        for attempt in range(1, _EMBED_ATTEMPTS + 1):
            try:
                resp = await client.post(
                    "/api/embed",
                    json={"model": settings.embed_model, "input": texts},
                    timeout=settings.ollama_timeout_seconds,
                )
            except httpx.TransportError as exc:
                # Connect/read error — transient; back off and retry.
                if attempt == _EMBED_ATTEMPTS:
                    logger.warning("embed call failed (transport): %s", exc)
                    return None
                await asyncio.sleep(0.5 * attempt)
                continue
            if resp.status_code >= 500:
                # Ollama 5xx is usually transient (model load / memory
                # pressure while it juggles classifier + embed models).
                if attempt == _EMBED_ATTEMPTS:
                    logger.warning(
                        "embed call failed: %s - Ollama said: %s",
                        resp.status_code, resp.text[:200],
                    )
                    return None
                await asyncio.sleep(0.5 * attempt)
                continue
            if resp.status_code >= 400:
                # 4xx (e.g. model not found) won't fix itself — don't retry.
                logger.warning(
                    "embed call rejected: %s - Ollama said: %s. "
                    "Is AGENT_EMBED_MODEL (%s) pulled?",
                    resp.status_code, resp.text[:200], settings.embed_model,
                )
                return None
            try:
                data = resp.json()
            except ValueError as exc:
                logger.warning("embed response not JSON: %s", exc)
                return None
            break
    if data is None:
        return None
    embeddings = data.get("embeddings")
    if embeddings is None and "embedding" in data:  # single-vector shape
        embeddings = [data["embedding"]]
    if not isinstance(embeddings, list) or len(embeddings) != len(texts):
        logger.warning("embed response shape unexpected (got %s vectors for %s texts)",
                       len(embeddings or []), len(texts))
        return None
    return embeddings


def _metadata(user_id: str, audit_task_id: str, m: dict) -> dict:
    """Chroma metadata — all values must be str/int/float/bool (never None)."""
    return {
        "user_id": user_id,
        "message_id": m.get("id") or "",
        "audit_task_id": audit_task_id or "",
        "from": m.get("from") or "",
        "subject": m.get("subject") or "",
        "received": m.get("received") or "",
        "category": m.get("category") or "",
        "spam": bool(m.get("spam") is True),
    }


async def index_messages(
    user_id: str, audit_task_id: str, messages: list[dict]
) -> int:
    """Embed + upsert a completed audit's messages into the search index.

    Best-effort: a failure (Chroma down, embed model missing) logs and returns
    0 without disturbing the audit. Upsert keys on `user_id:message_id`, so
    re-auditing the same message refreshes rather than duplicates it.
    """
    collection = await _get_collection()
    if collection is None:
        return 0

    docs: list[str] = []
    ids: list[str] = []
    metas: list[dict] = []
    for m in messages:
        mid = m.get("id")
        if not mid:
            continue
        text = _doc_text(m)
        if not text:
            continue
        ids.append(f"{user_id}:{mid}")
        docs.append(text)
        metas.append(_metadata(user_id, audit_task_id, m))

    if not ids:
        return 0

    # Embed + upsert in chunks: a transient embed failure costs only its
    # chunk, and the next audit re-upserts everything anyway (idempotent).
    upserted = 0
    failed_chunks = 0
    for start in range(0, len(ids), _EMBED_CHUNK):
        end = start + _EMBED_CHUNK
        chunk_docs = docs[start:end]
        embeddings = await _embed(chunk_docs)
        if embeddings is None:
            failed_chunks += 1
            continue
        try:
            await asyncio.to_thread(
                collection.upsert,
                ids=ids[start:end],
                embeddings=embeddings,
                documents=chunk_docs,
                metadatas=metas[start:end],
            )
        except Exception as exc:
            logger.warning("search index upsert failed: %s", exc)
            failed_chunks += 1
            continue
        upserted += len(chunk_docs)

    if failed_chunks:
        logger.warning(
            "search index: %d message(s) upserted, %d chunk(s) skipped "
            "(transient embed/upsert failures; next audit retries)",
            upserted, failed_chunks,
        )
    elif upserted:
        logger.info("search index: upserted %d message(s)", upserted)
    return upserted


async def search(user_id: str, query: str, *, limit: int = 20) -> list[dict]:
    """Semantic search the user's indexed messages. Returns hits ordered by
    relevance, each with the metadata needed to deep-link to its audit row."""
    query = (query or "").strip()
    if not query:
        return []
    collection = await _get_collection()
    if collection is None:
        return []
    vec = await _embed([query])
    if not vec:
        return []
    try:
        res = await asyncio.to_thread(
            collection.query,
            query_embeddings=vec,
            n_results=limit,
            where={"user_id": user_id},
        )
    except Exception as exc:
        logger.warning("search query failed: %s", exc)
        return []

    metas = (res.get("metadatas") or [[]])[0]
    dists = (res.get("distances") or [[]])[0]
    out: list[dict] = []
    for i, meta in enumerate(metas):
        hit = dict(meta)
        dist = dists[i] if i < len(dists) else None
        # Cosine distance → a friendly 0..1 similarity for display.
        if isinstance(dist, (int, float)):
            hit["score"] = round(max(0.0, 1.0 - dist), 3)
        out.append(hit)
    return out
