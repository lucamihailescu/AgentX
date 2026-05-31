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

_collection: Any = None
_init_lock = asyncio.Lock()
_unavailable = False  # sticky after a hard init failure


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
        try:
            import chromadb  # noqa: PLC0415 — defer heavy import

            def _open():
                client = chromadb.PersistentClient(path=settings.chroma_path)
                # We always pass embeddings explicitly, so no embedding
                # function is needed (avoids Chroma loading a default model).
                return client.get_or_create_collection(
                    _COLLECTION, metadata={"hnsw:space": "cosine"}
                )

            _collection = await asyncio.to_thread(_open)
            logger.info(
                "search index ready (chroma path=%s, collection=%s)",
                settings.chroma_path, _COLLECTION,
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
    try:
        async with httpx.AsyncClient(base_url=settings.ollama_url) as client:
            resp = await client.post(
                "/api/embed",
                json={"model": settings.embed_model, "input": texts},
                timeout=settings.ollama_timeout_seconds,
            )
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("embed call failed: %s", exc)
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

    embeddings = await _embed(docs)
    if embeddings is None:
        return 0

    try:
        await asyncio.to_thread(
            collection.upsert,
            ids=ids,
            embeddings=embeddings,
            documents=docs,
            metadatas=metas,
        )
    except Exception as exc:
        logger.warning("search index upsert failed: %s", exc)
        return 0
    logger.info("search index: upserted %d message(s)", len(ids))
    return len(ids)


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
