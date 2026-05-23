"""Multi-signal verdict blending.

Combines up to three independent signals into the final spam verdict:

  1. Ollama (LLM, content-aware, slow, sometimes wrong)
  2. Rspamd (email-tuned heuristics + per-user Bayes, fast, optional)
  3. Per-sender prior (the user's own delete/unsub history from sender_stats)

Each source contributes a p_spam in [0, 1] with a weight; the final
probability is a weighted average. Verdict transitions vs the model's
original call (flip / fill / adjust) are annotated so the UI can show
when blending changed the answer.

`sender_rules` short-circuits this whole pipeline upstream for explicit
allow/deny entries — this layer is for the *implicit* signal where the
user hasn't written a rule yet.
"""

from __future__ import annotations

import aiosqlite

from .config import settings


# Per-sender prior thresholds.
MIN_ACTIONS = 2  # below this, the prior is ignored entirely
MAX_ACTIONS = 5  # action count at which the prior reaches full weight


async def load_priors(user_id: str) -> dict[str, dict]:
    """Return `{sender_address: {n_seen, n_actions}}` for every sender
    with at least `MIN_ACTIONS` user actions on record.
    """
    if not settings.calibration_enabled:
        return {}
    async with aiosqlite.connect(settings.db_path) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """SELECT target, seen, deleted, unsubscribed
               FROM sender_stats
               WHERE user_id = ? AND target_type = 'address'
                 AND (deleted + unsubscribed) >= ?""",
            (user_id, MIN_ACTIONS),
        )
        return {
            r["target"]: {
                "n_seen": int(r["seen"]),
                "n_actions": int(r["deleted"]) + int(r["unsubscribed"]),
            }
            for r in await cur.fetchall()
        }


def _prior_p_and_weight(prior: dict | None) -> tuple[float, float] | None:
    """Return `(p_spam, weight)` for a per-sender prior, or None if the
    prior is too weak to count."""
    if not prior:
        return None
    n_actions = prior["n_actions"]
    n_seen = max(prior["n_seen"], n_actions)
    if n_actions < MIN_ACTIONS:
        return None
    p = (n_actions + 1) / (n_seen + 2)            # Laplace-smoothed
    w = min(n_actions, MAX_ACTIONS) / MAX_ACTIONS  # 0..1
    return p, w


def blend(
    ollama: dict,
    *,
    rspamd: dict | None = None,
    prior: dict | None = None,
) -> dict:
    """Combine the Ollama verdict with optional Rspamd and per-sender prior.

    `ollama` is the verdict dict from ollama_client.classify.
    `rspamd` is `{"p_spam": float, "score": float, "action": str, "symbols": list}`
        or None.
    `prior` is `{"n_seen", "n_actions"}` or None.

    Returns a new verdict dict with `spam`, `confidence`, `reason`, and
    annotation fields. Falls back gracefully when sources are missing.
    """
    orig_spam = ollama.get("spam")
    orig_conf = ollama.get("confidence")
    base_reason = (ollama.get("reason") or "").strip()

    sources: list[tuple[float, float, str]] = []  # (weight, p_spam, label)

    ollama_failed = orig_spam is None
    if not ollama_failed:
        m_conf = orig_conf if isinstance(orig_conf, (int, float)) else 0.5
        p_o = m_conf if orig_spam else (1.0 - m_conf)
        sources.append((1.0, p_o, "ollama"))

    if rspamd is not None:
        # Weight from settings; 0 effectively disables.
        rw = max(settings.rspamd_weight, 0.0)
        if rw > 0:
            sources.append((rw, float(rspamd["p_spam"]), "rspamd"))

    prior_pw = _prior_p_and_weight(prior)
    if prior_pw is not None:
        p_pr, w_pr = prior_pw
        sources.append((w_pr, p_pr, "prior"))

    if not sources:
        # Nothing to combine and Ollama failed — preserve the failure state.
        return dict(ollama)

    total_w = sum(w for w, _, _ in sources)
    p_combined = sum(w * p for w, p, _ in sources) / total_w

    new_spam = p_combined > 0.5
    new_conf = round(max(p_combined, 1.0 - p_combined), 3)
    used = [label for _, _, label in sources]

    out = {**ollama, "spam": new_spam, "confidence": new_conf, "blend_sources": used}

    # Stash raw signals for downstream UI / debugging.
    if rspamd is not None:
        out["rspamd_score"] = round(float(rspamd["score"]), 2)
        out["rspamd_action"] = rspamd.get("action")
        if rspamd.get("symbols"):
            out["rspamd_symbols"] = list(rspamd["symbols"])[:8]
    if prior_pw is not None:
        out["prior_n_actions"] = int(prior["n_actions"])
        out["prior_n_seen"] = int(prior["n_seen"])

    # Annotation: did blending change the model's call?
    flipped = (not ollama_failed) and orig_spam != new_spam
    filled = ollama_failed
    if flipped or filled:
        out["calibration_applied"] = "flipped" if flipped else "filled"
        prefix = base_reason or ("model failed" if filled else "")
        sep = " — " if prefix else ""
        sig_summary = _signal_summary(rspamd, prior)
        out["reason"] = f"{prefix}{sep}{sig_summary}" if sig_summary else (
            prefix or "blended"
        )
    elif (orig_conf is None or abs(new_conf - orig_conf) >= 0.05) and len(sources) > 1:
        out["calibration_applied"] = "adjusted"
        sig_summary = _signal_summary(rspamd, prior)
        if base_reason and sig_summary:
            out["reason"] = f"{base_reason} ({sig_summary})"

    return out


def _signal_summary(rspamd: dict | None, prior: dict | None) -> str:
    """Short human-readable description of the non-Ollama signals."""
    parts: list[str] = []
    if rspamd is not None:
        parts.append(f"rspamd {rspamd.get('action', '?')} (score {rspamd.get('score', 0):.1f})")
    prior_pw = _prior_p_and_weight(prior)
    if prior_pw is not None and prior is not None:
        n = prior["n_actions"]
        parts.append(f"{n} prior action{'s' if n != 1 else ''}")
    return ", ".join(parts)


# Back-compat shim: the previous version had `apply(verdict, prior)`. Internal
# call sites have been migrated to `blend`; leaving this here covers any tests
# / external callers that still use the old name.
def apply(verdict: dict, prior: dict) -> dict:
    return blend(verdict, prior=prior)
