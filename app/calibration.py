"""Per-sender calibration on top of the Ollama classifier.

The model is stateless — it sees each message in isolation. The user's
history with a given sender is a strong, deterministic signal that we
already collect in `sender_stats` (delete + unsub counts). This module
blends that prior into the model's verdict using a weighted log-odds
combination so:

  - confidence is boosted when model and prior agree
  - the verdict flips when the prior is strong enough to outweigh
    a borderline model call
  - a model failure (verdict=None) falls back to the prior alone

`sender_rules` already short-circuits Ollama entirely for explicit
allow/deny entries — this module covers the *implicit* signal from
accumulated actions where the user never wrote a rule.
"""

from __future__ import annotations

import aiosqlite

from .config import settings


# Minimum user actions before the prior is allowed to influence the
# verdict at all. Below this, we trust the model.
MIN_ACTIONS = 2
# Number of actions at which the prior reaches full weight. Anything
# above this is capped — diminishing returns past a point.
MAX_ACTIONS = 5


async def load_priors(user_id: str) -> dict[str, dict]:
    """Return a `{sender_address: {n_seen, n_actions}}` map for every
    sender this user has any action history with. Excludes senders with
    zero actions to keep the map small — they wouldn't qualify anyway.
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


def apply(verdict: dict, prior: dict) -> dict:
    """Blend the model verdict with the sender's prior.

    `verdict` is the dict returned by ollama_client.classify (or that
    shape produced upstream). `prior` is one entry from `load_priors`.
    Mutates a copy of verdict and returns it.
    """
    n_actions = prior["n_actions"]
    n_seen = max(prior["n_seen"], n_actions)  # in case stats lag
    if n_actions < MIN_ACTIONS:
        return verdict

    # Laplace-smoothed P(spam | sender).
    p_prior = (n_actions + 1) / (n_seen + 2)
    weight = min(n_actions, MAX_ACTIONS) / MAX_ACTIONS  # 0..1

    orig_spam = verdict.get("spam")
    orig_conf = verdict.get("confidence")

    if orig_spam is None:
        # Model failed — fall back to prior alone.
        p_combined = p_prior
    else:
        m_conf = orig_conf if isinstance(orig_conf, (int, float)) else 0.5
        p_model = m_conf if orig_spam else (1.0 - m_conf)
        p_combined = (1.0 - weight) * p_model + weight * p_prior

    new_spam = p_combined > 0.5
    new_conf = round(max(p_combined, 1.0 - p_combined), 3)

    out = {**verdict, "spam": new_spam, "confidence": new_conf}

    flipped = orig_spam is not None and orig_spam != new_spam
    failed = orig_spam is None
    base_reason = (verdict.get("reason") or "").strip()
    action_word = "action" if n_actions == 1 else "actions"

    if flipped or failed:
        out["calibration_applied"] = "flipped" if flipped else "filled"
        prefix = base_reason or ("model failed" if failed else "")
        sep = " — " if prefix else ""
        out["reason"] = (
            f"{prefix}{sep}calibrated: {n_actions} prior {action_word} against "
            f"this sender"
        )
    else:
        # Same verdict — the prior shifted confidence in one direction or
        # the other. Skip noise (< 0.05 shift).
        if orig_conf is None or abs(new_conf - orig_conf) >= 0.05:
            out["calibration_applied"] = "adjusted"
            if base_reason:
                out["reason"] = (
                    f"{base_reason} (±{n_actions} prior {action_word})"
                )

    out["prior_n_actions"] = n_actions
    out["prior_n_seen"] = n_seen
    return out
