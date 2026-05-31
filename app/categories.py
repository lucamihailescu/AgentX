"""Triage taxonomy — multi-class categorization layered on top of the
spam verdict.

Where the spam classifier answers "is this junk?", the triage layer answers
"what *kind* of mail is this, and does it want a reply?". The model returns a
free-form `category` + a `needs_reply` boolean alongside the spam verdict
(see `ollama_client.classify`); this module pins those to a fixed, predictable
set and maps each onto a short mailbox label so the worker can file the
message back into Outlook categories / Gmail labels.

Keeping the canonical set small and fixed (rather than user-configurable) means
the rendered chips, filter buttons, and folder names are all knowable ahead of
time — the UI doesn't have to discover categories at runtime.
"""

from __future__ import annotations

from .config import settings

# Canonical categories, in display order. `Other` is the catch-all the
# normalizer falls back to for anything it can't confidently place.
CATEGORIES: tuple[str, ...] = (
    "Personal",
    "Finance/Receipts",
    "Travel",
    "Newsletter/Promotions",
    "Notifications/Updates",
    "Other",
)

OTHER = "Other"

# Canonical category → short, filesystem-friendly leaf used to build the
# mailbox label (`<prefix>/<leaf>`). Outlook categories are free strings;
# Gmail treats "/" as nesting, so these become tidy sub-labels there.
_LABEL_LEAF: dict[str, str] = {
    "Personal": "Personal",
    "Finance/Receipts": "Finance",
    "Travel": "Travel",
    "Newsletter/Promotions": "Promotions",
    "Notifications/Updates": "Updates",
    "Other": "Other",
}

# Separate marker label for "the model thinks this wants a human reply",
# applied in addition to the category label.
_NEEDS_REPLY_LEAF = "Needs Reply"

# Substrings we'll accept as aliases when the model picks a near-synonym
# instead of the exact canonical label. First match (in CATEGORIES order via
# the loop below) wins, so more-specific buckets are checked before `Other`.
_ALIASES: dict[str, tuple[str, ...]] = {
    "Personal": ("personal", "friend", "family", "individual"),
    "Finance/Receipts": (
        "finance", "receipt", "invoice", "payment", "bill", "bank",
        "order", "purchase", "transaction", "statement",
    ),
    "Travel": ("travel", "flight", "hotel", "booking", "itinerary",
               "reservation", "trip", "boarding"),
    "Newsletter/Promotions": (
        "newsletter", "promotion", "promotional", "marketing", "deal",
        "offer", "sale", "digest", "campaign",
    ),
    "Notifications/Updates": (
        "notification", "update", "alert", "reminder", "security",
        "system", "automated", "no-reply", "noreply", "social",
    ),
}


def normalize_category(value: object) -> str:
    """Coerce a raw model category string to one of `CATEGORIES`.

    Tries an exact (case-insensitive) match first, then substring aliases,
    and finally falls back to `Other`. Always returns a canonical value.
    """
    if not isinstance(value, str):
        return OTHER
    v = value.strip().lower()
    if not v:
        return OTHER
    for canonical in CATEGORIES:
        if v == canonical.lower():
            return canonical
    for canonical in CATEGORIES:
        for alias in _ALIASES.get(canonical, ()):
            if alias in v:
                return canonical
    return OTHER


def category_label(category: str) -> str:
    """Mailbox label for a canonical category, e.g. ``AgentX/Finance``."""
    leaf = _LABEL_LEAF.get(category, OTHER)
    return f"{settings.label_prefix}/{leaf}"


def needs_reply_label() -> str:
    """Mailbox label flagging a message that wants a human reply."""
    return f"{settings.label_prefix}/{_NEEDS_REPLY_LEAF}"


def phishing_label() -> str:
    """Mailbox label flagging a suspected phishing / BEC message."""
    return f"{settings.label_prefix}/Phishing"
