"""Phishing / BEC heuristics.

Spam asks "is this junk?"; this layer asks the orthogonal question "is this
*deceptive* — trying to look like someone it isn't?". The two are independent:
a newsletter is spammy but honest; a credential-harvest mail spoofing your bank
may be low-volume and slip past a spam score entirely. So phishing is surfaced
as its own verdict, not folded into `spam`.

Everything here is deterministic and runs on metadata the providers already
fetched (the `From` header, `Reply-To`, and `Authentication-Results` /
`Received-SPF`). No LLM, no network — a fast pass over each message dict.

The signal that matters most for consumer BEC is *authentication failure with
display-name deception*: a message that claims (in its display name) to be from
PayPal/your boss/your bank, sent from an unrelated domain, that also fails
DMARC. Each signal carries a weight; the message is flagged when the total
clears `_PHISHING_THRESHOLD`. Reasons are always recorded for triggered signals
so the UI can explain *why*.
"""

from __future__ import annotations

import re
from email.utils import parseaddr

from .config import settings

# ── weights ──────────────────────────────────────────────────────────────
_W_DISPLAY_ADDR_MISMATCH = 3   # display name embeds a different email address
_W_DISPLAY_DOMAIN_MISMATCH = 2  # display name embeds a different bare domain
_W_BRAND_IMPERSONATION = 3     # display name names a brand; domain isn't theirs
_W_REPLYTO_MISMATCH = 2        # Reply-To domain differs from From domain
_W_DMARC_FAIL = 3
_W_SPF_FAIL = 2
_W_DKIM_FAIL = 1

_PHISHING_THRESHOLD = 3

# Consumer brands commonly impersonated, mapped to the registrable domains
# that legitimately send as them. A display name mentioning the brand from a
# domain outside this set is a strong impersonation signal.
_BRANDS: dict[str, frozenset[str]] = {
    "paypal": frozenset({"paypal.com"}),
    "apple": frozenset({"apple.com", "icloud.com"}),
    "icloud": frozenset({"apple.com", "icloud.com"}),
    "microsoft": frozenset({"microsoft.com", "outlook.com", "office.com", "live.com", "microsoftonline.com"}),
    "office365": frozenset({"microsoft.com", "outlook.com", "office.com"}),
    "amazon": frozenset({"amazon.com", "amazon.co.uk", "amazonses.com"}),
    "google": frozenset({"google.com", "gmail.com", "googlemail.com"}),
    "netflix": frozenset({"netflix.com"}),
    "facebook": frozenset({"facebook.com", "facebookmail.com"}),
    "instagram": frozenset({"instagram.com", "mail.instagram.com"}),
    "linkedin": frozenset({"linkedin.com"}),
    "chase": frozenset({"chase.com"}),
    "wells fargo": frozenset({"wellsfargo.com"}),
    "wellsfargo": frozenset({"wellsfargo.com"}),
    "bank of america": frozenset({"bankofamerica.com"}),
    "citibank": frozenset({"citi.com", "citibank.com"}),
    "docusign": frozenset({"docusign.com", "docusign.net"}),
    "dhl": frozenset({"dhl.com"}),
    "fedex": frozenset({"fedex.com"}),
    "ups": frozenset({"ups.com"}),
    "usps": frozenset({"usps.com"}),
    "coinbase": frozenset({"coinbase.com"}),
}

# Bare-domain token like "paypal.com" appearing inside a display name.
_DOMAIN_IN_TEXT_RE = re.compile(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+\.[a-z]{2,})\b", re.I)
_AUTH_RESULT_RE = {
    "spf": re.compile(r"\bspf=(\w+)", re.I),
    "dkim": re.compile(r"\bdkim=(\w+)", re.I),
    "dmarc": re.compile(r"\bdmarc=(\w+)", re.I),
}


def _domain_of(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[-1].strip().lower().rstrip(".") or None


def _registrable_matches(domain: str | None, allowed: frozenset[str]) -> bool:
    """True if `domain` is one of `allowed` or a subdomain of one."""
    if not domain:
        return False
    return any(domain == a or domain.endswith("." + a) for a in allowed)


def _same_org(d1: str | None, d2: str | None) -> bool:
    """Cheap same-organization check: equal, or one is a subdomain of the
    other, or they share the same last-two-label registrable domain."""
    if not d1 or not d2:
        return False
    if d1 == d2 or d1.endswith("." + d2) or d2.endswith("." + d1):
        return True
    return d1.split(".")[-2:] == d2.split(".")[-2:]


def _parse_auth(auth_headers: dict[str, str] | None) -> dict[str, str]:
    """Return {'spf','dkim','dmarc': result}. Results are lowercase tokens
    ('pass'/'fail'/'softfail'/'none'/...) or absent when not stated."""
    out: dict[str, str] = {}
    if not auth_headers:
        return out
    blob = " ".join(
        auth_headers.get(k, "")
        for k in ("authentication-results", "received-spf")
    )
    for mech, rx in _AUTH_RESULT_RE.items():
        m = rx.search(blob)
        if m:
            out[mech] = m.group(1).lower()
    # Received-SPF header states the SPF result as its leading token, e.g.
    # "Received-SPF: fail (google.com: ...)". Prefer an explicit spf= token,
    # fall back to this.
    if "spf" not in out:
        rspf = (auth_headers.get("received-spf") or "").strip().lower()
        first = rspf.split("(", 1)[0].strip().split()
        if first and first[0] in {"pass", "fail", "softfail", "neutral", "none"}:
            out["spf"] = first[0]
    return out


def analyze(message: dict) -> dict | None:
    """Inspect a message dict and return phishing annotations, or None when
    nothing is suspicious.

    Returns ``{"phishing": bool, "phishing_score": int,
    "phishing_reasons": [str]}``. `phishing` is True only when the weighted
    score clears the threshold; reasons are recorded for every triggered
    signal regardless, so a sub-threshold message can still show *why* it was
    close without being alarmingly flagged.
    """
    from_addr = (message.get("from") or "").strip().lower() or None
    from_domain = _domain_of(from_addr)
    from_header = message.get("from_header") or ""
    display_name, _ = parseaddr(from_header)
    display_low = (display_name or "").strip().lower()
    auth = _parse_auth(message.get("auth_headers"))

    score = 0
    reasons: list[str] = []

    # 1) Display name embeds a *different* email address than the real sender.
    embedded = parseaddr(display_name)[1] if "@" in display_low else ""
    embedded_domain = _domain_of(embedded)
    if embedded_domain and from_domain and not _same_org(embedded_domain, from_domain):
        score += _W_DISPLAY_ADDR_MISMATCH
        reasons.append(
            f"display name shows {embedded} but message is from {from_domain}"
        )
    elif display_low and from_domain:
        # 2) Display name embeds a bare domain unrelated to the real sender.
        for cand in _DOMAIN_IN_TEXT_RE.findall(display_low):
            cand = cand.lower().rstrip(".")
            if not _same_org(cand, from_domain):
                score += _W_DISPLAY_DOMAIN_MISMATCH
                reasons.append(
                    f"display name mentions {cand} but message is from {from_domain}"
                )
                break

    # 3) Brand impersonation: display name names a brand, domain isn't theirs.
    for brand, allowed in _BRANDS.items():
        if brand in display_low and not _registrable_matches(from_domain, allowed):
            score += _W_BRAND_IMPERSONATION
            reasons.append(
                f"claims to be {brand} but sender domain {from_domain or '?'} isn't theirs"
            )
            break

    # 4) Reply-To points to a different organization (classic BEC redirect).
    reply_to = _domain_of(
        parseaddr((message.get("auth_headers") or {}).get("reply-to", ""))[1]
    )
    if reply_to and from_domain and not _same_org(reply_to, from_domain):
        score += _W_REPLYTO_MISMATCH
        reasons.append(f"Reply-To domain {reply_to} differs from sender {from_domain}")

    # 5) Authentication failures. DMARC pass means aligned, authenticated mail
    #    — suppress the noisier spf/dkim signals in that case to avoid flagging
    #    legitimately-forwarded or ESP-relayed mail.
    dmarc = auth.get("dmarc")
    if dmarc == "fail":
        score += _W_DMARC_FAIL
        reasons.append("DMARC authentication failed")
    elif dmarc != "pass":
        if auth.get("spf") in {"fail", "softfail"}:
            score += _W_SPF_FAIL
            reasons.append(f"SPF {auth['spf']}")
        if auth.get("dkim") == "fail":
            score += _W_DKIM_FAIL
            reasons.append("DKIM signature failed")

    if not reasons:
        return None
    return {
        "phishing": score >= _PHISHING_THRESHOLD,
        "phishing_score": score,
        "phishing_reasons": reasons,
    }


def flag_messages(messages: list[dict]) -> int:
    """Run `analyze` over every non-auto-deleted message in place, attaching
    phishing annotations. Returns the count flagged as phishing.

    Runs even on allow-listed senders: a spoofed message *claiming* to be a
    trusted contact is exactly the case a sender allow-rule would otherwise
    wave through.
    """
    if not settings.phishing_enabled:
        return 0
    flagged = 0
    for m in messages:
        if m.get("auto_deleted"):
            continue
        verdict = analyze(m)
        if verdict is None:
            continue
        m.update(verdict)
        if verdict["phishing"]:
            flagged += 1
    return flagged
