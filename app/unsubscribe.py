"""List-Unsubscribe (RFC 2369) + One-Click (RFC 8058) handling.

Body-link parsing is intentionally not supported — only the standardized
header is read, matching how Apple Mail / Gmail / Outlook handle unsubscribe.
"""

import re

import httpx


class UnsubscribeError(Exception):
    pass


def find_unsubscribe(headers: list[dict]) -> dict | None:
    """Return ``{"url": str, "one_click": bool}`` for the first HTTPS unsubscribe
    target in the given internet-message headers, or ``None`` if there isn't one.
    """
    by_name = {(h.get("name") or "").lower(): h.get("value") or "" for h in headers}
    raw = by_name.get("list-unsubscribe", "")
    if not raw:
        return None
    uris = re.findall(r"<([^>]+)>", raw)
    https_url = next(
        (u.strip() for u in uris if u.strip().lower().startswith("https://")),
        None,
    )
    if not https_url:
        return None
    one_click = "one-click" in by_name.get("list-unsubscribe-post", "").lower()
    return {"url": https_url, "one_click": one_click}


async def perform_unsubscribe(url: str, one_click: bool) -> None:
    """Hit the unsubscribe URL. POST per RFC 8058 if one-click is supported,
    otherwise GET. Follows redirects; treats any 2xx (after redirects) as success.
    """
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
            if one_click:
                resp = await client.post(url, data={"List-Unsubscribe": "One-Click"})
            else:
                resp = await client.get(url)
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise UnsubscribeError(f"{type(exc).__name__}: {exc}") from exc
