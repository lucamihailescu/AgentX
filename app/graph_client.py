from typing import Any, Awaitable, Callable

import httpx

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

TokenProvider = Callable[[], Awaitable[str]]


class GraphError(Exception):
    pass


class GraphClient:
    """Thin async Graph wrapper that pulls a fresh access token from the
    provided async callable before every request — relying on MSAL's silent
    cache to refresh on demand.
    """

    def __init__(self, token_provider: TokenProvider) -> None:
        self._token_provider = token_provider
        self._client = httpx.AsyncClient(base_url=GRAPH_BASE, timeout=30.0)

    async def __aenter__(self) -> "GraphClient":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self._client.aclose()

    async def request(self, method: str, path: str, json: Any = None) -> httpx.Response:
        token = await self._token_provider()
        resp = await self._client.request(
            method, path, headers={"Authorization": f"Bearer {token}"}, json=json
        )
        if resp.status_code >= 400:
            raise GraphError(f"{method} {path} -> {resp.status_code}: {resp.text[:200]}")
        return resp
