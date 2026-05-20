from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from cloudguardiq.auth.graph_principal_resolver import (
    PrincipalLookupError,
    PrincipalNotFoundError,
    clear_cache,
    resolve_customer_principal_id,
)


class _StubToken:
    def __init__(self, token: str = "fake") -> None:
        self.token = token
        self.expires_on = 0


class _StubCred:
    def __init__(self, *, tenant_id: str) -> None:
        self.tenant_id = tenant_id

    def get_token(self, scope: str) -> _StubToken:  # noqa: ARG002
        return _StubToken()


class _StubFactory:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def for_tenant(self, tenant_id: str) -> Any:
        self.calls.append(tenant_id)
        return _StubCred(tenant_id=tenant_id)


def _mk_client(handler):
    transport = httpx.MockTransport(handler)
    return httpx.AsyncClient(transport=transport)


@pytest.fixture(autouse=True)
def _clear() -> None:
    clear_cache()
    yield
    clear_cache()


def test_resolve_returns_oid_from_graph() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"id": "sp-oid-xyz"})

    async def go() -> str:
        async with _mk_client(handler) as client:
            return await resolve_customer_principal_id(
                _StubFactory(),
                client_id="11111111-1111-1111-1111-111111111111",
                tenant_id="22222222-2222-2222-2222-222222222222",
                http_client=client,
            )

    result = asyncio.run(go())
    assert result == "sp-oid-xyz"
    assert len(requests) == 1
    assert "servicePrincipals(appId=" in str(requests[0].url)
    assert requests[0].headers["Authorization"] == "Bearer fake"


def test_resolve_raises_not_found_on_404() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(404, json={"error": {"code": "Request_ResourceNotFound"}})

    async def go() -> None:
        async with _mk_client(handler) as client:
            await resolve_customer_principal_id(
                _StubFactory(),
                client_id="cid",
                tenant_id="tid",
                http_client=client,
            )

    with pytest.raises(PrincipalNotFoundError):
        asyncio.run(go())


def test_resolve_raises_lookup_error_on_other_status() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(500, text="boom")

    async def go() -> None:
        async with _mk_client(handler) as client:
            await resolve_customer_principal_id(
                _StubFactory(),
                client_id="cid",
                tenant_id="tid",
                http_client=client,
            )

    with pytest.raises(PrincipalLookupError):
        asyncio.run(go())


def test_resolve_caches_subsequent_calls() -> None:
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        call_count["n"] += 1
        return httpx.Response(200, json={"id": "cached-oid"})

    factory = _StubFactory()

    async def go() -> tuple[str, str]:
        async with _mk_client(handler) as client:
            a = await resolve_customer_principal_id(
                factory, client_id="cid", tenant_id="tid", http_client=client,
            )
            b = await resolve_customer_principal_id(
                factory, client_id="cid", tenant_id="tid", http_client=client,
            )
            return a, b

    a, b = asyncio.run(go())
    assert a == b == "cached-oid"
    assert call_count["n"] == 1
    # Factory was only invoked once because second call hit the cache.
    assert factory.calls == ["tid"]


def test_resolve_requires_client_id_and_tenant() -> None:
    factory = _StubFactory()

    async def call(cid: str, tid: str) -> None:
        await resolve_customer_principal_id(
            factory, client_id=cid, tenant_id=tid,
        )

    with pytest.raises(PrincipalLookupError):
        asyncio.run(call("", "t"))
    with pytest.raises(PrincipalLookupError):
        asyncio.run(call("c", ""))


def test_resolve_wraps_token_error() -> None:
    class _BadCred:
        def get_token(self, scope: str) -> _StubToken:  # noqa: ARG002
            raise RuntimeError("nope")

    class _BadFactory:
        def for_tenant(self, tenant_id: str) -> Any:  # noqa: ARG002
            return _BadCred()

    async def go() -> None:
        await resolve_customer_principal_id(
            _BadFactory(), client_id="cid", tenant_id="tid",
        )

    with pytest.raises(PrincipalLookupError, match="token"):
        asyncio.run(go())
