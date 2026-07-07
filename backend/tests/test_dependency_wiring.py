from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from app.enrichment import dependencies as enrichment_dependencies
from app.enrichment.service import EnrichmentService
from app.graph import dependencies as graph_dependencies
from app.graph.service import GraphService


def test_make_enrichment_provider_builds_composite_and_rejects_unknown_mode(monkeypatch) -> None:
    monkeypatch.setattr(
        enrichment_dependencies,
        "get_settings",
        lambda: SimpleNamespace(
            enrichment_provider_mode="ipinfo_malwarebazaar",
            enrichment_ipinfo_token="token",
            enrichment_ipinfo_base_url="https://ipinfo.example",
            enrichment_http_timeout_seconds=3,
            enrichment_malware_bazaar_auth_key="mb-key",
            enrichment_malware_bazaar_url="https://mb.example",
        ),
    )

    provider = enrichment_dependencies.make_enrichment_provider()

    assert provider.__class__.__name__ == "CompositeEnrichmentProvider"

    monkeypatch.setattr(enrichment_dependencies, "get_settings", lambda: SimpleNamespace(enrichment_provider_mode="unknown"))
    with pytest.raises(ValueError, match="unsupported enrichment provider mode"):
        enrichment_dependencies.make_enrichment_provider()


def test_close_enrichment_provider_handles_async_and_sync_close() -> None:
    calls: list[str] = []

    class AsyncProvider:
        async def close(self) -> None:
            calls.append("async")

    class SyncProvider:
        def close(self) -> None:
            calls.append("sync")

    asyncio.run(enrichment_dependencies.close_enrichment_provider(AsyncProvider()))
    asyncio.run(enrichment_dependencies.close_enrichment_provider(SyncProvider()))
    asyncio.run(enrichment_dependencies.close_enrichment_provider(object()))

    assert calls == ["async", "sync"]


def test_get_enrichment_service_yields_service_and_closes_resources(monkeypatch) -> None:
    closed: list[str] = []

    class FakeCache:
        def __init__(self, redis_url: str) -> None:
            self.redis_url = redis_url

        async def close(self) -> None:
            closed.append("cache")

    class FakeProvider:
        async def close(self) -> None:
            closed.append("provider")

    monkeypatch.setattr(
        enrichment_dependencies,
        "get_settings",
        lambda: SimpleNamespace(redis_url="redis://unit/0", enrichment_cache_ttl_seconds=42, enrichment_enabled=False),
    )
    monkeypatch.setattr(enrichment_dependencies, "RedisEnrichmentCache", FakeCache)
    monkeypatch.setattr(enrichment_dependencies, "make_enrichment_provider", lambda: FakeProvider())

    async def consume() -> EnrichmentService:
        generator = enrichment_dependencies.get_enrichment_service()
        service = await generator.__anext__()
        await generator.aclose()
        return service

    service = asyncio.run(consume())

    assert isinstance(service, EnrichmentService)
    assert closed == ["provider", "cache"]


def test_get_graph_service_closes_driver(monkeypatch) -> None:
    closed = {"driver": False}

    class FakeDriver:
        async def close(self) -> None:
            closed["driver"] = True

    monkeypatch.setattr(graph_dependencies, "create_graph_driver", lambda: FakeDriver())

    async def consume() -> GraphService:
        generator = graph_dependencies.get_graph_service()
        service = await generator.__anext__()
        await generator.aclose()
        return service

    service = asyncio.run(consume())

    assert isinstance(service, GraphService)
    assert closed["driver"] is True
