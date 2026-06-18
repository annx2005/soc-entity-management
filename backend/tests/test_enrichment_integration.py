from __future__ import annotations

import asyncio
import os

import pytest

from app.enrichment.cache import RedisEnrichmentCache
from app.enrichment.schemas import EnrichmentResult


def test_redis_enrichment_cache_when_configured() -> None:
    redis_url = os.getenv("REDIS_TEST_URL")
    if not redis_url:
        pytest.skip("set REDIS_TEST_URL to run Redis enrichment integration tests")

    asyncio.run(_run_redis_cache_test(redis_url))


async def _run_redis_cache_test(redis_url: str) -> None:
    cache = RedisEnrichmentCache(redis_url)
    key = "enrichment:test:ip:8.8.8.8"
    result = EnrichmentResult(
        entity_type="ip",
        value="8.8.8.8",
        data={"country": "US"},
        source="integration",
        cache_status="miss",
    )
    try:
        await cache.set(key, result, 60)
        cached = await cache.get(key)
        assert cached is not None
        assert cached.data["country"] == "US"
    finally:
        await cache._client.delete(key)
        await cache.close()
