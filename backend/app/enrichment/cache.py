from __future__ import annotations

from typing import Protocol

from redis.asyncio import Redis

from app.enrichment.schemas import EnrichmentResult


class EnrichmentCache(Protocol):
    async def get(self, key: str) -> EnrichmentResult | None:
        ...

    async def set(self, key: str, result: EnrichmentResult, ttl_seconds: int) -> None:
        ...


class RedisEnrichmentCache:
    def __init__(self, redis_url: str) -> None:
        self._client = Redis.from_url(redis_url, socket_connect_timeout=1, decode_responses=True)

    async def get(self, key: str) -> EnrichmentResult | None:
        value = await self._client.get(key)
        if not value:
            return None
        return EnrichmentResult.model_validate_json(value)

    async def set(self, key: str, result: EnrichmentResult, ttl_seconds: int) -> None:
        await self._client.setex(key, ttl_seconds, result.model_dump_json())

    async def close(self) -> None:
        await self._client.aclose()
