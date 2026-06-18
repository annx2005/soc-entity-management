from __future__ import annotations

from collections.abc import AsyncGenerator

from app.core.config import get_settings
from app.enrichment.cache import RedisEnrichmentCache
from app.enrichment.providers import OfflineJsonEnrichmentProvider
from app.enrichment.service import EnrichmentService


async def get_enrichment_service() -> AsyncGenerator[EnrichmentService, None]:
    settings = get_settings()
    cache = RedisEnrichmentCache(settings.redis_url)
    provider = OfflineJsonEnrichmentProvider(
        settings.enrichment_ip_source_path,
        settings.enrichment_file_hash_source_path,
    )
    try:
        yield EnrichmentService(
            provider,
            cache=cache,
            ttl_seconds=settings.enrichment_cache_ttl_seconds,
            enabled=settings.enrichment_enabled,
        )
    finally:
        await cache.close()
