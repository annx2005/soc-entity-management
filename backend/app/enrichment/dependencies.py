from __future__ import annotations

from collections.abc import Awaitable
from collections.abc import AsyncGenerator

from app.core.config import get_settings
from app.enrichment.cache import RedisEnrichmentCache
from app.enrichment.providers import (
    CompositeEnrichmentProvider,
    IpinfoLiteEnrichmentProvider,
    MalwareBazaarEnrichmentProvider,
    OfflineJsonEnrichmentProvider,
)
from app.enrichment.service import EnrichmentService


async def get_enrichment_service() -> AsyncGenerator[EnrichmentService, None]:
    settings = get_settings()
    cache = RedisEnrichmentCache(settings.redis_url)
    provider = make_enrichment_provider()
    try:
        yield EnrichmentService(
            provider,
            cache=cache,
            ttl_seconds=settings.enrichment_cache_ttl_seconds,
            enabled=settings.enrichment_enabled,
        )
    finally:
        await close_enrichment_provider(provider)
        await cache.close()


def make_enrichment_provider():
    settings = get_settings()
    if settings.enrichment_provider_mode == "ipinfo_malwarebazaar":
        return CompositeEnrichmentProvider(
            [
                IpinfoLiteEnrichmentProvider(
                    token=settings.enrichment_ipinfo_token,
                    base_url=settings.enrichment_ipinfo_base_url,
                    timeout_seconds=settings.enrichment_http_timeout_seconds,
                ),
                MalwareBazaarEnrichmentProvider(
                    auth_key=settings.enrichment_malware_bazaar_auth_key,
                    base_url=settings.enrichment_malware_bazaar_url,
                    timeout_seconds=settings.enrichment_http_timeout_seconds,
                ),
            ]
        )
    return OfflineJsonEnrichmentProvider(
        settings.enrichment_ip_source_path,
        settings.enrichment_file_hash_source_path,
    )


async def close_enrichment_provider(provider: object) -> None:
    close = getattr(provider, "close", None)
    if callable(close):
        result = close()
        if isinstance(result, Awaitable):
            await result
