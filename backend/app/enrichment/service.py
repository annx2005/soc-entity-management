from __future__ import annotations

from app.entities.schemas import Entity, EntityType
from app.enrichment.cache import EnrichmentCache
from app.enrichment.providers import EnrichmentProvider
from app.enrichment.schemas import EnrichmentResult


ENRICHABLE_TYPES = {EntityType.IP, EntityType.FILE_HASH}


class EnrichmentService:
    def __init__(
        self,
        provider: EnrichmentProvider,
        *,
        cache: EnrichmentCache | None = None,
        ttl_seconds: int = 86400,
        enabled: bool = True,
    ) -> None:
        self._provider = provider
        self._cache = cache
        self._ttl_seconds = ttl_seconds
        self._enabled = enabled

    async def enrich_entities(self, tenant_id: str, entities: list[Entity]) -> list[Entity]:
        if not self._enabled:
            return entities
        enriched: list[Entity] = []
        for entity in entities:
            if entity.type not in ENRICHABLE_TYPES:
                enriched.append(entity)
                continue
            enriched.append(await self._enrich_entity(tenant_id, entity))
        return enriched

    async def _enrich_entity(self, tenant_id: str, entity: Entity) -> Entity:
        cache_key = enrichment_cache_key(tenant_id, entity.type.value, entity.value)
        cache_failed = False

        try:
            cached = await self._cache.get(cache_key) if self._cache else None
        except Exception as exc:
            cached = None
            cache_failed = True
            cache_error = str(exc)
        else:
            cache_error = None

        if cached is not None:
            return _with_enrichment(entity, cached.model_copy(update={"cache_status": "hit"}))

        try:
            result = await self._provider.lookup(entity.type, entity.value)
        except Exception as exc:
            return _with_enrichment_error(entity, str(exc))

        if result is None:
            return _with_enrichment_error(entity, cache_error) if cache_failed and cache_error else entity

        result = result.model_copy(update={"cache_status": "error" if cache_failed else "miss"})
        if self._cache is not None:
            try:
                await self._cache.set(cache_key, result, self._ttl_seconds)
            except Exception:
                pass
        return _with_enrichment(entity, result)


def enrichment_cache_key(tenant_id: str, entity_type: str, value: str) -> str:
    return f"enrichment:{tenant_id}:{entity_type}:{value}"


def _with_enrichment(entity: Entity, result: EnrichmentResult) -> Entity:
    properties = dict(entity.properties)
    properties["enrichment"] = {
        **result.data,
        "source": result.source,
        "cache_status": result.cache_status,
    }
    properties.pop("enrichment_error", None)
    properties.pop("enrichment_status", None)
    return entity.model_copy(update={"properties": properties})


def _with_enrichment_error(entity: Entity, message: str) -> Entity:
    properties = dict(entity.properties)
    properties["enrichment_status"] = "error"
    properties["enrichment_error"] = message
    return entity.model_copy(update={"properties": properties})
