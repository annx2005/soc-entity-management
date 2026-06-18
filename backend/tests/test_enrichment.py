from __future__ import annotations

import asyncio
from typing import Any

from app.entities.schemas import Entity, EntityType
from app.enrichment.providers import OfflineJsonEnrichmentProvider
from app.enrichment.schemas import EnrichmentResult
from app.enrichment.service import EnrichmentService, enrichment_cache_key


def test_offline_provider_ip_hit_and_miss(tmp_path) -> None:
    ip_path = tmp_path / "ip.json"
    hash_path = tmp_path / "hash.json"
    ip_path.write_text('{"8.8.8.8":{"country":"US","asn":"AS15169","provider":"offline-demo"}}', encoding="utf-8")
    hash_path.write_text("{}", encoding="utf-8")
    provider = OfflineJsonEnrichmentProvider(str(ip_path), str(hash_path))

    hit = provider.lookup(EntityType.IP, "8.8.8.8")
    miss = provider.lookup(EntityType.IP, "1.1.1.1")

    assert hit is not None
    assert hit.data["country"] == "US"
    assert hit.source == "offline-demo"
    assert miss is None


def test_offline_provider_file_hash_lookup_is_case_insensitive(tmp_path) -> None:
    ip_path = tmp_path / "ip.json"
    hash_path = tmp_path / "hash.json"
    ip_path.write_text("{}", encoding="utf-8")
    hash_path.write_text(
        '{"DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF":{"reputation":"malicious","provider":"offline-demo"}}',
        encoding="utf-8",
    )
    provider = OfflineJsonEnrichmentProvider(str(ip_path), str(hash_path))

    result = provider.lookup(EntityType.FILE_HASH, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

    assert result is not None
    assert result.data["reputation"] == "malicious"


def test_enrichment_service_cache_miss_calls_provider_and_sets_ttl() -> None:
    cache = FakeCache()
    provider = FakeProvider(
        {
            (EntityType.IP, "8.8.8.8"): {"country": "US", "asn": "AS15169", "provider": "offline-demo"},
        }
    )
    service = EnrichmentService(provider, cache=cache, ttl_seconds=123)
    entity = make_entity(EntityType.IP, "8.8.8.8", {"source_field": "dst_endpoint.ip", "version": 4})

    [enriched] = asyncio.run(service.enrich_entities("tenant-a", [entity]))

    expected_key = "enrichment:tenant-a:ip:8.8.8.8"
    assert enrichment_cache_key("tenant-a", "ip", "8.8.8.8") == expected_key
    assert provider.calls == [(EntityType.IP, "8.8.8.8")]
    assert cache.set_calls == [(expected_key, 123)]
    assert enriched.properties["source_field"] == "dst_endpoint.ip"
    assert enriched.properties["version"] == 4
    assert enriched.properties["enrichment"]["country"] == "US"
    assert enriched.properties["enrichment"]["cache_status"] == "miss"


def test_enrichment_service_cache_hit_skips_provider() -> None:
    cache = FakeCache(
        {
            "enrichment:tenant-a:file_hash:deadbeef": EnrichmentResult(
                entity_type="file_hash",
                value="deadbeef",
                data={"reputation": "malicious", "provider": "offline-demo"},
                source="offline-demo",
                cache_status="miss",
            )
        }
    )
    provider = FakeProvider({})
    service = EnrichmentService(provider, cache=cache)
    entity = make_entity(EntityType.FILE_HASH, "deadbeef", {"algorithm": "md5"})

    [enriched] = asyncio.run(service.enrich_entities("tenant-a", [entity]))

    assert provider.calls == []
    assert enriched.properties["algorithm"] == "md5"
    assert enriched.properties["enrichment"]["reputation"] == "malicious"
    assert enriched.properties["enrichment"]["cache_status"] == "hit"


def test_enrichment_service_only_enriches_ip_and_file_hash() -> None:
    provider = FakeProvider({(EntityType.IP, "8.8.8.8"): {"country": "US"}})
    service = EnrichmentService(provider)
    user = make_entity(EntityType.USER, "alice", {"source_field": "actor.user.name"})
    ip = make_entity(EntityType.IP, "8.8.8.8", {"source_field": "dst_endpoint.ip"})

    enriched = asyncio.run(service.enrich_entities("tenant-a", [user, ip]))

    assert provider.calls == [(EntityType.IP, "8.8.8.8")]
    assert "enrichment" not in enriched[0].properties
    assert enriched[1].properties["enrichment"]["country"] == "US"


def test_enrichment_service_gracefully_handles_cache_and_provider_errors() -> None:
    service = EnrichmentService(RaisingProvider(), cache=RaisingCache())
    entity = make_entity(EntityType.IP, "8.8.8.8", {"source_field": "dst_endpoint.ip"})

    [enriched] = asyncio.run(service.enrich_entities("tenant-a", [entity]))

    assert enriched.value == "8.8.8.8"
    assert enriched.properties["source_field"] == "dst_endpoint.ip"
    assert enriched.properties["enrichment_status"] == "error"
    assert "provider failed" in enriched.properties["enrichment_error"]


def make_entity(entity_type: EntityType, value: str, properties: dict[str, Any] | None = None) -> Entity:
    return Entity(
        id=f"{entity_type.value}:{value}",
        type=entity_type,
        value=value,
        tenant_id="tenant-a",
        first_seen="2026-07-02T14:50:00Z",
        last_seen="2026-07-02T14:50:00Z",
        source="unit_test",
        properties=properties or {},
    )


class FakeProvider:
    def __init__(self, results: dict[tuple[EntityType, str], dict[str, Any]]) -> None:
        self.results = results
        self.calls: list[tuple[EntityType, str]] = []

    def lookup(self, entity_type: EntityType, value: str) -> EnrichmentResult | None:
        self.calls.append((entity_type, value))
        data = self.results.get((entity_type, value))
        if data is None:
            return None
        return EnrichmentResult(
            entity_type=entity_type.value,
            value=value,
            data=data,
            source=str(data.get("provider") or "fake"),
            cache_status="miss",
        )


class FakeCache:
    def __init__(self, values: dict[str, EnrichmentResult] | None = None) -> None:
        self.values = values or {}
        self.set_calls: list[tuple[str, int]] = []

    async def get(self, key: str) -> EnrichmentResult | None:
        return self.values.get(key)

    async def set(self, key: str, result: EnrichmentResult, ttl_seconds: int) -> None:
        self.values[key] = result
        self.set_calls.append((key, ttl_seconds))


class RaisingProvider:
    def lookup(self, entity_type: EntityType, value: str) -> EnrichmentResult | None:
        raise RuntimeError("provider failed")


class RaisingCache:
    async def get(self, key: str) -> EnrichmentResult | None:
        raise RuntimeError("cache failed")

    async def set(self, key: str, result: EnrichmentResult, ttl_seconds: int) -> None:
        raise RuntimeError("cache failed")
