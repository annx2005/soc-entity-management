from __future__ import annotations

import asyncio
from typing import Any

import httpx
from prometheus_client import REGISTRY, generate_latest

from app.entities.schemas import Entity, EntityType
from app.enrichment.providers import (
    CompositeEnrichmentProvider,
    IpinfoLiteEnrichmentProvider,
    MalwareBazaarEnrichmentProvider,
    OfflineJsonEnrichmentProvider,
)
from app.enrichment.schemas import EnrichmentResult
from app.enrichment.service import EnrichmentService, enrichment_cache_key


def test_offline_provider_ip_hit_and_miss(tmp_path) -> None:
    ip_path = tmp_path / "ip.json"
    hash_path = tmp_path / "hash.json"
    ip_path.write_text('{"8.8.8.8":{"country":"US","asn":"AS15169","provider":"offline-demo"}}', encoding="utf-8")
    hash_path.write_text("{}", encoding="utf-8")
    provider = OfflineJsonEnrichmentProvider(str(ip_path), str(hash_path))

    hit = asyncio.run(provider.lookup(EntityType.IP, "8.8.8.8"))
    miss = asyncio.run(provider.lookup(EntityType.IP, "1.1.1.1"))

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

    result = asyncio.run(provider.lookup(EntityType.FILE_HASH, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))

    assert result is not None
    assert result.data["reputation"] == "malicious"


def test_ipinfo_lite_provider_maps_country_and_asn() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/lite/8.8.8.8"
        assert request.url.params["token"] == "ipinfo-token"
        return httpx.Response(
            200,
            json={
                "ip": "8.8.8.8",
                "country": "United States",
                "country_code": "US",
                "asn": "AS15169",
                "as_name": "Google LLC",
                "as_domain": "google.com",
                "continent": "North America",
                "continent_code": "NA",
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = IpinfoLiteEnrichmentProvider(token="ipinfo-token", client=client)

    try:
        result = asyncio.run(provider.lookup(EntityType.IP, "8.8.8.8"))
    finally:
        asyncio.run(client.aclose())

    assert result is not None
    assert result.source == "ipinfo-lite"
    assert result.data["country"] == "United States"
    assert result.data["asn"] == "AS15169"


def test_malware_bazaar_provider_maps_signature_to_malware_family() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        body = request.content.decode("utf-8")
        assert request.method == "POST"
        assert request.headers["Auth-Key"] == "mb-key"
        assert "query=get_info" in body
        assert "hash=deadbeef" in body
        return httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [
                    {
                        "sha256_hash": "deadbeef",
                        "file_name": "sample.exe",
                        "file_type": "exe",
                        "signature": "Remcos",
                        "tags": ["rat"],
                    }
                ],
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = MalwareBazaarEnrichmentProvider(auth_key="mb-key", client=client)

    try:
        result = asyncio.run(provider.lookup(EntityType.FILE_HASH, "deadbeef"))
    finally:
        asyncio.run(client.aclose())

    assert result is not None
    assert result.source == "malwarebazaar"
    assert result.data["malware_family"] == "Remcos"
    assert result.data["file_name"] == "sample.exe"


def test_composite_provider_delegates_to_matching_provider() -> None:
    composite = CompositeEnrichmentProvider(
        [
            FakeProvider({(EntityType.IP, "8.8.8.8"): {"country": "US", "provider": "ipinfo-lite"}}),
            FakeProvider({(EntityType.FILE_HASH, "deadbeef"): {"malware_family": "Remcos", "provider": "malwarebazaar"}}),
        ]
    )

    ip_result = asyncio.run(composite.lookup(EntityType.IP, "8.8.8.8"))
    hash_result = asyncio.run(composite.lookup(EntityType.FILE_HASH, "deadbeef"))

    assert ip_result is not None
    assert ip_result.source == "ipinfo-lite"
    assert hash_result is not None
    assert hash_result.source == "malwarebazaar"


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


def test_enrichment_service_records_prometheus_metrics() -> None:
    service = EnrichmentService(FakeProvider({(EntityType.IP, "9.9.9.9"): {"country": "US"}}))
    entity = make_entity(EntityType.IP, "9.9.9.9", {"source_field": "dst_endpoint.ip"})

    asyncio.run(service.enrich_entities("tenant-a", [entity]))

    output = generate_latest(REGISTRY).decode("utf-8")
    assert "soc_enrichment_requests_total" in output
    assert 'entity_type="ip"' in output
    assert 'cache_status="miss"' in output
    assert 'outcome="success"' in output


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

    async def lookup(self, entity_type: EntityType, value: str) -> EnrichmentResult | None:
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
    async def lookup(self, entity_type: EntityType, value: str) -> EnrichmentResult | None:
        raise RuntimeError("provider failed")


class RaisingCache:
    async def get(self, key: str) -> EnrichmentResult | None:
        raise RuntimeError("cache failed")

    async def set(self, key: str, result: EnrichmentResult, ttl_seconds: int) -> None:
        raise RuntimeError("cache failed")
