from __future__ import annotations

import asyncio
import uuid
from collections import defaultdict

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.entities import router as entities_router
from app.auth.dependencies import TenantContext, get_tenant_context
from app.entities import EntityType, extract_entities
from app.graph.constants import label_for_entity_type, validate_relationship_type
from app.graph.dependencies import get_graph_service
from app.graph.inference import infer_relationships
from app.graph.repository import _merge_properties
from app.graph.kafka_service import process_ocsf_event_message
from app.graph.schemas import EntityResponse, GraphResponse
from app.graph.service import GraphService
from app.ingestion.kafka_messages import OCSFEventMessage
from app.normalization.normalizer import normalize_event
from app.ocsf.schemas import OCSFEvent


TENANT_ID = "00000000-0000-0000-0000-000000000001"
OTHER_TENANT_ID = "00000000-0000-0000-0000-000000000002"


def base_record(event_id: str, eventdata: dict) -> dict:
    return {
        "id": "evt-graph-1",
        "tenant_id": "tenant-acme",
        "timestamp": "2026-07-02T14:50:01.005+0000",
        "agent": {"name": "Xuan-An", "ip": "192.168.0.119"},
        "data": {
            "win": {
                "system": {
                    "eventID": event_id,
                    "systemTime": "2026-07-02T14:50:00.000Z",
                    "computer": "Xuan-An",
                },
                "eventdata": eventdata,
            }
        },
    }


def test_graph_allowlists_reject_unknown_dynamic_values() -> None:
    assert label_for_entity_type(extract_entities(auth_event())[0].type) == "User"
    assert label_for_entity_type(EntityType.URL) == "URL"
    assert validate_relationship_type("LOGGED_IN_TO") == "LOGGED_IN_TO"

    with pytest.raises(ValueError):
        validate_relationship_type("MATCH (n) DETACH DELETE n")


def test_merge_properties_preserves_existing_values_and_unions_source_fields() -> None:
    merged = _merge_properties(
        {"source_field": "actor.user.email", "source_fields": ["actor.user.email"], "domain": "example.com"},
        {"source_field": "email.sender", "source_fields": ["email.sender"], "domain": None, "reputation": "known"},
    )

    assert merged == {
        "source_field": "actor.user.email",
        "source_fields": ["actor.user.email", "email.sender"],
        "domain": "example.com",
        "reputation": "known",
    }


def test_infer_network_relationships_uses_src_and_dst_ip_roles() -> None:
    event = normalize_event(
        base_record(
            "3",
            {
                "user": r"NT AUTHORITY\SYSTEM",
                "sourceIp": "172.20.208.1",
                "destinationIp": "224.0.0.251",
                "image": r"C:\Program Files\App\agent.exe",
            },
        )
    )
    entities = extract_entities(event)

    relationships = infer_relationships(event, entities)

    assert {relationship.relationship_type for relationship in relationships} == {"USED_IP", "CONNECTED_TO"}
    used_ip = next(relationship for relationship in relationships if relationship.relationship_type == "USED_IP")
    connected_to = next(relationship for relationship in relationships if relationship.relationship_type == "CONNECTED_TO")
    ip_by_id = {entity.id: entity.value for entity in entities}
    assert ip_by_id[used_ip.to_id] == "172.20.208.1"
    assert ip_by_id[connected_to.to_id] == "224.0.0.251"


def test_infer_all_initial_relationship_rules() -> None:
    success = auth_event("4624")
    failure = auth_event("4625")
    dns = normalize_event(
        base_record(
            "22",
            {
                "user": r"Xuan-An\XuanAn",
                "queryName": "GitHub.COM.",
                "queryResults": "::ffff:20.205.243.166;",
                "image": r"C:\Windows\System32\curl.exe",
            },
        )
    )
    process = normalize_event(
        base_record(
            "1",
            {
                "user": r"Xuan-An\XuanAn",
                "image": r"C:\Windows\System32\curl.exe",
                "commandLine": r'"C:\Windows\system32\curl.exe" https://github.com',
                "hashes": "SHA256=642A07EEEA4D3132426E673FB3C88BE8CEAD3D03CA1F019C7E7D0000ED2122BE",
            },
        )
    )

    assert [rel.relationship_type for rel in infer_relationships(success, extract_entities(success))] == [
        "LOGGED_IN_TO",
        "AUTHENTICATED_TO",
    ]
    assert [rel.relationship_type for rel in infer_relationships(failure, extract_entities(failure))] == [
        "FAILED_LOGON_TO",
        "ATTEMPTED_LOGON_TO",
    ]
    assert {rel.relationship_type for rel in infer_relationships(dns, extract_entities(dns))} == {"RESOLVED_DOMAIN", "RESOLVED_TO"}
    assert {rel.relationship_type for rel in infer_relationships(process, extract_entities(process))} == {"EXECUTED_ON", "HAS_HASH", "RAN_AS"}


def test_infer_auth_relationships_connect_source_ip_to_host() -> None:
    event = auth_event("4624")
    entities = extract_entities(event)

    relationships = infer_relationships(event, entities)

    authenticated_to = next(relationship for relationship in relationships if relationship.relationship_type == "AUTHENTICATED_TO")
    entity_by_id = {entity.id: entity for entity in entities}
    assert entity_by_id[authenticated_to.from_id].type.value == "ip"
    assert entity_by_id[authenticated_to.from_id].value == "127.0.0.1"
    assert entity_by_id[authenticated_to.to_id].type.value == "host"
    assert entity_by_id[authenticated_to.to_id].value == "xuan-an"


def test_graph_service_is_idempotent_with_unique_event_evidence() -> None:
    event = auth_event()
    repo = FakeGraphRepository()
    service = GraphService(repo)

    first = asyncio.run(service.process_event(event))
    second = asyncio.run(service.process_event(event))

    assert first.entities == second.entities
    assert len(repo.events) == 1
    assert len(repo.entities) == first.entities
    assert len(repo.observations) == first.observations
    assert len(repo.relationship_facts) == 2
    assert all(fact["count"] == 1 for fact in repo.relationship_facts.values())


def test_graph_service_enriches_entities_before_upsert_and_keeps_relationship_inference() -> None:
    event = normalize_event(
        base_record(
            "3",
            {
                "user": r"NT AUTHORITY\SYSTEM",
                "sourceIp": "172.20.208.1",
                "destinationIp": "8.8.8.8",
                "image": r"C:\Program Files\App\agent.exe",
            },
        )
    )
    repo = FakeGraphRepository()
    service = GraphService(repo, enrichment_service=FakeEnrichmentService())

    result = asyncio.run(service.process_event(event))

    ip_entities = [entity for entity in repo.entities.values() if entity.type.value == "ip"]
    destination_ip = next(entity for entity in ip_entities if entity.value == "8.8.8.8")
    assert destination_ip.properties["source_field"] == "dst_endpoint.ip"
    assert destination_ip.properties["enrichment"]["country"] == "US"
    assert result.relationships == 2


def test_graph_service_caps_unique_sample_evidence_refs() -> None:
    repo = FakeGraphRepository()
    service = GraphService(repo)

    for index in range(60):
        event = auth_event()
        event.event_id = f"evt-{index:03d}"
        asyncio.run(service.process_event(event))

    assert len(repo.relationship_facts) == 2
    for fact in repo.relationship_facts.values():
        assert fact["count"] == 60
        assert len(fact["sample_evidence_refs"]) == 50
        assert fact["sample_evidence_refs"][0] == "evt-010"
        assert fact["sample_evidence_refs"][-1] == "evt-059"


def test_graph_service_audits_entity_and_relationship_upserts() -> None:
    event = auth_event()
    repo = FakeGraphRepository()
    audit = FakeAuditLogger()
    service = GraphService(repo, audit_logger=audit)

    asyncio.run(service.process_event(event))
    asyncio.run(service.process_event(event))

    actions = [entry["action"] for entry in audit.entries]
    assert "entity_created" in actions
    assert "entity_updated" in actions
    assert "relationship_created" in actions
    assert "relationship_updated" in actions
    assert all(entry["tenant_id"] == event.tenant_id for entry in audit.entries)


def test_process_ocsf_event_message_runs_graph_flow() -> None:
    event = auth_event()
    message = OCSFEventMessage(
        source_message_id="raw-1",
        batch_id=1,
        event_id=event.event_id,
        tenant_id=event.tenant_id,
        class_uid=event.class_uid,
        class_name=event.class_name,
        activity_id=event.activity_id,
        activity_name=event.activity_name,
        ocsf_event=event.model_dump(mode="json"),
    )
    repo = FakeGraphRepository()
    service = GraphService(repo)

    result = asyncio.run(process_ocsf_event_message(message, service))

    assert result.status == "processed"
    assert len(repo.events) == 1


def test_entities_api_uses_tenant_context_and_returns_404_cross_tenant() -> None:
    client = graph_test_client(
        FakeApiGraphService(
            entities={
                TENANT_ID: {
                    "entity-a": EntityResponse(
                        id="entity-a",
                        tenant_id=TENANT_ID,
                        entity_type="ip",
                        value="1.2.3.4",
                    )
                }
            }
        )
    )

    list_response = client.get("/api/entities", headers={"Authorization": "Bearer test"})
    detail_response = client.get("/api/entities/entity-a", headers={"Authorization": "Bearer test"})
    cross_tenant_response = client.get("/api/entities/entity-b", headers={"Authorization": "Bearer test"})

    assert list_response.status_code == 200
    assert list_response.json()[0]["id"] == "entity-a"
    assert detail_response.status_code == 200
    assert cross_tenant_response.status_code == 404


def test_entities_api_list_omits_entities_from_other_tenants() -> None:
    client = graph_test_client(
        FakeApiGraphService(
            entities={
                TENANT_ID: {
                    "entity-a": EntityResponse(
                        id="entity-a",
                        tenant_id=TENANT_ID,
                        entity_type="ip",
                        value="1.2.3.4",
                    )
                },
                OTHER_TENANT_ID: {
                    "entity-b": EntityResponse(
                        id="entity-b",
                        tenant_id=OTHER_TENANT_ID,
                        entity_type="host",
                        value="workstation-b",
                    )
                },
            }
        )
    )

    response = client.get("/api/entities", headers={"Authorization": "Bearer test"})

    assert response.status_code == 200
    assert [item["id"] for item in response.json()] == ["entity-a"]


@pytest.mark.parametrize(
    ("path", "expected_status"),
    [
        ("/api/entities/entity-a/relationships", 200),
        ("/api/entities/entity-a/evidence", 200),
        ("/api/graph/entity-a", 200),
        ("/api/entities/entity-b/relationships", 404),
        ("/api/entities/entity-b/evidence", 404),
        ("/api/graph/entity-b", 404),
    ],
)
def test_entity_subresources_enforce_tenant_isolation(path: str, expected_status: int) -> None:
    client = graph_test_client(
        FakeApiGraphService(
            entities={
                TENANT_ID: {
                    "entity-a": EntityResponse(
                        id="entity-a",
                        tenant_id=TENANT_ID,
                        entity_type="ip",
                        value="1.2.3.4",
                    )
                },
                OTHER_TENANT_ID: {
                    "entity-b": EntityResponse(
                        id="entity-b",
                        tenant_id=OTHER_TENANT_ID,
                        entity_type="host",
                        value="workstation-b",
                    )
                },
            }
        )
    )

    response = client.get(path, headers={"Authorization": "Bearer test"})

    assert response.status_code == expected_status


@pytest.mark.parametrize("hops", [3, 4])
def test_graph_api_accepts_multi_hop_depth(hops: int) -> None:
    graph_service = FakeApiGraphService(
        entities={
            TENANT_ID: {
                "entity-a": EntityResponse(
                    id="entity-a",
                    tenant_id=TENANT_ID,
                    entity_type="ip",
                    value="1.2.3.4",
                )
            }
        }
    )
    client = graph_test_client(graph_service)

    response = client.get(f"/api/graph/entity-a?hops={hops}", headers={"Authorization": "Bearer test"})

    assert response.status_code == 200
    assert graph_service.graph_calls[-1]["hops"] == hops


def test_graph_api_rejects_too_many_hops() -> None:
    graph_service = FakeApiGraphService(
        entities={
            TENANT_ID: {
                "entity-a": EntityResponse(
                    id="entity-a",
                    tenant_id=TENANT_ID,
                    entity_type="ip",
                    value="1.2.3.4",
                )
            }
        }
    )
    client = graph_test_client(graph_service)

    response = client.get("/api/graph/entity-a?hops=5", headers={"Authorization": "Bearer test"})

    assert response.status_code == 422


def test_graph_path_api_returns_graph_response() -> None:
    graph_service = FakeApiGraphService(
        entities={
            TENANT_ID: {
                "entity-a": EntityResponse(
                    id="entity-a",
                    tenant_id=TENANT_ID,
                    entity_type="user",
                    value="alice",
                ),
                "entity-b": EntityResponse(
                    id="entity-b",
                    tenant_id=TENANT_ID,
                    entity_type="domain",
                    value="example.com",
                ),
            }
        }
    )
    client = graph_test_client(graph_service)

    response = client.get(
        "/api/graph/path?source_id=entity-a&target_id=entity-b&max_hops=4",
        headers={"Authorization": "Bearer test"},
    )

    assert response.status_code == 200
    assert response.json() == {"nodes": [], "edges": []}
    assert graph_service.path_calls[-1]["source_id"] == "entity-a"
    assert graph_service.path_calls[-1]["target_id"] == "entity-b"
    assert graph_service.path_calls[-1]["max_hops"] == 4


@pytest.mark.parametrize(
    ("source_id", "target_id"),
    [
        ("entity-a", "entity-b"),
        ("entity-b", "entity-a"),
    ],
)
def test_graph_path_api_returns_404_for_cross_tenant_endpoint(source_id: str, target_id: str) -> None:
    graph_service = FakeApiGraphService(
        entities={
            TENANT_ID: {
                "entity-a": EntityResponse(
                    id="entity-a",
                    tenant_id=TENANT_ID,
                    entity_type="ip",
                    value="1.2.3.4",
                )
            },
            OTHER_TENANT_ID: {
                "entity-b": EntityResponse(
                    id="entity-b",
                    tenant_id=OTHER_TENANT_ID,
                    entity_type="host",
                    value="workstation-b",
                )
            },
        }
    )
    client = graph_test_client(graph_service)

    response = client.get(
        f"/api/graph/path?source_id={source_id}&target_id={target_id}",
        headers={"Authorization": "Bearer test"},
    )

    assert response.status_code == 404


def test_graph_path_api_rejects_platform_scope() -> None:
    client = graph_test_client(FakeApiGraphService(), platform=True)

    response = client.get(
        "/api/graph/path?source_id=entity-a&target_id=entity-b",
        headers={"Authorization": "Bearer test"},
    )

    assert response.status_code == 403


def test_entities_api_rejects_platform_scope() -> None:
    client = graph_test_client(FakeApiGraphService(), platform=True)

    response = client.get("/api/entities", headers={"Authorization": "Bearer test"})

    assert response.status_code == 403


def auth_event(event_id: str = "4624") -> OCSFEvent:
    process_name = r"C:\Windows\System32\services.exe" if event_id == "4624" else r"C:\Windows\System32\svchost.exe"
    return normalize_event(
        base_record(
            event_id,
            {"targetUserName": "XuanAn", "ipAddress": "127.0.0.1", "processName": process_name},
        )
    )


class FakeGraphRepository:
    def __init__(self) -> None:
        self.events: dict[str, OCSFEvent] = {}
        self.entities = {}
        self.observations = set()
        self.relationship_facts = {}
        self.evidence_links = defaultdict(set)

    async def ensure_schema(self) -> None:
        return None

    async def upsert_event(self, event: OCSFEvent) -> str:
        self.events[event.event_id] = event
        return event.event_id

    async def upsert_entity(self, entity) -> None:
        status = "updated" if entity.id in self.entities else "created"
        self.entities[entity.id] = entity
        return status

    async def upsert_observation(self, event: OCSFEvent, entity) -> str:
        field_path = entity.properties.get("source_field") or "unknown"
        key = (event.tenant_id, event.event_id, entity.id, field_path)
        self.observations.add(key)
        return ":".join(key)

    async def upsert_relationship(self, tenant_id: str, candidate) -> None:
        fact_key = (tenant_id, candidate.relationship_type, candidate.from_id, candidate.to_id)
        status = "updated" if fact_key in self.relationship_facts else "created"
        fact = self.relationship_facts.setdefault(
            fact_key,
            {"count": 0, "sample_evidence_refs": []},
        )
        if candidate.evidence_ref in self.evidence_links[fact_key]:
            return status
        self.evidence_links[fact_key].add(candidate.evidence_ref)
        fact["count"] += 1
        fact["sample_evidence_refs"] = (fact["sample_evidence_refs"] + [candidate.evidence_ref])[-50:]
        return status


class FakeEnrichmentService:
    async def enrich_entities(self, tenant_id: str, entities):
        enriched = []
        for entity in entities:
            if entity.type.value == "ip" and entity.value == "8.8.8.8":
                properties = dict(entity.properties)
                properties["enrichment"] = {"country": "US", "asn": "AS15169", "cache_status": "miss"}
                enriched.append(entity.model_copy(update={"properties": properties}))
            else:
                enriched.append(entity)
        return enriched


class FakeAuditLogger:
    def __init__(self) -> None:
        self.entries = []

    def record(self, **kwargs) -> None:
        self.entries.append(kwargs)


class FakeApiGraphService:
    def __init__(self, entities: dict[str, dict[str, EntityResponse]] | None = None) -> None:
        self.entities = entities or {}
        self.graph_calls = []
        self.path_calls = []

    async def list_entities(self, tenant_id: str, entity_type: str | None = None, value: str | None = None, limit: int = 100, offset: int = 0):
        return list(self.entities.get(tenant_id, {}).values())[offset : offset + limit]

    async def get_entity(self, tenant_id: str, entity_id: str):
        return self.entities.get(tenant_id, {}).get(entity_id)

    async def list_relationships(self, tenant_id: str, entity_id: str, limit: int = 100):
        return []

    async def list_evidence(self, tenant_id: str, entity_id: str, limit: int = 100):
        return []

    async def get_graph(self, tenant_id: str, entity_id: str, hops: int = 1, limit: int = 200):
        self.graph_calls.append({"tenant_id": tenant_id, "entity_id": entity_id, "hops": hops, "limit": limit})
        return GraphResponse(nodes=[], edges=[])

    async def find_path(self, tenant_id: str, source_id: str, target_id: str, max_hops: int = 4, limit: int = 50):
        self.path_calls.append(
            {"tenant_id": tenant_id, "source_id": source_id, "target_id": target_id, "max_hops": max_hops, "limit": limit}
        )
        return GraphResponse(nodes=[], edges=[])


def graph_test_client(graph_service: FakeApiGraphService, *, platform: bool = False) -> TestClient:
    app = FastAPI()
    app.include_router(entities_router)

    def override_context() -> TenantContext:
        return TenantContext(
            account_id=uuid.uuid4(),
            tenant_id=None if platform else uuid.UUID(TENANT_ID),
            tenant_slug=None if platform else "tenant-a",
            email="analyst@example.com",
            role="analyst",
            scope="platform" if platform else "tenant",
        )

    def override_graph_service() -> FakeApiGraphService:
        return graph_service

    app.dependency_overrides[get_tenant_context] = override_context
    app.dependency_overrides[get_graph_service] = override_graph_service
    return TestClient(app)
