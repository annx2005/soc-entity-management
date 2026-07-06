from __future__ import annotations

import asyncio
import os

import pytest
from neo4j import AsyncGraphDatabase

from app.entities.schemas import Entity, EntityType
from app.graph.repository import GraphRepository
from app.graph.schemas import GraphQueryFilters, RelationshipCandidate
from app.graph.service import GraphService
from app.normalization.normalizer import normalize_event


def test_graph_repository_against_neo4j_when_configured() -> None:
    uri = os.getenv("NEO4J_TEST_URI")
    if not uri:
        pytest.skip("set NEO4J_TEST_URI to run Neo4j integration tests")

    asyncio.run(_run_graph_repository_integration(uri))


async def _run_graph_repository_integration(uri: str) -> None:
    user = os.getenv("NEO4J_TEST_USER", "neo4j")
    password = os.getenv("NEO4J_TEST_PASSWORD", "neo4j_password")
    tenant_id = "tenant-integration-graph"
    driver = AsyncGraphDatabase.driver(uri, auth=(user, password))
    repo = GraphRepository(driver)
    service = GraphService(repo)
    event = normalize_event(
        {
            "id": "evt-graph-integration-1",
            "tenant_id": tenant_id,
            "timestamp": "2026-07-02T14:50:01.005+0000",
            "agent": {"name": "Xuan-An", "ip": "192.168.0.119"},
            "data": {
                "win": {
                    "system": {
                        "eventID": "4624",
                        "systemTime": "2026-07-02T14:50:00.000Z",
                        "computer": "Xuan-An",
                    },
                    "eventdata": {
                        "targetUserName": "XuanAn",
                        "ipAddress": "127.0.0.1",
                        "processName": r"C:\Windows\System32\services.exe",
                    },
                }
            },
        }
    )

    try:
        await _delete_test_tenant(driver, tenant_id)
        await service.process_event(event)
        await service.process_event(event)

        entities = await service.list_entities(tenant_id, limit=100)
        user = next(entity for entity in entities if entity.entity_type == "user")
        relationships = await service.list_relationships(tenant_id, user.id)

        assert len(entities) == 4
        assert len(relationships) == 1
        assert relationships[0].relationship_type == "LOGGED_IN_TO"
        assert relationships[0].count == 1

        await _seed_entity_chain(repo, event)
        graph = await service.get_graph(tenant_id, "chain-user", hops=3, limit=50)
        path = await service.find_path(tenant_id, "chain-user", "chain-domain", max_hops=4, limit=10)
        cross_tenant_path = await service.find_path(tenant_id, "chain-user", "other-tenant-domain", max_hops=4, limit=10)
        filtered_graph = await service.get_graph(
            tenant_id,
            "chain-host",
            hops=1,
            limit=10,
            filters=GraphQueryFilters(relationship_types=["USED_IP"]),
        )
        filtered_time_graph = await service.get_graph(
            tenant_id,
            "chain-host",
            hops=1,
            limit=10,
            filters=GraphQueryFilters(from_time="2026-07-03T00:00:00Z"),
        )

        graph_entity_ids = {node.properties["id"] for node in graph.nodes}
        path_entity_ids = {node.properties["id"] for node in path.nodes}
        filtered_entity_ids = {node.properties["id"] for node in filtered_graph.nodes}
        assert "chain-domain" in graph_entity_ids
        assert path_entity_ids == {"chain-user", "chain-host", "chain-ip", "chain-domain"}
        assert len(path.edges) == 3
        assert cross_tenant_path.nodes == []
        assert cross_tenant_path.edges == []
        assert filtered_entity_ids == {"chain-host", "chain-ip"}
        assert [edge.type for edge in filtered_graph.edges] == ["USED_IP"]
        assert filtered_time_graph.nodes == []
        assert filtered_time_graph.edges == []
    finally:
        await _delete_test_tenant(driver, tenant_id)
        await _delete_test_tenant(driver, "tenant-integration-other")
        await driver.close()


async def _delete_test_tenant(driver, tenant_id: str) -> None:
    async with driver.session() as session:
        await session.run(
            """
            MATCH (n)
            WHERE n.tenant_id = $tenant_id
            DETACH DELETE n
            """,
            tenant_id=tenant_id,
        )


async def _seed_entity_chain(repo: GraphRepository, event) -> None:
    observed_at = "2026-07-02T14:50:00Z"
    entities = [
        Entity(
            id="chain-user",
            type=EntityType.USER,
            value="chain-user",
            tenant_id=event.tenant_id,
            first_seen=observed_at,
            last_seen=observed_at,
            source="integration-test",
        ),
        Entity(
            id="chain-host",
            type=EntityType.HOST,
            value="chain-host",
            tenant_id=event.tenant_id,
            first_seen=observed_at,
            last_seen=observed_at,
            source="integration-test",
        ),
        Entity(
            id="chain-ip",
            type=EntityType.IP,
            value="10.20.30.40",
            tenant_id=event.tenant_id,
            first_seen=observed_at,
            last_seen=observed_at,
            source="integration-test",
        ),
        Entity(
            id="chain-domain",
            type=EntityType.DOMAIN,
            value="chain.example",
            tenant_id=event.tenant_id,
            first_seen=observed_at,
            last_seen=observed_at,
            source="integration-test",
        ),
        Entity(
            id="other-tenant-domain",
            type=EntityType.DOMAIN,
            value="other.example",
            tenant_id="tenant-integration-other",
            first_seen=observed_at,
            last_seen=observed_at,
            source="integration-test",
        ),
    ]
    for entity in entities:
        await repo.upsert_entity(entity)

    candidates = [
        RelationshipCandidate(
            relationship_type="LOGGED_IN_TO",
            from_id="chain-user",
            to_id="chain-host",
            evidence_ref=event.event_id,
            observed_at=observed_at,
        ),
        RelationshipCandidate(
            relationship_type="USED_IP",
            from_id="chain-host",
            to_id="chain-ip",
            evidence_ref=event.event_id,
            observed_at=observed_at,
        ),
        RelationshipCandidate(
            relationship_type="RESOLVED_TO",
            from_id="chain-ip",
            to_id="chain-domain",
            evidence_ref=event.event_id,
            observed_at=observed_at,
        ),
    ]
    for candidate in candidates:
        await repo.upsert_relationship(event.tenant_id, candidate)
