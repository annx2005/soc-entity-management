from __future__ import annotations

import asyncio
import os

import pytest
from neo4j import AsyncGraphDatabase

from app.graph.repository import GraphRepository
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
    finally:
        await _delete_test_tenant(driver, tenant_id)
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
