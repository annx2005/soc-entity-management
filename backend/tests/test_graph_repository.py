"""Unit tests for GraphRepository using a mock Neo4j driver.

These tests cover the core query logic of GraphRepository without requiring a
live Neo4j instance. They mock the driver/session at the lowest level so the
actual Cypher-parameter assembly, result mapping, and branching paths are all
exercised.
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.entities.schemas import Entity, EntityType
from app.graph.repository import (
    GraphRepository,
    _is_private_ip,
    _merge_properties,
    _merge_unique_strings,
    _promoted_properties,
)
from app.graph.schemas import RelationshipCandidate
from app.ocsf.schemas import OCSFEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TENANT = "tenant-unit"
OBS_TIME = "2026-07-07T00:00:00Z"


def _make_entity(
    entity_id: str = "entity-1",
    entity_type: EntityType = EntityType.IP,
    value: str = "1.2.3.4",
    properties: dict[str, Any] | None = None,
) -> Entity:
    return Entity(
        id=entity_id,
        type=entity_type,
        value=value,
        tenant_id=TENANT,
        first_seen=OBS_TIME,
        last_seen=OBS_TIME,
        source="unit-test",
        properties=properties or {},
    )


def _make_event(event_id: str = "evt-1") -> OCSFEvent:
    return OCSFEvent(
        metadata={"version": "1.2.0"},
        time=1783000000000,
        class_uid=1002,
        class_name="Authentication",
        category_uid=3,
        category_name="Identity & Access Management",
        activity_id=1,
        activity_name="Logon",
        type_uid=100201,
        type_name="Authentication: Logon",
        tenant_id=TENANT,
        event_id=event_id,
        source_name="wazuh",
        raw_data={},
    )


def _empty_async_iter():
    """Return an async iterable that yields nothing."""
    async def _gen(self):
        return
        yield
    return _gen


def _make_mock_session_with_single(record: dict | None):
    """Mock driver/session where .run().single() returns one record."""
    mock_result = AsyncMock()
    mock_result.single = AsyncMock(return_value=record)
    mock_result.__aiter__ = _empty_async_iter()

    mock_session = AsyncMock()
    mock_session.run = AsyncMock(return_value=mock_result)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    mock_driver = MagicMock()
    mock_driver.session = MagicMock(return_value=mock_session)
    return mock_driver, mock_session


def _make_mock_session_empty_iter():
    """Mock driver/session where .run() returns an empty async iterator."""
    mock_result = AsyncMock()
    mock_result.__aiter__ = _empty_async_iter()

    mock_session = AsyncMock()
    mock_session.run = AsyncMock(return_value=mock_result)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    mock_driver = MagicMock()
    mock_driver.session = MagicMock(return_value=mock_session)
    return mock_driver, mock_session


# ---------------------------------------------------------------------------
# ensure_schema
# ---------------------------------------------------------------------------


def test_ensure_schema_runs_all_statements() -> None:
    mock_driver, mock_session = _make_mock_session_empty_iter()
    repo = GraphRepository(mock_driver)

    asyncio.run(repo.ensure_schema())

    # 16 DDL statements defined in ensure_schema
    assert mock_session.run.call_count == 16


# ---------------------------------------------------------------------------
# upsert_event
# ---------------------------------------------------------------------------


def test_upsert_event_returns_graph_id() -> None:
    event = _make_event("evt-upsert")
    mock_driver, mock_session = _make_mock_session_with_single({"id": f"{TENANT}:evt-upsert"})
    repo = GraphRepository(mock_driver)

    result = asyncio.run(repo.upsert_event(event))

    assert result == f"{TENANT}:evt-upsert"
    call_kwargs = mock_session.run.call_args.kwargs
    assert call_kwargs["event_id"] == "evt-upsert"
    assert call_kwargs["tenant_id"] == TENANT


def test_upsert_events_returns_empty_for_empty_list() -> None:
    mock_driver, _ = _make_mock_session_empty_iter()

    result = asyncio.run(GraphRepository(mock_driver).upsert_events([]))

    assert result == {}


def test_upsert_events_passes_all_rows() -> None:
    events = [_make_event("evt-a"), _make_event("evt-b")]

    async def fake_aiter(self):
        yield {"event_id": "evt-a", "id": f"{TENANT}:evt-a"}
        yield {"event_id": "evt-b", "id": f"{TENANT}:evt-b"}

    mock_result = AsyncMock()
    mock_result.__aiter__ = fake_aiter

    mock_session = AsyncMock()
    mock_session.run = AsyncMock(return_value=mock_result)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    mock_driver = MagicMock()
    mock_driver.session = MagicMock(return_value=mock_session)

    result = asyncio.run(GraphRepository(mock_driver).upsert_events(events))

    assert "evt-a" in result
    assert "evt-b" in result
    rows_arg = mock_session.run.call_args.kwargs["rows"]
    assert len(rows_arg) == 2


# ---------------------------------------------------------------------------
# upsert_entity
# ---------------------------------------------------------------------------


def test_upsert_entity_returns_created_status() -> None:
    entity = _make_entity()
    mock_driver, mock_session = _make_mock_session_with_single({"status": "created"})

    with patch.object(GraphRepository, "_merged_entity_properties", new=AsyncMock(return_value={})):
        result = asyncio.run(GraphRepository(mock_driver).upsert_entity(entity))

    assert result == "created"


def test_upsert_entity_returns_updated_status() -> None:
    entity = _make_entity()
    mock_driver, mock_session = _make_mock_session_with_single({"status": "updated"})

    with patch.object(GraphRepository, "_merged_entity_properties", new=AsyncMock(return_value={})):
        result = asyncio.run(GraphRepository(mock_driver).upsert_entity(entity))

    assert result == "updated"


def test_upsert_entities_returns_empty_for_empty_list() -> None:
    mock_driver, _ = _make_mock_session_empty_iter()

    result = asyncio.run(GraphRepository(mock_driver).upsert_entities([]))

    assert result == {}


# ---------------------------------------------------------------------------
# upsert_observation / upsert_observations
# ---------------------------------------------------------------------------


def test_upsert_observation_returns_id() -> None:
    event = _make_event()
    entity = _make_entity(properties={"source_field": "src_endpoint.ip"})
    mock_driver, mock_session = _make_mock_session_with_single({"id": "obs-abc"})

    result = asyncio.run(GraphRepository(mock_driver).upsert_observation(event, entity))

    assert result == "obs-abc"
    call_kwargs = mock_session.run.call_args.kwargs
    assert call_kwargs["field_path"] == "src_endpoint.ip"
    assert call_kwargs["entity_id"] == entity.id


def test_upsert_observation_uses_unknown_when_source_field_missing() -> None:
    event = _make_event()
    entity = _make_entity()  # no source_field
    mock_driver, mock_session = _make_mock_session_with_single({"id": "obs-xyz"})

    asyncio.run(GraphRepository(mock_driver).upsert_observation(event, entity))

    assert mock_session.run.call_args.kwargs["field_path"] == "unknown"


def test_upsert_observations_returns_empty_for_empty_list() -> None:
    mock_driver, _ = _make_mock_session_empty_iter()

    result = asyncio.run(GraphRepository(mock_driver).upsert_observations([]))

    assert result == []


# ---------------------------------------------------------------------------
# upsert_relationship / upsert_relationships
# ---------------------------------------------------------------------------


def test_upsert_relationship_returns_created() -> None:
    event = _make_event()
    candidate = RelationshipCandidate(
        relationship_type="LOGGED_IN_TO",
        from_id="user-1",
        to_id="host-1",
        evidence_ref=event.event_id,
        observed_at=OBS_TIME,
    )
    mock_driver, mock_session = _make_mock_session_with_single({"status": "created"})

    result = asyncio.run(GraphRepository(mock_driver).upsert_relationship(TENANT, candidate))

    assert result == "created"


def test_upsert_relationship_rejects_invalid_type() -> None:
    from app.graph.constants import validate_relationship_type

    with pytest.raises(ValueError):
        validate_relationship_type("DROP ALL DATA")


def test_upsert_relationships_returns_empty_for_empty_list() -> None:
    mock_driver, _ = _make_mock_session_empty_iter()

    result = asyncio.run(GraphRepository(mock_driver).upsert_relationships(TENANT, []))

    assert result == {}


# ---------------------------------------------------------------------------
# get_entity
# ---------------------------------------------------------------------------


def test_get_entity_returns_none_when_not_found() -> None:
    mock_driver, _ = _make_mock_session_with_single(None)

    result = asyncio.run(GraphRepository(mock_driver).get_entity(TENANT, "nonexistent"))

    assert result is None


def test_get_entity_returns_entity_when_found() -> None:
    from tests.test_graph_repository_helpers import FakeNode, FakeTemporal

    fake_node = FakeNode(
        {
            "id": "entity-1",
            "tenant_id": TENANT,
            "entity_type": "ip",
            "value": "1.2.3.4",
            "first_seen": FakeTemporal(OBS_TIME),
            "last_seen": FakeTemporal(OBS_TIME),
            "source": "unit",
            "properties_json": "{}",
        }
    )
    mock_driver, mock_session = _make_mock_session_with_single({"entity": fake_node})

    result = asyncio.run(GraphRepository(mock_driver).get_entity(TENANT, "entity-1"))

    assert result is not None
    assert result.id == "entity-1"
    assert result.entity_type == "ip"
    assert result.value == "1.2.3.4"


# ---------------------------------------------------------------------------
# list_entities
# ---------------------------------------------------------------------------


def test_list_entities_returns_empty() -> None:
    mock_driver, _ = _make_mock_session_empty_iter()

    result = asyncio.run(GraphRepository(mock_driver).list_entities(TENANT))

    assert result == []


def test_list_entities_with_value_uses_fulltext_path() -> None:
    mock_driver, mock_session = _make_mock_session_empty_iter()

    result = asyncio.run(GraphRepository(mock_driver).list_entities(TENANT, value="1.2.3.4"))

    assert result == []
    query_str = mock_session.run.call_args.args[0]
    assert "UNION" in query_str


def test_list_entities_with_entity_type_uses_standard_path() -> None:
    mock_driver, mock_session = _make_mock_session_empty_iter()

    result = asyncio.run(GraphRepository(mock_driver).list_entities(TENANT, entity_type="ip"))

    assert result == []
    call_kwargs = mock_session.run.call_args.kwargs
    assert call_kwargs["entity_type"] == "ip"


# ---------------------------------------------------------------------------
# count_entities_by_type / list_relationships / list_evidence / list_relationship_evidence
# ---------------------------------------------------------------------------


def test_count_entities_by_type_returns_empty() -> None:
    mock_driver, _ = _make_mock_session_empty_iter()

    result = asyncio.run(GraphRepository(mock_driver).count_entities_by_type(TENANT))

    assert result == []


def test_list_relationships_returns_empty() -> None:
    mock_driver, _ = _make_mock_session_empty_iter()

    result = asyncio.run(GraphRepository(mock_driver).list_relationships(TENANT, "entity-1"))

    assert result == []


def test_list_evidence_returns_empty() -> None:
    mock_driver, _ = _make_mock_session_empty_iter()

    result = asyncio.run(GraphRepository(mock_driver).list_evidence(TENANT, "entity-1"))

    assert result == []


def test_list_relationship_evidence_returns_empty() -> None:
    mock_driver, _ = _make_mock_session_empty_iter()

    result = asyncio.run(GraphRepository(mock_driver).list_relationship_evidence(TENANT, "entity-1", "rel-1"))

    assert result == []


# ---------------------------------------------------------------------------
# get_graph / find_path — hop validation
# ---------------------------------------------------------------------------


def test_get_graph_raises_for_invalid_hops() -> None:
    mock_driver, _ = _make_mock_session_empty_iter()
    repo = GraphRepository(mock_driver)

    with pytest.raises(ValueError, match="hops must be between 1 and 4"):
        asyncio.run(repo.get_graph(TENANT, "entity-1", hops=0))

    with pytest.raises(ValueError, match="hops must be between 1 and 4"):
        asyncio.run(repo.get_graph(TENANT, "entity-1", hops=5))


def test_find_path_raises_for_invalid_hops() -> None:
    mock_driver, _ = _make_mock_session_empty_iter()
    repo = GraphRepository(mock_driver)

    with pytest.raises(ValueError, match="max_hops must be between 1 and 4"):
        asyncio.run(repo.find_path(TENANT, "a", "b", max_hops=0))

    with pytest.raises(ValueError, match="max_hops must be between 1 and 4"):
        asyncio.run(repo.find_path(TENANT, "a", "b", max_hops=5))


def test_get_graph_returns_empty_response_when_no_data() -> None:
    mock_driver, _ = _make_mock_session_empty_iter()

    result = asyncio.run(GraphRepository(mock_driver).get_graph(TENANT, "entity-1", hops=2))

    assert result.nodes == []
    assert result.edges == []


def test_find_path_returns_empty_response_when_no_data() -> None:
    mock_driver, _ = _make_mock_session_empty_iter()

    result = asyncio.run(GraphRepository(mock_driver).find_path(TENANT, "user-1", "domain-1", max_hops=3))

    assert result.nodes == []
    assert result.edges == []


# ---------------------------------------------------------------------------
# Pure helpers — no DB needed
# ---------------------------------------------------------------------------


def test_merge_properties_handles_nested_dicts() -> None:
    existing = {"enrichment": {"country": "US"}, "source_field": "src.ip"}
    incoming = {"enrichment": {"asn": "AS123"}, "source_field": "dst.ip"}
    merged = _merge_properties(existing, incoming)

    assert merged["enrichment"]["country"] == "US"
    assert merged["enrichment"]["asn"] == "AS123"
    assert merged["source_field"] == "src.ip"  # keeps first value


def test_merge_properties_skips_empty_values() -> None:
    result = _merge_properties({"name": "alice"}, {"name": None, "extra": "", "list": []})

    assert result == {"name": "alice"}


def test_merge_unique_strings_deduplicates() -> None:
    result = _merge_unique_strings(["a", "b"], ["b", "c"])
    assert result == ["a", "b", "c"]


def test_merge_unique_strings_handles_none() -> None:
    result = _merge_unique_strings(None, ["a"])
    assert result == ["a"]


def test_promoted_properties_ip_entity() -> None:
    entity = _make_entity(
        entity_type=EntityType.IP,
        value="8.8.8.8",
        properties={"version": 4, "enrichment": {"country": "US", "reputation": "clean"}},
    )
    props = _promoted_properties(entity)

    assert props["is_private"] is False
    assert props["country"] == "US"
    assert props["reputation"] == "clean"
    assert props["ip_version"] == 4


def test_promoted_properties_private_ip() -> None:
    entity = _make_entity(entity_type=EntityType.IP, value="192.168.1.1")
    props = _promoted_properties(entity)

    assert props["is_private"] is True


def test_promoted_properties_invalid_ip_returns_none() -> None:
    assert _is_private_ip("not-an-ip") is None


def test_promoted_properties_file_hash_entity() -> None:
    entity = _make_entity(
        entity_type=EntityType.FILE_HASH,
        value="abc123",
        properties={"algorithm": "sha256", "enrichment": {"reputation": "malicious", "malware_family": "Mirai"}},
    )
    props = _promoted_properties(entity)

    assert props["algorithm"] == "sha256"
    assert props["reputation"] == "malicious"
    assert props["malware_family"] == "Mirai"


def test_promoted_properties_process_entity() -> None:
    entity = _make_entity(
        entity_type=EntityType.PROCESS,
        value="cmd.exe",
        properties={"name": "cmd.exe", "path": r"C:\Windows\cmd.exe", "cmd_line": "cmd /c whoami"},
    )
    props = _promoted_properties(entity)

    assert props["name"] == "cmd.exe"
    assert props["path"] == r"C:\Windows\cmd.exe"
    assert props["cmd_line"] == "cmd /c whoami"


def test_promoted_properties_url_entity() -> None:
    entity = _make_entity(
        entity_type=EntityType.URL,
        value="https://example.com/path",
        properties={"scheme": "https", "host": "example.com", "path": "/path"},
    )
    props = _promoted_properties(entity)

    assert props["scheme"] == "https"
    assert props["host"] == "example.com"
    assert props["path"] == "/path"


def test_promoted_properties_email_entity() -> None:
    entity = _make_entity(
        entity_type=EntityType.EMAIL,
        value="user@example.com",
        properties={"domain": "example.com"},
    )
    props = _promoted_properties(entity)

    assert props["domain"] == "example.com"


def test_promoted_properties_cve_entity() -> None:
    entity = _make_entity(
        entity_type=EntityType.CVE,
        value="CVE-2021-44228",
        properties={"year": 2021},
    )
    props = _promoted_properties(entity)

    assert props["year"] == 2021


def test_promoted_properties_unknown_type_returns_empty() -> None:
    entity = _make_entity(entity_type=EntityType.USER, value="alice")

    assert _promoted_properties(entity) == {}


def test_create_graph_driver_uses_settings() -> None:
    from app.graph.repository import create_graph_driver

    with patch("app.graph.repository.AsyncGraphDatabase.driver") as mock_gdb:
        mock_gdb.return_value = MagicMock()
        driver = create_graph_driver()
        assert mock_gdb.called
        assert driver is mock_gdb.return_value
