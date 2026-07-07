from __future__ import annotations

from app.graph.repository import (
    _entity_response,
    _evidence_response,
    _fulltext_prefix_query,
    _graph_edge,
    _graph_node,
    _json_loads,
    _relationship_evidence_response,
    _relationship_response,
    _serialize_properties,
)


class FakeTemporal:
    def __init__(self, value: str) -> None:
        self.value = value

    def iso_format(self) -> str:
        return self.value


class FakeNode(dict):
    def __init__(self, *args, element_id: str = "node-1", labels: list[str] | None = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.element_id = element_id
        self.labels = labels or ["Entity"]


class FakeRelationship(dict):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.element_id = "rel-1"
        self.type = "CONNECTED_TO"
        self.start_node = FakeNode(element_id="start")
        self.end_node = FakeNode(element_id="end")


def test_repository_json_and_fulltext_helpers() -> None:
    assert _json_loads(None) == {}
    assert _json_loads({"a": 1}) == {"a": 1}
    assert _json_loads('{"a":1}') == {"a": 1}
    assert _json_loads("[1,2]") == {}
    assert _json_loads("{bad json") == {}
    assert _fulltext_prefix_query("PowerShell.exe 10.0.0.1") == "powershell* AND exe* AND 10* AND 0* AND 0* AND 1*"


def test_repository_response_serializers_convert_temporal_and_json_properties() -> None:
    entity = _entity_response(
        FakeNode(
            {
                "id": "entity-1",
                "tenant_id": "tenant-a",
                "entity_type": "ip",
                "value": "8.8.8.8",
                "first_seen": FakeTemporal("2026-07-07T00:00:00Z"),
                "last_seen": FakeTemporal("2026-07-07T00:01:00Z"),
                "source": "unit",
                "properties_json": '{"country":"US"}',
            }
        )
    )
    relationship = _relationship_response(
        FakeNode(
            {
                "id": "fact-1",
                "tenant_id": "tenant-a",
                "relationship_type": "CONNECTED_TO",
                "from_id": "host-1",
                "to_id": "ip-1",
                "first_seen": FakeTemporal("2026-07-07T00:00:00Z"),
                "last_seen": FakeTemporal("2026-07-07T00:01:00Z"),
                "count": 2,
                "sample_evidence_refs": ["evt-1"],
            }
        )
    )

    assert entity.properties == {"country": "US"}
    assert entity.first_seen == "2026-07-07T00:00:00Z"
    assert relationship.count == 2
    assert relationship.sample_evidence_refs == ["evt-1"]


def test_repository_evidence_and_graph_serializers() -> None:
    event_node = FakeNode(
        {
            "event_id": "evt-1",
            "time": FakeTemporal("2026-07-07T00:00:00Z"),
            "class_uid": 1007,
            "class_name": "Process Activity",
            "activity_id": 1,
            "activity_name": "Launch",
            "source_name": "sysmon",
        }
    )
    observation_node = FakeNode({"field_path": "process.file.path", "value": r"C:\Windows\cmd.exe"})
    relationship_fact = FakeNode({"id": "fact-1"})
    graph_node = FakeNode({"id": "entity-1", "last_seen": FakeTemporal("2026-07-07T00:00:00Z")}, labels=["Entity", "Host"])
    graph_edge = FakeRelationship({"count": 3, "last_seen": FakeTemporal("2026-07-07T00:00:00Z")})

    evidence = _evidence_response(event_node, observation_node)
    relationship_evidence = _relationship_evidence_response(event_node, relationship_fact)
    serialized_node = _graph_node(graph_node)
    serialized_edge = _graph_edge(graph_edge)

    assert evidence.field_path == "process.file.path"
    assert relationship_evidence.relationship_id == "fact-1"
    assert serialized_node.labels == ["Entity", "Host"]
    assert serialized_node.properties["last_seen"] == "2026-07-07T00:00:00Z"
    assert serialized_edge.start_id == "start"
    assert serialized_edge.end_id == "end"
    assert serialized_edge.properties["last_seen"] == "2026-07-07T00:00:00Z"
    assert _serialize_properties({"time": FakeTemporal("2026-07-07T00:00:00Z")}) == {"time": "2026-07-07T00:00:00Z"}
