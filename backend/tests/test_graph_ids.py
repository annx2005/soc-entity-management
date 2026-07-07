from __future__ import annotations

from app.graph.ids import graph_event_id, observation_id, relationship_fact_id, stable_hash


def test_graph_ids_are_stable_and_namespace_inputs() -> None:
    assert stable_hash("tenant", "event") == stable_hash("tenant", "event")
    assert stable_hash("tenant", "event") != stable_hash("tenant", "other-event")
    assert len(stable_hash("tenant", "event")) == 64
    assert graph_event_id("tenant-a", "evt-1") == stable_hash("tenant-a", "evt-1")
    assert observation_id("tenant-a", "evt-1", "entity-1", "field") == stable_hash("tenant-a", "evt-1", "entity-1", "field")
    assert relationship_fact_id("tenant-a", "CONNECTED_TO", "a", "b") == stable_hash("tenant-a", "CONNECTED_TO", "a", "b")
