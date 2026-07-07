from __future__ import annotations

import json
import re
from typing import Any

from neo4j import AsyncDriver, AsyncGraphDatabase
from neo4j.graph import Node, Path, Relationship

from app.core.config import get_settings
from app.entities.schemas import Entity, EntityType
from app.graph.constants import label_for_entity_type, validate_relationship_type
from app.graph.ids import graph_event_id, observation_id, relationship_fact_id
from app.graph.schemas import EntityResponse, EntityTypeCountResponse, EvidenceResponse, GraphEdge, GraphNode, GraphResponse, RelationshipCandidate, RelationshipResponse
from app.ocsf.schemas import OCSFEvent


class GraphRepository:
    def __init__(self, driver: AsyncDriver):
        self._driver = driver

    async def ensure_schema(self) -> None:
        statements = [
            "CREATE CONSTRAINT entity_id_unique IF NOT EXISTS FOR (n:Entity) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT event_id_unique IF NOT EXISTS FOR (n:Event) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT observation_id_unique IF NOT EXISTS FOR (n:Observation) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT relationship_fact_id_unique IF NOT EXISTS FOR (n:RelationshipFact) REQUIRE n.id IS UNIQUE",
            "CREATE INDEX entity_tenant_type_idx IF NOT EXISTS FOR (n:Entity) ON (n.tenant_id, n.entity_type)",
            "CREATE INDEX entity_tenant_value_idx IF NOT EXISTS FOR (n:Entity) ON (n.tenant_id, n.value)",
            "CREATE INDEX event_tenant_time_idx IF NOT EXISTS FOR (n:Event) ON (n.tenant_id, n.time)",
            "CREATE INDEX relationship_fact_tenant_type_idx IF NOT EXISTS FOR (n:RelationshipFact) ON (n.tenant_id, n.relationship_type)",
            "CREATE INDEX relationship_fact_tenant_from_idx IF NOT EXISTS FOR (n:RelationshipFact) ON (n.tenant_id, n.from_id)",
            "CREATE INDEX relationship_fact_tenant_to_idx IF NOT EXISTS FOR (n:RelationshipFact) ON (n.tenant_id, n.to_id)",
            "CREATE INDEX entity_tenant_last_seen_idx IF NOT EXISTS FOR (n:Entity) ON (n.tenant_id, n.last_seen)",
            "CREATE INDEX entity_tenant_type_last_seen_idx IF NOT EXISTS FOR (n:Entity) ON (n.tenant_id, n.entity_type, n.last_seen)",
            "CREATE INDEX observation_tenant_entity_observed_idx IF NOT EXISTS FOR (n:Observation) ON (n.tenant_id, n.entity_id, n.observed_at)",
            "CREATE INDEX relationship_fact_tenant_from_last_seen_idx IF NOT EXISTS FOR (n:RelationshipFact) ON (n.tenant_id, n.from_id, n.last_seen)",
            "CREATE INDEX relationship_fact_tenant_to_last_seen_idx IF NOT EXISTS FOR (n:RelationshipFact) ON (n.tenant_id, n.to_id, n.last_seen)",
            "CREATE FULLTEXT INDEX entity_value_fulltext_idx IF NOT EXISTS FOR (n:Entity) ON EACH [n.value]",
        ]
        async with self._driver.session() as session:
            for statement in statements:
                await session.run(statement)

    async def upsert_event(self, event: OCSFEvent) -> str:
        event_graph_id = graph_event_id(event.tenant_id, event.event_id)
        query = """
        MERGE (event:Event {id: $id})
        ON CREATE SET
            event.tenant_id = $tenant_id,
            event.event_id = $event_id,
            event.time = datetime($time),
            event.class_uid = $class_uid,
            event.class_name = $class_name,
            event.activity_id = $activity_id,
            event.activity_name = $activity_name,
            event.source_name = $source_name,
            event.ocsf_version = $ocsf_version
        ON MATCH SET
            event.time = datetime($time),
            event.class_uid = $class_uid,
            event.class_name = $class_name,
            event.activity_id = $activity_id,
            event.activity_name = $activity_name,
            event.source_name = $source_name,
            event.ocsf_version = $ocsf_version
        RETURN event.id AS id
        """
        async with self._driver.session() as session:
            result = await session.run(
                query,
                id=event_graph_id,
                tenant_id=event.tenant_id,
                event_id=event.event_id,
                time=_event_time_iso(event),
                class_uid=event.class_uid,
                class_name=event.class_name,
                activity_id=event.activity_id,
                activity_name=event.activity_name,
                source_name=event.source_name,
                ocsf_version=str(event.metadata.get("version", "1.2.0")),
            )
            record = await result.single()
            return str(record["id"])

    async def upsert_events(self, events: list[OCSFEvent]) -> dict[str, str]:
        rows = [
            {
                "id": graph_event_id(event.tenant_id, event.event_id),
                "tenant_id": event.tenant_id,
                "event_id": event.event_id,
                "time": _event_time_iso(event),
                "class_uid": event.class_uid,
                "class_name": event.class_name,
                "activity_id": event.activity_id,
                "activity_name": event.activity_name,
                "source_name": event.source_name,
                "ocsf_version": str(event.metadata.get("version", "1.2.0")),
            }
            for event in events
        ]
        if not rows:
            return {}
        query = """
        UNWIND $rows AS row
        MERGE (event:Event {id: row.id})
        ON CREATE SET
            event.tenant_id = row.tenant_id,
            event.event_id = row.event_id,
            event.time = datetime(row.time),
            event.class_uid = row.class_uid,
            event.class_name = row.class_name,
            event.activity_id = row.activity_id,
            event.activity_name = row.activity_name,
            event.source_name = row.source_name,
            event.ocsf_version = row.ocsf_version
        ON MATCH SET
            event.time = datetime(row.time),
            event.class_uid = row.class_uid,
            event.class_name = row.class_name,
            event.activity_id = row.activity_id,
            event.activity_name = row.activity_name,
            event.source_name = row.source_name,
            event.ocsf_version = row.ocsf_version
        RETURN row.event_id AS event_id, event.id AS id
        """
        async with self._driver.session() as session:
            result = await session.run(query, rows=rows)
            return {str(record["event_id"]): str(record["id"]) async for record in result}

    async def upsert_entity(self, entity: Entity) -> str:
        label = label_for_entity_type(entity.type)
        properties = await self._merged_entity_properties(entity)
        query = f"""
        MERGE (entity:Entity:{label} {{id: $id}})
        ON CREATE SET
            entity.tenant_id = $tenant_id,
            entity.entity_type = $entity_type,
            entity.value = $value,
            entity.first_seen = datetime($first_seen),
            entity.last_seen = datetime($last_seen),
            entity.source = $source,
            entity.properties_json = $properties_json,
            entity.audit_created = true
        ON MATCH SET
            entity.first_seen = CASE
                WHEN datetime($first_seen) < entity.first_seen THEN datetime($first_seen)
                ELSE entity.first_seen
            END,
            entity.last_seen = CASE
                WHEN datetime($last_seen) > entity.last_seen THEN datetime($last_seen)
                ELSE entity.last_seen
            END,
            entity.source = $source,
            entity.properties_json = $properties_json,
            entity.audit_created = false
        SET entity += $promoted_properties
        WITH entity, entity.audit_created AS was_created
        REMOVE entity.audit_created
        RETURN CASE WHEN was_created THEN 'created' ELSE 'updated' END AS status
        """
        async with self._driver.session() as session:
            result = await session.run(
                query,
                id=entity.id,
                tenant_id=entity.tenant_id,
                entity_type=entity.type.value,
                value=entity.value,
                first_seen=entity.first_seen,
                last_seen=entity.last_seen,
                source=entity.source,
                properties_json=_json_dumps(properties),
                promoted_properties=_promoted_properties(entity.model_copy(update={"properties": properties})),
            )
            record = await result.single()
            return str(record["status"])

    async def upsert_entities(self, entities: list[Entity]) -> dict[str, str]:
        if not entities:
            return {}
        properties_by_id = await self._merged_entity_properties_batch(entities)
        statuses: dict[str, str] = {}
        grouped: dict[EntityType, list[Entity]] = {}
        for entity in entities:
            grouped.setdefault(entity.type, []).append(entity)

        async with self._driver.session() as session:
            for entity_type, group in grouped.items():
                label = label_for_entity_type(entity_type)
                rows = []
                for entity in group:
                    properties = properties_by_id[entity.id]
                    rows.append(
                        {
                            "id": entity.id,
                            "tenant_id": entity.tenant_id,
                            "entity_type": entity.type.value,
                            "value": entity.value,
                            "first_seen": entity.first_seen,
                            "last_seen": entity.last_seen,
                            "source": entity.source,
                            "properties_json": _json_dumps(properties),
                            "promoted_properties": _promoted_properties(entity.model_copy(update={"properties": properties})),
                        }
                    )
                query = f"""
                UNWIND $rows AS row
                MERGE (entity:Entity:{label} {{id: row.id}})
                ON CREATE SET
                    entity.tenant_id = row.tenant_id,
                    entity.entity_type = row.entity_type,
                    entity.value = row.value,
                    entity.first_seen = datetime(row.first_seen),
                    entity.last_seen = datetime(row.last_seen),
                    entity.source = row.source,
                    entity.properties_json = row.properties_json,
                    entity.audit_created = true
                ON MATCH SET
                    entity.first_seen = CASE
                        WHEN datetime(row.first_seen) < entity.first_seen THEN datetime(row.first_seen)
                        ELSE entity.first_seen
                    END,
                    entity.last_seen = CASE
                        WHEN datetime(row.last_seen) > entity.last_seen THEN datetime(row.last_seen)
                        ELSE entity.last_seen
                    END,
                    entity.source = row.source,
                    entity.properties_json = row.properties_json,
                    entity.audit_created = false
                SET entity += row.promoted_properties
                WITH row, entity, entity.audit_created AS was_created
                REMOVE entity.audit_created
                RETURN row.id AS id, CASE WHEN was_created THEN 'created' ELSE 'updated' END AS status
                """
                result = await session.run(query, rows=rows)
                async for record in result:
                    statuses[str(record["id"])] = str(record["status"])
        return statuses

    async def _merged_entity_properties(self, entity: Entity) -> dict[str, Any]:
        query = "MATCH (entity:Entity {id: $id, tenant_id: $tenant_id}) RETURN entity.properties_json AS properties_json"
        async with self._driver.session() as session:
            result = await session.run(query, id=entity.id, tenant_id=entity.tenant_id)
            record = await result.single()
        existing = _json_loads(record["properties_json"]) if record else {}
        return _merge_properties(existing, entity.properties)

    async def _merged_entity_properties_batch(self, entities: list[Entity]) -> dict[str, dict[str, Any]]:
        query = """
        MATCH (entity:Entity)
        WHERE entity.id IN $ids
        RETURN entity.id AS id, entity.properties_json AS properties_json
        """
        ids = list({entity.id for entity in entities})
        async with self._driver.session() as session:
            result = await session.run(query, ids=ids)
            existing = {str(record["id"]): _json_loads(record["properties_json"]) async for record in result}
        merged = {}
        for entity in entities:
            merged[entity.id] = _merge_properties(existing.get(entity.id, {}), entity.properties)
        return merged

    async def upsert_observation(self, event: OCSFEvent, entity: Entity) -> str:
        field_path = str(entity.properties.get("source_field") or "unknown")
        obs_id = observation_id(event.tenant_id, event.event_id, entity.id, field_path)
        query = """
        MATCH (event:Event {id: $event_graph_id, tenant_id: $tenant_id})
        MATCH (entity:Entity {id: $entity_id, tenant_id: $tenant_id})
        MERGE (obs:Observation {id: $id})
        ON CREATE SET
            obs.tenant_id = $tenant_id,
            obs.field_path = $field_path,
            obs.entity_id = $entity_id,
            obs.entity_type = $entity_type,
            obs.value = $value,
            obs.observed_at = datetime($observed_at),
            obs.confidence = 1.0
        ON MATCH SET
            obs.value = $value,
            obs.entity_id = $entity_id,
            obs.observed_at = datetime($observed_at)
        MERGE (event)-[:OBSERVED]->(obs)
        MERGE (obs)-[:OF_ENTITY]->(entity)
        RETURN obs.id AS id
        """
        async with self._driver.session() as session:
            result = await session.run(
                query,
                event_graph_id=graph_event_id(event.tenant_id, event.event_id),
                tenant_id=event.tenant_id,
                entity_id=entity.id,
                id=obs_id,
                field_path=field_path,
                entity_type=entity.type.value,
                value=entity.value,
                observed_at=entity.first_seen,
            )
            record = await result.single()
            return str(record["id"])

    async def upsert_observations(self, event_entities: list[tuple[OCSFEvent, Entity]]) -> list[str]:
        rows = []
        for event, entity in event_entities:
            field_path = str(entity.properties.get("source_field") or "unknown")
            rows.append(
                {
                    "event_graph_id": graph_event_id(event.tenant_id, event.event_id),
                    "tenant_id": event.tenant_id,
                    "entity_id": entity.id,
                    "id": observation_id(event.tenant_id, event.event_id, entity.id, field_path),
                    "field_path": field_path,
                    "entity_type": entity.type.value,
                    "value": entity.value,
                    "observed_at": entity.first_seen,
                }
            )
        if not rows:
            return []
        query = """
        UNWIND $rows AS row
        MATCH (event:Event {id: row.event_graph_id, tenant_id: row.tenant_id})
        MATCH (entity:Entity {id: row.entity_id, tenant_id: row.tenant_id})
        MERGE (obs:Observation {id: row.id})
        ON CREATE SET
            obs.tenant_id = row.tenant_id,
            obs.field_path = row.field_path,
            obs.entity_id = row.entity_id,
            obs.entity_type = row.entity_type,
            obs.value = row.value,
            obs.observed_at = datetime(row.observed_at),
            obs.confidence = 1.0
        ON MATCH SET
            obs.value = row.value,
            obs.entity_id = row.entity_id,
            obs.observed_at = datetime(row.observed_at)
        MERGE (event)-[:OBSERVED]->(obs)
        MERGE (obs)-[:OF_ENTITY]->(entity)
        RETURN obs.id AS id
        """
        async with self._driver.session() as session:
            result = await session.run(query, rows=rows)
            return [str(record["id"]) async for record in result]

    async def upsert_relationship(self, tenant_id: str, candidate: RelationshipCandidate) -> str:
        relationship_type = validate_relationship_type(candidate.relationship_type)
        fact_id = relationship_fact_id(tenant_id, relationship_type, candidate.from_id, candidate.to_id)
        query = f"""
        MATCH (from_entity:Entity {{id: $from_id, tenant_id: $tenant_id}})
        MATCH (to_entity:Entity {{id: $to_id, tenant_id: $tenant_id}})
        MATCH (event:Event {{id: $event_graph_id, tenant_id: $tenant_id}})
        MERGE (fact:RelationshipFact {{id: $fact_id}})
        ON CREATE SET
            fact.tenant_id = $tenant_id,
            fact.relationship_type = $relationship_type,
            fact.from_id = $from_id,
            fact.to_id = $to_id,
            fact.first_seen = datetime($observed_at),
            fact.last_seen = datetime($observed_at),
            fact.count = 0,
            fact.sample_evidence_refs = [],
            fact.audit_created = true
        ON MATCH SET
            fact.audit_created = false
        WITH from_entity, to_entity, event, fact
        OPTIONAL MATCH (event)-[existing:EVIDENCES]->(fact)
        WITH from_entity, to_entity, event, fact, existing IS NULL AS is_new, fact.audit_created AS was_created
        MERGE (event)-[:EVIDENCES]->(fact)
        SET
            fact.first_seen = CASE
                WHEN datetime($observed_at) < fact.first_seen THEN datetime($observed_at)
                ELSE fact.first_seen
            END,
            fact.last_seen = CASE
                WHEN datetime($observed_at) > fact.last_seen THEN datetime($observed_at)
                ELSE fact.last_seen
            END,
            fact.count = fact.count + CASE WHEN is_new THEN 1 ELSE 0 END,
            fact.sample_evidence_refs = CASE
                WHEN is_new AND NOT $evidence_ref IN fact.sample_evidence_refs
                THEN (fact.sample_evidence_refs + $evidence_ref)[-50..]
                ELSE fact.sample_evidence_refs
            END
        MERGE (from_entity)-[rel:{relationship_type}]->(to_entity)
        ON CREATE SET
            rel.tenant_id = $tenant_id,
            rel.relationship_type = $relationship_type,
            rel.fact_id = $fact_id,
            rel.first_seen = datetime($observed_at),
            rel.last_seen = datetime($observed_at),
            rel.count = 0
        SET
            rel.first_seen = fact.first_seen,
            rel.last_seen = fact.last_seen,
            rel.count = fact.count
        REMOVE fact.audit_created
        RETURN CASE WHEN was_created THEN 'created' ELSE 'updated' END AS status
        """
        async with self._driver.session() as session:
            result = await session.run(
                query,
                tenant_id=tenant_id,
                from_id=candidate.from_id,
                to_id=candidate.to_id,
                event_graph_id=graph_event_id(tenant_id, candidate.evidence_ref),
                fact_id=fact_id,
                relationship_type=relationship_type,
                evidence_ref=candidate.evidence_ref,
                observed_at=candidate.observed_at,
            )
            record = await result.single()
            return str(record["status"])

    async def upsert_relationships(self, tenant_id: str, candidates: list[RelationshipCandidate]) -> dict[tuple[str, str, str], str]:
        if not candidates:
            return {}
        grouped: dict[str, list[RelationshipCandidate]] = {}
        for candidate in candidates:
            relationship_type = validate_relationship_type(candidate.relationship_type)
            grouped.setdefault(relationship_type, []).append(candidate)

        statuses: dict[tuple[str, str, str], str] = {}
        async with self._driver.session() as session:
            for relationship_type, group in grouped.items():
                rows = [
                    {
                        "from_id": candidate.from_id,
                        "to_id": candidate.to_id,
                        "event_graph_id": graph_event_id(tenant_id, candidate.evidence_ref),
                        "fact_id": relationship_fact_id(tenant_id, relationship_type, candidate.from_id, candidate.to_id),
                        "evidence_ref": candidate.evidence_ref,
                        "observed_at": candidate.observed_at,
                    }
                    for candidate in group
                ]
                query = f"""
                UNWIND $rows AS row
                MATCH (from_entity:Entity {{id: row.from_id, tenant_id: $tenant_id}})
                MATCH (to_entity:Entity {{id: row.to_id, tenant_id: $tenant_id}})
                MATCH (event:Event {{id: row.event_graph_id, tenant_id: $tenant_id}})
                MERGE (fact:RelationshipFact {{id: row.fact_id}})
                ON CREATE SET
                    fact.tenant_id = $tenant_id,
                    fact.relationship_type = $relationship_type,
                    fact.from_id = row.from_id,
                    fact.to_id = row.to_id,
                    fact.first_seen = datetime(row.observed_at),
                    fact.last_seen = datetime(row.observed_at),
                    fact.count = 0,
                    fact.sample_evidence_refs = [],
                    fact.audit_created = true
                ON MATCH SET
                    fact.audit_created = false
                WITH row, from_entity, to_entity, event, fact
                OPTIONAL MATCH (event)-[existing:EVIDENCES]->(fact)
                WITH row, from_entity, to_entity, event, fact, existing IS NULL AS is_new, fact.audit_created AS was_created
                MERGE (event)-[:EVIDENCES]->(fact)
                SET
                    fact.first_seen = CASE
                        WHEN datetime(row.observed_at) < fact.first_seen THEN datetime(row.observed_at)
                        ELSE fact.first_seen
                    END,
                    fact.last_seen = CASE
                        WHEN datetime(row.observed_at) > fact.last_seen THEN datetime(row.observed_at)
                        ELSE fact.last_seen
                    END,
                    fact.count = fact.count + CASE WHEN is_new THEN 1 ELSE 0 END,
                    fact.sample_evidence_refs = CASE
                        WHEN is_new AND NOT row.evidence_ref IN fact.sample_evidence_refs
                        THEN (fact.sample_evidence_refs + row.evidence_ref)[-50..]
                        ELSE fact.sample_evidence_refs
                    END
                MERGE (from_entity)-[rel:{relationship_type}]->(to_entity)
                ON CREATE SET
                    rel.tenant_id = $tenant_id,
                    rel.relationship_type = $relationship_type,
                    rel.fact_id = row.fact_id,
                    rel.first_seen = datetime(row.observed_at),
                    rel.last_seen = datetime(row.observed_at),
                    rel.count = 0
                SET
                    rel.first_seen = fact.first_seen,
                    rel.last_seen = fact.last_seen,
                    rel.count = fact.count
                REMOVE fact.audit_created
                RETURN row.from_id AS from_id, row.to_id AS to_id, CASE WHEN was_created THEN 'created' ELSE 'updated' END AS status
                """
                result = await session.run(query, rows=rows, tenant_id=tenant_id, relationship_type=relationship_type)
                async for record in result:
                    statuses[(relationship_type, str(record["from_id"]), str(record["to_id"]))] = str(record["status"])
        return statuses

    async def get_entity(self, tenant_id: str, entity_id: str) -> EntityResponse | None:
        query = "MATCH (entity:Entity {id: $entity_id, tenant_id: $tenant_id}) RETURN entity"
        async with self._driver.session() as session:
            result = await session.run(query, tenant_id=tenant_id, entity_id=entity_id)
            record = await result.single()
            return _entity_response(record["entity"]) if record else None

    async def list_entities(
        self,
        tenant_id: str,
        entity_type: str | None = None,
        value: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EntityResponse]:
        clauses = ["entity.tenant_id = $tenant_id"]
        params: dict[str, Any] = {"tenant_id": tenant_id, "limit": limit, "offset": offset}
        if entity_type:
            clauses.append("entity.entity_type = $entity_type")
            params["entity_type"] = entity_type
        if value:
            normalized_value = value.strip().lower()
            clauses.append("entity.value CONTAINS $value")
            params["value"] = normalized_value
            params["fulltext_value"] = _fulltext_prefix_query(normalized_value)
            params["exact_value"] = normalized_value
        if value and not entity_type and params["fulltext_value"]:
            query = """
            CALL {
                MATCH (entity:Entity {tenant_id: $tenant_id, value: $exact_value})
                RETURN entity, 0 AS rank
                UNION
                CALL db.index.fulltext.queryNodes('entity_value_fulltext_idx', $fulltext_value) YIELD node, score
                WITH node AS entity, score
                WHERE entity.tenant_id = $tenant_id
                RETURN entity, 1 AS rank
            }
            WITH entity, min(rank) AS rank
            RETURN entity
            ORDER BY rank ASC, entity.last_seen DESC
            SKIP $offset
            LIMIT $limit
            """
            async with self._driver.session() as session:
                result = await session.run(query, **params)
                return [_entity_response(record["entity"]) async for record in result]
        query = f"""
        MATCH (entity:Entity)
        WHERE {" AND ".join(clauses)}
        RETURN entity
        ORDER BY entity.last_seen DESC
        SKIP $offset
        LIMIT $limit
        """
        async with self._driver.session() as session:
            result = await session.run(query, **params)
            return [_entity_response(record["entity"]) async for record in result]

    async def count_entities_by_type(self, tenant_id: str, value: str | None = None) -> list[EntityTypeCountResponse]:
        clauses = ["entity.tenant_id = $tenant_id"]
        params: dict[str, Any] = {"tenant_id": tenant_id}
        if value:
            clauses.append("entity.value CONTAINS $value")
            params["value"] = value
        query = f"""
        MATCH (entity:Entity)
        WHERE {" AND ".join(clauses)}
        RETURN entity.entity_type AS entity_type, count(entity) AS count
        """
        async with self._driver.session() as session:
            result = await session.run(query, **params)
            return [
                EntityTypeCountResponse(
                    entity_type=str(record["entity_type"]),
                    count=int(record["count"] or 0),
                )
                async for record in result
            ]

    async def list_relationships(self, tenant_id: str, entity_id: str, limit: int = 100) -> list[RelationshipResponse]:
        query = """
        CALL {
            MATCH (fact:RelationshipFact {tenant_id: $tenant_id, from_id: $entity_id})
            RETURN fact
            UNION
            MATCH (fact:RelationshipFact {tenant_id: $tenant_id, to_id: $entity_id})
            RETURN fact
        }
        RETURN fact
        ORDER BY fact.last_seen DESC
        LIMIT $limit
        """
        async with self._driver.session() as session:
            result = await session.run(query, tenant_id=tenant_id, entity_id=entity_id, limit=limit)
            return [_relationship_response(record["fact"]) async for record in result]

    async def list_evidence(self, tenant_id: str, entity_id: str, limit: int = 100) -> list[EvidenceResponse]:
        query = """
        MATCH (entity:Entity {id: $entity_id, tenant_id: $tenant_id})
        MATCH (obs:Observation {tenant_id: $tenant_id, entity_id: $entity_id})-[:OF_ENTITY]->(entity)
        MATCH (event:Event {tenant_id: $tenant_id})-[:OBSERVED]->(obs)
        RETURN event, obs
        ORDER BY event.time DESC
        LIMIT $limit
        """
        async with self._driver.session() as session:
            result = await session.run(query, tenant_id=tenant_id, entity_id=entity_id, limit=limit)
            return [_evidence_response(record["event"], record["obs"]) async for record in result]

    async def list_relationship_evidence(
        self,
        tenant_id: str,
        entity_id: str,
        relationship_id: str,
        limit: int = 100,
    ) -> list[EvidenceResponse]:
        query = """
        MATCH (entity:Entity {id: $entity_id, tenant_id: $tenant_id})
        MATCH (fact:RelationshipFact {id: $relationship_id, tenant_id: $tenant_id})
        WHERE fact.from_id = entity.id OR fact.to_id = entity.id
        MATCH (event:Event {tenant_id: $tenant_id})-[:EVIDENCES]->(fact)
        RETURN event, fact
        ORDER BY event.time DESC
        LIMIT $limit
        """
        async with self._driver.session() as session:
            result = await session.run(
                query,
                tenant_id=tenant_id,
                entity_id=entity_id,
                relationship_id=relationship_id,
                limit=limit,
            )
            return [_relationship_evidence_response(record["event"], record["fact"]) async for record in result]

    async def get_graph(self, tenant_id: str, entity_id: str, hops: int = 1, limit: int = 200) -> GraphResponse:
        if hops < 1 or hops > 4:
            raise ValueError("hops must be between 1 and 4")
        query = f"""
        MATCH (entity:Entity {{id: $entity_id, tenant_id: $tenant_id}})
        OPTIONAL MATCH path = (entity)-[*1..{hops}]-(neighbor:Entity)
        WHERE neighbor.tenant_id = $tenant_id
          AND all(node IN nodes(path) WHERE node:Entity AND node.tenant_id = $tenant_id)
          AND all(rel IN relationships(path) WHERE rel.tenant_id = $tenant_id)
        RETURN entity, path
        LIMIT $limit
        """
        return await self._paths_to_graph(query, tenant_id=tenant_id, entity_id=entity_id, limit=limit)

    async def find_path(self, tenant_id: str, source_id: str, target_id: str, max_hops: int = 4, limit: int = 50) -> GraphResponse:
        if max_hops < 1 or max_hops > 4:
            raise ValueError("max_hops must be between 1 and 4")
        query = f"""
        MATCH (source:Entity {{id: $source_id, tenant_id: $tenant_id}})
        MATCH (target:Entity {{id: $target_id, tenant_id: $tenant_id}})
        MATCH path = allShortestPaths((source)-[*1..{max_hops}]-(target))
        WHERE all(node IN nodes(path) WHERE node:Entity AND node.tenant_id = $tenant_id)
          AND all(rel IN relationships(path) WHERE rel.tenant_id = $tenant_id)
        RETURN path
        LIMIT $limit
        """
        return await self._paths_to_graph(query, tenant_id=tenant_id, source_id=source_id, target_id=target_id, limit=limit)

    async def _paths_to_graph(self, query: str, **params: Any) -> GraphResponse:
        nodes: dict[str, GraphNode] = {}
        edges: dict[str, GraphEdge] = {}
        async with self._driver.session() as session:
            result = await session.run(query, **params)
            async for record in result:
                entity = record.get("entity")
                if entity is not None:
                    nodes[str(entity.element_id)] = _graph_node(entity)
                path: Path | None = record["path"]
                if path is None:
                    continue
                for node in path.nodes:
                    nodes[str(node.element_id)] = _graph_node(node)
                for rel in path.relationships:
                    edges[str(rel.element_id)] = _graph_edge(rel)
        return GraphResponse(nodes=list(nodes.values()), edges=list(edges.values()))


def create_graph_driver() -> AsyncDriver:
    settings = get_settings()
    return AsyncGraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password))


def _event_time_iso(event: OCSFEvent) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(event.time / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _promoted_properties(entity: Entity) -> dict[str, Any]:
    enrichment = entity.properties.get("enrichment") if isinstance(entity.properties.get("enrichment"), dict) else {}
    if entity.type == EntityType.FILE_HASH:
        return {
            "algorithm": entity.properties.get("algorithm"),
            "reputation": enrichment.get("reputation"),
            "malware_family": enrichment.get("malware_family"),
        }
    if entity.type == EntityType.IP:
        return {
            "ip_version": entity.properties.get("version"),
            "is_private": _is_private_ip(entity.value),
            "country": enrichment.get("country"),
            "asn": enrichment.get("asn"),
            "reputation": enrichment.get("reputation"),
        }
    if entity.type == EntityType.PROCESS:
        return {
            "name": entity.properties.get("name"),
            "path": entity.properties.get("path"),
            "cmd_line": entity.properties.get("cmd_line"),
        }
    if entity.type == EntityType.URL:
        return {
            "scheme": entity.properties.get("scheme"),
            "host": entity.properties.get("host"),
            "path": entity.properties.get("path"),
        }
    if entity.type == EntityType.EMAIL:
        return {"domain": entity.properties.get("domain")}
    if entity.type == EntityType.CVE:
        return {"year": entity.properties.get("year")}
    if entity.type == EntityType.CLOUD_RESOURCE:
        return {
            "provider": entity.properties.get("provider"),
            "account_id": entity.properties.get("account_id"),
            "region": entity.properties.get("region"),
            "resource_type": entity.properties.get("resource_type"),
            "service": entity.properties.get("service"),
        }
    return {}


def _is_private_ip(value: str) -> bool | None:
    import ipaddress

    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return None


def _json_dumps(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _json_loads(value: Any) -> dict[str, Any]:
    if not value:
        return {}
    if isinstance(value, dict):
        return value
    try:
        loaded = json.loads(str(value))
    except json.JSONDecodeError:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _fulltext_prefix_query(value: str) -> str:
    tokens = re.findall(r"[a-z0-9]+", value.lower())
    return " AND ".join(f"{token}*" for token in tokens)


def _merge_properties(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    for key, value in incoming.items():
        if value in (None, "", [], {}):
            continue
        if key == "source_fields":
            merged[key] = _merge_unique_strings(merged.get(key), value)
        elif key == "source_field":
            merged.setdefault(key, value)
        elif key not in merged or merged[key] in (None, "", [], {}):
            merged[key] = value
        elif isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _merge_properties(merged[key], value)
    return merged


def _merge_unique_strings(existing: Any, incoming: Any) -> list[str]:
    values: list[str] = []
    for source in (existing, incoming):
        items = source if isinstance(source, list) else [source]
        for item in items:
            if item is None:
                continue
            value = str(item)
            if value not in values:
                values.append(value)
    return values


def _entity_response(node: Node) -> EntityResponse:
    data = dict(node)
    return EntityResponse(
        id=str(data.get("id")),
        tenant_id=str(data.get("tenant_id")),
        entity_type=str(data.get("entity_type")),
        value=str(data.get("value")),
        first_seen=_temporal_to_str(data.get("first_seen")),
        last_seen=_temporal_to_str(data.get("last_seen")),
        source=data.get("source"),
        properties=_json_loads(data.get("properties_json")),
    )


def _relationship_response(node: Node) -> RelationshipResponse:
    data = dict(node)
    return RelationshipResponse(
        id=str(data.get("id")),
        tenant_id=str(data.get("tenant_id")),
        relationship_type=str(data.get("relationship_type")),
        from_id=str(data.get("from_id")),
        to_id=str(data.get("to_id")),
        first_seen=_temporal_to_str(data.get("first_seen")),
        last_seen=_temporal_to_str(data.get("last_seen")),
        count=int(data.get("count") or 0),
        sample_evidence_refs=list(data.get("sample_evidence_refs") or []),
    )


def _evidence_response(event_node: Node, observation_node: Node) -> EvidenceResponse:
    event = dict(event_node)
    obs = dict(observation_node)
    return EvidenceResponse(
        event_id=str(event.get("event_id")),
        time=_temporal_to_str(event.get("time")),
        class_uid=event.get("class_uid"),
        class_name=event.get("class_name"),
        activity_id=event.get("activity_id"),
        activity_name=event.get("activity_name"),
        source_name=event.get("source_name"),
        field_path=obs.get("field_path"),
        value=obs.get("value"),
    )


def _relationship_evidence_response(event_node: Node, relationship_fact_node: Node) -> EvidenceResponse:
    event = dict(event_node)
    relationship_fact = dict(relationship_fact_node)
    return EvidenceResponse(
        event_id=str(event.get("event_id")),
        time=_temporal_to_str(event.get("time")),
        class_uid=event.get("class_uid"),
        class_name=event.get("class_name"),
        activity_id=event.get("activity_id"),
        activity_name=event.get("activity_name"),
        source_name=event.get("source_name"),
        relationship_id=str(relationship_fact.get("id")),
    )


def _graph_node(node: Node) -> GraphNode:
    return GraphNode(id=str(node.element_id), labels=list(node.labels), properties=_serialize_properties(dict(node)))


def _graph_edge(rel: Relationship) -> GraphEdge:
    return GraphEdge(
        id=str(rel.element_id),
        type=rel.type,
        start_id=str(rel.start_node.element_id),
        end_id=str(rel.end_node.element_id),
        properties=_serialize_properties(dict(rel)),
    )


def _serialize_properties(properties: dict[str, Any]) -> dict[str, Any]:
    return {key: _temporal_to_str(value) for key, value in properties.items()}


def _temporal_to_str(value: Any) -> Any:
    return value.iso_format() if hasattr(value, "iso_format") else value
