from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Protocol

from app.entities.extractor import extract_entities
from app.entities.schemas import Entity
from app.enrichment.service import EnrichmentService
from app.graph.inference import infer_relationships
from app.graph.repository import GraphRepository
from app.graph.schemas import EntityResponse, EntityTypeCountResponse, EvidenceResponse, GraphIngestResult, GraphResponse, RelationshipResponse
from app.observability.metrics import record_entity_upsert, record_graph_event, record_relationship_upsert
from app.ocsf.schemas import OCSFEvent


class AuditLoggerProtocol(Protocol):
    def record(
        self,
        *,
        tenant_id: str | None,
        action: str,
        target_type: str,
        target_id: str | None = None,
        actor: str | None = None,
        metadata: dict | None = None,
    ) -> None:
        ...


class GraphRepositoryProtocol(Protocol):
    async def ensure_schema(self) -> None:
        ...

    async def upsert_event(self, event: OCSFEvent) -> str:
        ...

    async def upsert_events(self, events: Iterable[OCSFEvent]) -> dict[str, str]:
        ...

    async def upsert_entity(self, entity: Entity) -> str:
        ...

    async def upsert_entities(self, entities: Iterable[Entity]) -> dict[str, str]:
        ...

    async def upsert_observation(self, event: OCSFEvent, entity: Entity) -> str:
        ...

    async def upsert_observations(self, event_entities: Iterable[tuple[OCSFEvent, Entity]]) -> list[str]:
        ...

    async def upsert_relationship(self, tenant_id: str, candidate) -> str:
        ...

    async def upsert_relationships(self, tenant_id: str, candidates: Iterable[Any]) -> dict[tuple[str, str, str], str]:
        ...

    async def get_entity(self, tenant_id: str, entity_id: str) -> EntityResponse | None:
        ...

    async def list_entities(
        self,
        tenant_id: str,
        entity_type: str | None = None,
        value: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EntityResponse]:
        ...

    async def count_entities_by_type(self, tenant_id: str, value: str | None = None) -> list[EntityTypeCountResponse]:
        ...

    async def list_relationships(self, tenant_id: str, entity_id: str, limit: int = 100) -> list[RelationshipResponse]:
        ...

    async def list_evidence(self, tenant_id: str, entity_id: str, limit: int = 100) -> list[EvidenceResponse]:
        ...

    async def list_relationship_evidence(
        self,
        tenant_id: str,
        entity_id: str,
        relationship_id: str,
        limit: int = 100,
    ) -> list[EvidenceResponse]:
        ...

    async def get_graph(self, tenant_id: str, entity_id: str, hops: int = 1, limit: int = 200) -> GraphResponse:
        ...

    async def find_path(self, tenant_id: str, source_id: str, target_id: str, max_hops: int = 4, limit: int = 50) -> GraphResponse:
        ...


class GraphService:
    def __init__(
        self,
        repository: GraphRepositoryProtocol,
        enrichment_service: EnrichmentService | None = None,
        audit_logger: AuditLoggerProtocol | None = None,
    ):
        self._repository = repository
        self._enrichment_service = enrichment_service
        self._audit_logger = audit_logger

    async def ensure_schema(self) -> None:
        await self._repository.ensure_schema()

    async def process_event(self, event: OCSFEvent) -> GraphIngestResult:
        results = await self.process_events_batch([event])
        return results[0]

    async def process_events_batch(self, events: Iterable[OCSFEvent]) -> list[GraphIngestResult]:
        events = list(events)
        if not events:
            return []
        try:
            await self._repository.ensure_schema()
            await self._upsert_events(events)

            entities_by_event: dict[str, list[Entity]] = {}
            all_entities: list[Entity] = []
            observations: list[tuple[OCSFEvent, Entity]] = []
            for event in events:
                entities = extract_entities(event)
                if self._enrichment_service is not None:
                    entities = await self._enrichment_service.enrich_entities(event.tenant_id, entities)
                entities_by_event[event.event_id] = entities
                all_entities.extend(entities)
                observations.extend((event, entity) for entity in entities)

            entity_statuses = await self._upsert_entities(all_entities)
            entity_audit_entries = []
            for entity in all_entities:
                entity_status = entity_statuses.get(entity.id, "updated")
                record_entity_upsert(entity.tenant_id, entity.type.value, entity_status)
                entity_audit_entries.append(
                    {
                        "tenant_id": entity.tenant_id,
                        "action": f"entity_{entity_status}",
                        "target_type": "entity",
                        "target_id": entity.id,
                        "metadata": {
                            "entity_type": entity.type.value,
                            "value": entity.value,
                            "source": entity.source,
                        },
                    }
                )
            self._record_graph_audit_many(entity_audit_entries)
            await self._upsert_observations(observations)

            relationships_by_event: dict[str, list[Any]] = {}
            relationship_statuses: dict[tuple[str, str, str], str] = {}
            for event in events:
                relationships = infer_relationships(event, entities_by_event[event.event_id])
                relationships_by_event[event.event_id] = relationships
                statuses = await self._upsert_relationships(event.tenant_id, relationships)
                relationship_statuses.update(statuses)

            relationship_audit_entries = []
            for event in events:
                for relationship in relationships_by_event[event.event_id]:
                    key = (relationship.relationship_type, relationship.from_id, relationship.to_id)
                    relationship_status = relationship_statuses.get(key, "updated")
                    record_relationship_upsert(event.tenant_id, relationship.relationship_type, relationship_status)
                    relationship_audit_entries.append(
                        {
                            "tenant_id": event.tenant_id,
                            "action": f"relationship_{relationship_status}",
                            "target_type": "relationship",
                            "target_id": f"{relationship.relationship_type}:{relationship.from_id}:{relationship.to_id}",
                            "metadata": {
                                "event_id": event.event_id,
                                "relationship_type": relationship.relationship_type,
                                "from_id": relationship.from_id,
                                "to_id": relationship.to_id,
                                "evidence_ref": relationship.evidence_ref,
                            },
                        }
                    )
                record_graph_event(event.tenant_id, "processed")

            self._record_graph_audit_many(relationship_audit_entries)
            return [
                GraphIngestResult(
                    tenant_id=event.tenant_id,
                    event_id=event.event_id,
                    entities=len(entities_by_event[event.event_id]),
                    observations=len(entities_by_event[event.event_id]),
                    relationships=len(relationships_by_event[event.event_id]),
                )
                for event in events
            ]
        except Exception:
            for event in events:
                record_graph_event(event.tenant_id, "error")
            raise

    async def _upsert_events(self, events: list[OCSFEvent]) -> None:
        method = getattr(self._repository, "upsert_events", None)
        if method is not None:
            await method(events)
            return
        for event in events:
            await self._repository.upsert_event(event)

    async def _upsert_entities(self, entities: list[Entity]) -> dict[str, str]:
        method = getattr(self._repository, "upsert_entities", None)
        if method is not None:
            return await method(entities)
        statuses = {}
        for entity in entities:
            statuses[entity.id] = await self._repository.upsert_entity(entity)
        return statuses

    async def _upsert_observations(self, observations: list[tuple[OCSFEvent, Entity]]) -> None:
        method = getattr(self._repository, "upsert_observations", None)
        if method is not None:
            await method(observations)
            return
        for event, entity in observations:
            await self._repository.upsert_observation(event, entity)

    async def _upsert_relationships(self, tenant_id: str, relationships: list[Any]) -> dict[tuple[str, str, str], str]:
        method = getattr(self._repository, "upsert_relationships", None)
        if method is not None:
            return await method(tenant_id, relationships)
        statuses = {}
        for relationship in relationships:
            statuses[(relationship.relationship_type, relationship.from_id, relationship.to_id)] = await self._repository.upsert_relationship(
                tenant_id, relationship
            )
        return statuses

    async def get_entity(self, tenant_id: str, entity_id: str) -> EntityResponse | None:
        return await self._repository.get_entity(tenant_id, entity_id)

    async def list_entities(
        self,
        tenant_id: str,
        entity_type: str | None = None,
        value: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EntityResponse]:
        return await self._repository.list_entities(tenant_id, entity_type=entity_type, value=value, limit=limit, offset=offset)

    async def count_entities_by_type(self, tenant_id: str, value: str | None = None) -> list[EntityTypeCountResponse]:
        return await self._repository.count_entities_by_type(tenant_id, value=value)

    async def list_relationships(self, tenant_id: str, entity_id: str, limit: int = 100) -> list[RelationshipResponse]:
        return await self._repository.list_relationships(tenant_id, entity_id, limit=limit)

    async def list_evidence(self, tenant_id: str, entity_id: str, limit: int = 100) -> list[EvidenceResponse]:
        return await self._repository.list_evidence(tenant_id, entity_id, limit=limit)

    async def list_relationship_evidence(
        self,
        tenant_id: str,
        entity_id: str,
        relationship_id: str,
        limit: int = 100,
    ) -> list[EvidenceResponse]:
        return await self._repository.list_relationship_evidence(tenant_id, entity_id, relationship_id, limit=limit)

    async def get_graph(self, tenant_id: str, entity_id: str, hops: int = 1, limit: int = 200) -> GraphResponse:
        return await self._repository.get_graph(tenant_id, entity_id, hops=hops, limit=limit)

    async def find_path(self, tenant_id: str, source_id: str, target_id: str, max_hops: int = 4, limit: int = 50) -> GraphResponse:
        return await self._repository.find_path(tenant_id, source_id, target_id, max_hops=max_hops, limit=limit)

    def _record_graph_audit(
        self,
        *,
        tenant_id: str,
        action: str,
        target_type: str,
        target_id: str,
        metadata: dict,
    ) -> None:
        if self._audit_logger is None or not action.endswith(("created", "updated")):
            return
        self._audit_logger.record(
            tenant_id=tenant_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            metadata=metadata,
        )

    def _record_graph_audit_many(self, entries: list[dict[str, Any]]) -> None:
        if self._audit_logger is None:
            return
        filtered = [entry for entry in entries if str(entry.get("action", "")).endswith(("created", "updated"))]
        if not filtered:
            return
        record_many = getattr(self._audit_logger, "record_many", None)
        if record_many is not None:
            record_many(filtered)
            return
        for entry in filtered:
            self._audit_logger.record(**entry)


def make_graph_service(repository: GraphRepository) -> GraphService:
    return GraphService(repository)
