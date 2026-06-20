from __future__ import annotations

from typing import Protocol

from app.entities.extractor import extract_entities
from app.entities.schemas import Entity
from app.enrichment.service import EnrichmentService
from app.graph.inference import infer_relationships
from app.graph.repository import GraphRepository
from app.graph.schemas import EntityResponse, EvidenceResponse, GraphIngestResult, GraphResponse, RelationshipResponse
from app.ocsf.schemas import OCSFEvent


class GraphRepositoryProtocol(Protocol):
    async def ensure_schema(self) -> None:
        ...

    async def upsert_event(self, event: OCSFEvent) -> str:
        ...

    async def upsert_entity(self, entity: Entity) -> None:
        ...

    async def upsert_observation(self, event: OCSFEvent, entity: Entity) -> str:
        ...

    async def upsert_relationship(self, tenant_id: str, candidate) -> None:
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

    async def list_relationships(self, tenant_id: str, entity_id: str, limit: int = 100) -> list[RelationshipResponse]:
        ...

    async def list_evidence(self, tenant_id: str, entity_id: str, limit: int = 100) -> list[EvidenceResponse]:
        ...

    async def get_graph(self, tenant_id: str, entity_id: str, hops: int = 1, limit: int = 200) -> GraphResponse:
        ...


class GraphService:
    def __init__(self, repository: GraphRepositoryProtocol, enrichment_service: EnrichmentService | None = None):
        self._repository = repository
        self._enrichment_service = enrichment_service

    async def ensure_schema(self) -> None:
        await self._repository.ensure_schema()

    async def process_event(self, event: OCSFEvent) -> GraphIngestResult:
        await self._repository.ensure_schema()
        await self._repository.upsert_event(event)

        entities = extract_entities(event)
        if self._enrichment_service is not None:
            entities = await self._enrichment_service.enrich_entities(event.tenant_id, entities)
        for entity in entities:
            await self._repository.upsert_entity(entity)
            await self._repository.upsert_observation(event, entity)

        relationships = infer_relationships(event, entities)
        for relationship in relationships:
            await self._repository.upsert_relationship(event.tenant_id, relationship)

        return GraphIngestResult(
            tenant_id=event.tenant_id,
            event_id=event.event_id,
            entities=len(entities),
            observations=len(entities),
            relationships=len(relationships),
        )

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

    async def list_relationships(self, tenant_id: str, entity_id: str, limit: int = 100) -> list[RelationshipResponse]:
        return await self._repository.list_relationships(tenant_id, entity_id, limit=limit)

    async def list_evidence(self, tenant_id: str, entity_id: str, limit: int = 100) -> list[EvidenceResponse]:
        return await self._repository.list_evidence(tenant_id, entity_id, limit=limit)

    async def get_graph(self, tenant_id: str, entity_id: str, hops: int = 1, limit: int = 200) -> GraphResponse:
        return await self._repository.get_graph(tenant_id, entity_id, hops=hops, limit=limit)


def make_graph_service(repository: GraphRepository) -> GraphService:
    return GraphService(repository)
