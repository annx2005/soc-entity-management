from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.auth.dependencies import TenantContext, get_tenant_context
from app.graph.dependencies import get_graph_service
from app.graph.constants import validate_relationship_type
from app.graph.schemas import (
    EntityResponse,
    EntityTypeCountResponse,
    EvidenceResponse,
    GraphQueryFilters,
    GraphResponse,
    RelationshipResponse,
)
from app.graph.service import GraphService

router = APIRouter(prefix="/api", tags=["graph"])


@router.get("/entities", response_model=list[EntityResponse])
async def list_entities(
    context: Annotated[TenantContext, Depends(get_tenant_context)],
    graph: Annotated[GraphService, Depends(get_graph_service)],
    entity_type: Annotated[Optional[str], Query()] = None,
    value: Annotated[Optional[str], Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[EntityResponse]:
    tenant_id = _tenant_id_or_forbidden(context)
    return await graph.list_entities(tenant_id, entity_type=entity_type, value=value, limit=limit, offset=offset)


@router.get("/entities/stats", response_model=list[EntityTypeCountResponse])
async def get_entity_stats(
    context: Annotated[TenantContext, Depends(get_tenant_context)],
    graph: Annotated[GraphService, Depends(get_graph_service)],
    value: Annotated[Optional[str], Query()] = None,
) -> list[EntityTypeCountResponse]:
    tenant_id = _tenant_id_or_forbidden(context)
    return await graph.count_entities_by_type(tenant_id, value=value)


@router.get("/entities/{entity_id}", response_model=EntityResponse)
async def get_entity(
    entity_id: str,
    context: Annotated[TenantContext, Depends(get_tenant_context)],
    graph: Annotated[GraphService, Depends(get_graph_service)],
) -> EntityResponse:
    tenant_id = _tenant_id_or_forbidden(context)
    entity = await graph.get_entity(tenant_id, entity_id)
    if entity is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="entity not found")
    return entity


@router.get("/entities/{entity_id}/relationships", response_model=list[RelationshipResponse])
async def get_entity_relationships(
    entity_id: str,
    context: Annotated[TenantContext, Depends(get_tenant_context)],
    graph: Annotated[GraphService, Depends(get_graph_service)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[RelationshipResponse]:
    tenant_id = _tenant_id_or_forbidden(context)
    await _require_entity(graph, tenant_id, entity_id)
    return await graph.list_relationships(tenant_id, entity_id, limit=limit)


@router.get("/entities/{entity_id}/evidence", response_model=list[EvidenceResponse])
async def get_entity_evidence(
    entity_id: str,
    context: Annotated[TenantContext, Depends(get_tenant_context)],
    graph: Annotated[GraphService, Depends(get_graph_service)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[EvidenceResponse]:
    tenant_id = _tenant_id_or_forbidden(context)
    await _require_entity(graph, tenant_id, entity_id)
    return await graph.list_evidence(tenant_id, entity_id, limit=limit)


@router.get("/entities/{entity_id}/relationships/{relationship_id}/evidence", response_model=list[EvidenceResponse])
async def get_relationship_evidence(
    entity_id: str,
    relationship_id: str,
    context: Annotated[TenantContext, Depends(get_tenant_context)],
    graph: Annotated[GraphService, Depends(get_graph_service)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[EvidenceResponse]:
    tenant_id = _tenant_id_or_forbidden(context)
    await _require_entity(graph, tenant_id, entity_id)
    evidence = await graph.list_relationship_evidence(tenant_id, entity_id, relationship_id, limit=limit)
    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="relationship evidence not found")
    return evidence


@router.get("/graph/path", response_model=GraphResponse)
async def find_graph_path(
    context: Annotated[TenantContext, Depends(get_tenant_context)],
    graph: Annotated[GraphService, Depends(get_graph_service)],
    source_id: Annotated[str, Query(min_length=1)],
    target_id: Annotated[str, Query(min_length=1)],
    max_hops: Annotated[int, Query(ge=1, le=4)] = 4,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> GraphResponse:
    tenant_id = _tenant_id_or_forbidden(context)
    await _require_entity(graph, tenant_id, source_id)
    await _require_entity(graph, tenant_id, target_id)
    return await graph.find_path(tenant_id, source_id, target_id, max_hops=max_hops, limit=limit)


@router.get("/graph/{entity_id}", response_model=GraphResponse)
async def get_graph(
    entity_id: str,
    context: Annotated[TenantContext, Depends(get_tenant_context)],
    graph: Annotated[GraphService, Depends(get_graph_service)],
    hops: Annotated[int, Query(ge=1, le=4)] = 1,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    relationship_type: Annotated[list[str] | None, Query()] = None,
    from_time: Annotated[datetime | None, Query()] = None,
    to_time: Annotated[datetime | None, Query()] = None,
) -> GraphResponse:
    tenant_id = _tenant_id_or_forbidden(context)
    await _require_entity(graph, tenant_id, entity_id)
    return await graph.get_graph(
        tenant_id,
        entity_id,
        hops=hops,
        limit=limit,
        filters=_graph_query_filters(relationship_type=relationship_type, from_time=from_time, to_time=to_time),
    )


def _tenant_id_or_forbidden(context: TenantContext) -> str:
    if context.tenant_id is None or context.scope != "tenant":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="platform graph querying is not supported")
    return str(context.tenant_id)


async def _require_entity(graph: GraphService, tenant_id: str, entity_id: str) -> EntityResponse:
    entity = await graph.get_entity(tenant_id, entity_id)
    if entity is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="entity not found")
    return entity


def _graph_query_filters(
    *,
    relationship_type: list[str] | None,
    from_time: datetime | None,
    to_time: datetime | None,
) -> GraphQueryFilters:
    try:
        relationship_types = list(dict.fromkeys(validate_relationship_type(item) for item in relationship_type or []))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    normalized_from = _normalize_query_datetime(from_time)
    normalized_to = _normalize_query_datetime(to_time)
    if normalized_from is not None and normalized_to is not None and normalized_from > normalized_to:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="from_time must be before to_time")

    return GraphQueryFilters(
        relationship_types=relationship_types,
        from_time=_datetime_to_query_value(normalized_from),
        to_time=_datetime_to_query_value(normalized_to),
    )


def _normalize_query_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _datetime_to_query_value(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat().replace("+00:00", "Z")
