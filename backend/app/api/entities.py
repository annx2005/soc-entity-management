from __future__ import annotations

from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.auth.dependencies import TenantContext, get_tenant_context
from app.graph.dependencies import get_graph_service
from app.graph.schemas import EntityResponse, EvidenceResponse, GraphResponse, RelationshipResponse
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


@router.get("/graph/{entity_id}", response_model=GraphResponse)
async def get_graph(
    entity_id: str,
    context: Annotated[TenantContext, Depends(get_tenant_context)],
    graph: Annotated[GraphService, Depends(get_graph_service)],
    hops: Annotated[int, Query(ge=1, le=2)] = 1,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> GraphResponse:
    tenant_id = _tenant_id_or_forbidden(context)
    await _require_entity(graph, tenant_id, entity_id)
    return await graph.get_graph(tenant_id, entity_id, hops=hops, limit=limit)


def _tenant_id_or_forbidden(context: TenantContext) -> str:
    if context.tenant_id is None or context.scope != "tenant":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="platform graph querying is not supported")
    return str(context.tenant_id)


async def _require_entity(graph: GraphService, tenant_id: str, entity_id: str) -> EntityResponse:
    entity = await graph.get_entity(tenant_id, entity_id)
    if entity is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="entity not found")
    return entity
