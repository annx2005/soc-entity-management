from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class RelationshipCandidate(BaseModel):
    relationship_type: str
    from_id: str
    to_id: str
    evidence_ref: str
    observed_at: str


class EntityResponse(BaseModel):
    id: str
    tenant_id: str
    entity_type: str
    value: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    source: Optional[str] = None
    properties: dict[str, Any] = Field(default_factory=dict)


class EntityTypeCountResponse(BaseModel):
    entity_type: str
    count: int


class RelationshipResponse(BaseModel):
    id: str
    tenant_id: str
    relationship_type: str
    from_id: str
    to_id: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    count: int = 0
    sample_evidence_refs: list[str] = Field(default_factory=list)


class EvidenceResponse(BaseModel):
    event_id: str
    time: Optional[str] = None
    class_uid: Optional[int] = None
    class_name: Optional[str] = None
    activity_id: Optional[int] = None
    activity_name: Optional[str] = None
    source_name: Optional[str] = None
    field_path: Optional[str] = None
    value: Optional[str] = None
    relationship_id: Optional[str] = None


class GraphNode(BaseModel):
    id: str
    labels: list[str]
    properties: dict[str, Any]


class GraphEdge(BaseModel):
    id: str
    type: str
    start_id: str
    end_id: str
    properties: dict[str, Any]


class GraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class GraphQueryFilters(BaseModel):
    relationship_types: list[str] = Field(default_factory=list)
    from_time: Optional[str] = None
    to_time: Optional[str] = None


class GraphIngestResult(BaseModel):
    tenant_id: str
    event_id: str
    entities: int
    observations: int
    relationships: int
    status: Literal["processed"] = "processed"
