from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


OCSF_VERSION = "1.2.0"


class OCSFEvent(BaseModel):
    """Small OCSF-compatible envelope for the event classes used by this MVP."""

    metadata: dict[str, Any]
    time: int
    class_uid: int
    class_name: str
    category_uid: int
    category_name: str
    activity_id: int
    activity_name: str
    type_uid: int
    type_name: str
    severity_id: int = 1
    raw_data: dict[str, Any]
    unmapped: dict[str, Any] = Field(default_factory=dict)

    tenant_id: str = "default"
    event_id: str
    source_name: str

    actor: Optional[dict[str, Any]] = None
    device: Optional[dict[str, Any]] = None
    src_endpoint: Optional[dict[str, Any]] = None
    dst_endpoint: Optional[dict[str, Any]] = None
    query: Optional[dict[str, Any]] = None
    process: Optional[dict[str, Any]] = None
    file: Optional[dict[str, Any]] = None
    finding: Optional[dict[str, Any]] = None
    vulnerabilities: Optional[list[dict[str, Any]]] = None

    model_config = ConfigDict(extra="allow")

    @property
    def event_type(self) -> str:
        value = self.unmapped.get("event_type")
        return str(value) if value else self.class_name.lower().replace(" ", "_")

    @property
    def source(self) -> str:
        return self.source_name
