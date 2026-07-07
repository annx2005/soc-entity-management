from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RawEventMessage(BaseModel):
    schema_version: Literal["soc.raw-event.v1"] = "soc.raw-event.v1"
    message_id: str = Field(default_factory=lambda: str(uuid4()))
    batch_id: int
    tenant_id: str = "default"
    source_name: str
    parser_id: Optional[str] = None
    line_number: int
    raw_line: str
    published_at: datetime = Field(default_factory=utc_now)


class NormalizedEventMessage(BaseModel):
    schema_version: Literal["soc.normalized-event.v1"] = "soc.normalized-event.v1"
    message_id: str = Field(default_factory=lambda: str(uuid4()))
    source_message_id: str
    batch_id: int
    event_id: str
    tenant_id: str
    event_type: str
    source: str
    normalized_event: dict[str, Any]
    published_at: datetime = Field(default_factory=utc_now)


class OCSFEventMessage(BaseModel):
    schema_version: Literal["soc.ocsf-event.v1"] = "soc.ocsf-event.v1"
    message_id: str = Field(default_factory=lambda: str(uuid4()))
    source_message_id: str
    batch_id: int
    event_id: str
    tenant_id: str
    class_uid: int
    class_name: str
    activity_id: int
    activity_name: str
    ocsf_version: str = "1.2.0"
    ocsf_event: dict[str, Any]
    published_at: datetime = Field(default_factory=utc_now)


class DeadLetterMessage(BaseModel):
    schema_version: Literal["soc.ingest-dlq.v1"] = "soc.ingest-dlq.v1"
    message_id: str = Field(default_factory=lambda: str(uuid4()))
    source_message_id: str
    batch_id: int
    source_name: str
    line_number: int
    error_type: str
    message: str
    raw_line: Optional[str] = None
    published_at: datetime = Field(default_factory=utc_now)
