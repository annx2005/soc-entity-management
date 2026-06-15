from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel


class IngestFileResponse(BaseModel):
    batch_id: int
    source_name: str
    status: str
    total_records: int
    normalized_records: int
    error_records: int


class ErrorRecordResponse(BaseModel):
    id: int
    batch_id: int
    line_number: int
    error_type: str
    message: str
    raw_line: Optional[str]

    model_config = {"from_attributes": True}


class NormalizedEventResponse(BaseModel):
    id: int
    batch_id: int
    event_id: str
    event_type: str
    source: str
    normalized_event: dict[str, Any]

    model_config = {"from_attributes": True}
