from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class AuditLogResponse(BaseModel):
    id: int
    tenant_id: Optional[str]
    action: str
    actor: str
    target_type: str
    target_id: Optional[str]
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    model_config = {"from_attributes": True}
