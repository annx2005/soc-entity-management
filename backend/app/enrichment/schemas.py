from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


CacheStatus = Literal["hit", "miss", "disabled", "error"]


class EnrichmentResult(BaseModel):
    entity_type: str
    value: str
    data: dict[str, Any] = Field(default_factory=dict)
    source: str
    cache_status: CacheStatus
