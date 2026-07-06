from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, Field


class EntityType(str, enum.Enum):
    USER = "user"
    HOST = "host"
    IP = "ip"
    DOMAIN = "domain"
    FILE_HASH = "file_hash"
    PROCESS = "process"
    URL = "url"
    EMAIL = "email"
    CVE = "cve"
    CLOUD_RESOURCE = "cloud_resource"


class Entity(BaseModel):
    id: str
    type: EntityType
    value: str
    tenant_id: str
    first_seen: str
    last_seen: str
    source: str
    properties: dict[str, Any] = Field(default_factory=dict)
