from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class LoginRequest(BaseModel):
    email: str
    password: str
    tenant_slug: Optional[str] = None


class TenantContextResponse(BaseModel):
    account_id: str
    tenant_id: Optional[str] = None
    tenant_slug: Optional[str] = None
    email: str
    role: str
    scope: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    context: TenantContextResponse
