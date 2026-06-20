from __future__ import annotations

import re
from typing import Optional

from pydantic import BaseModel, field_validator


SLUG_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,48}[a-z0-9])?$")


class LoginRequest(BaseModel):
    email: str
    password: str
    tenant_slug: Optional[str] = None

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        email = value.strip().lower()
        if "@" not in email or email.startswith("@") or email.endswith("@"):
            raise ValueError("email must be a valid address")
        return email

    @field_validator("tenant_slug")
    @classmethod
    def normalize_tenant_slug(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        slug = value.strip().lower()
        if not slug:
            return None
        if not SLUG_PATTERN.fullmatch(slug):
            raise ValueError("tenant_slug must use lowercase letters, numbers, or hyphens")
        return slug


class RegisterRequest(BaseModel):
    tenant_name: str
    tenant_slug: str
    email: str
    password: str

    @field_validator("tenant_name")
    @classmethod
    def validate_tenant_name(cls, value: str) -> str:
        tenant_name = value.strip()
        if len(tenant_name) < 2:
            raise ValueError("tenant_name must be at least 2 characters")
        if len(tenant_name) > 255:
            raise ValueError("tenant_name must be at most 255 characters")
        return tenant_name

    @field_validator("tenant_slug")
    @classmethod
    def validate_tenant_slug(cls, value: str) -> str:
        slug = value.strip().lower()
        if not SLUG_PATTERN.fullmatch(slug):
            raise ValueError("tenant_slug must use lowercase letters, numbers, or hyphens")
        return slug

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        email = value.strip().lower()
        if "@" not in email or email.startswith("@") or email.endswith("@"):
            raise ValueError("email must be a valid address")
        return email

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        password = value.strip()
        if len(password) < 8:
            raise ValueError("password must be at least 8 characters")
        return password


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
