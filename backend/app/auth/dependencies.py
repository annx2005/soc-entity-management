from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Annotated, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.auth.security import TokenError, decode_access_token
from app.database.models import Account, AccountScope, AccountStatus, Tenant, TenantStatus
from app.database.session import get_db


bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class TenantContext:
    account_id: uuid.UUID
    tenant_id: Optional[uuid.UUID]
    tenant_slug: Optional[str]
    email: str
    role: str
    scope: str


def get_tenant_context(
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(bearer_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> TenantContext:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _unauthorized("missing bearer token")

    try:
        payload = decode_access_token(credentials.credentials)
        account_id = uuid.UUID(str(payload.get("sub")))
    except (TokenError, ValueError, TypeError):
        raise _unauthorized("invalid bearer token")

    account = db.get(Account, account_id)
    if account is None or account.status != AccountStatus.ACTIVE:
        raise _unauthorized("account is not active")

    tenant: Tenant | None = None
    if account.scope == AccountScope.TENANT:
        if account.tenant_id is None:
            raise _unauthorized("tenant account is missing tenant")
        tenant = db.get(Tenant, account.tenant_id)
        if tenant is None or tenant.status != TenantStatus.ACTIVE:
            raise _unauthorized("tenant is not active")

    token_scope = payload.get("scope")
    token_tenant_id = payload.get("tenant_id")
    if token_scope != account.scope.value:
        raise _unauthorized("token scope no longer matches account")
    if account.scope == AccountScope.TENANT and token_tenant_id != str(account.tenant_id):
        raise _unauthorized("token tenant no longer matches account")
    if account.scope == AccountScope.PLATFORM and token_tenant_id is not None:
        raise _unauthorized("platform token must not contain tenant")

    return TenantContext(
        account_id=account.id,
        tenant_id=account.tenant_id,
        tenant_slug=tenant.slug if tenant else None,
        email=account.email,
        role=account.role.value,
        scope=account.scope.value,
    )


def _unauthorized(message: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=message,
        headers={"WWW-Authenticate": "Bearer"},
    )
