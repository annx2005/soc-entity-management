from __future__ import annotations

from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.audit.schemas import AuditLogResponse
from app.audit.service import list_audit_logs
from app.auth.dependencies import TenantContext, get_tenant_context
from app.database.session import get_db

router = APIRouter(prefix="/api/audit-logs", tags=["audit"])


@router.get("", response_model=list[AuditLogResponse])
def get_audit_logs(
    context: Annotated[TenantContext, Depends(get_tenant_context)],
    db: Annotated[Session, Depends(get_db)],
    action: Annotated[Optional[str], Query()] = None,
    target_type: Annotated[Optional[str], Query()] = None,
    target_id: Annotated[Optional[str], Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[AuditLogResponse]:
    tenant_id = _tenant_id_or_forbidden(context)
    return list(
        list_audit_logs(
            db,
            tenant_id=tenant_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            limit=limit,
            offset=offset,
        )
    )


def _tenant_id_or_forbidden(context: TenantContext) -> str:
    if context.tenant_id is None or context.scope != "tenant":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="platform audit querying is not supported")
    return str(context.tenant_id)
