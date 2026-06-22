from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import AuditLog


def record_audit_log(
    db: Session,
    *,
    tenant_id: str | None,
    action: str,
    target_type: str,
    target_id: str | None = None,
    actor: str = "system",
    metadata: dict[str, Any] | None = None,
) -> AuditLog:
    log = AuditLog(
        tenant_id=tenant_id,
        action=action,
        actor=actor,
        target_type=target_type,
        target_id=target_id,
        metadata_json=metadata or {},
    )
    db.add(log)
    return log


def list_audit_logs(
    db: Session,
    *,
    tenant_id: str,
    limit: int = 100,
    offset: int = 0,
    action: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
) -> Iterable[AuditLog]:
    stmt = select(AuditLog).where(AuditLog.tenant_id == tenant_id)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if target_type:
        stmt = stmt.where(AuditLog.target_type == target_type)
    if target_id:
        stmt = stmt.where(AuditLog.target_id == target_id)
    stmt = stmt.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).offset(offset).limit(limit)
    return db.scalars(stmt).all()


class AuditLogger:
    def __init__(self, session_factory: Callable[[], Session], actor: str = "system"):
        self._session_factory = session_factory
        self._actor = actor

    def record(
        self,
        *,
        tenant_id: str | None,
        action: str,
        target_type: str,
        target_id: str | None = None,
        actor: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        with self._session_factory() as db:
            record_audit_log(
                db,
                tenant_id=tenant_id,
                action=action,
                target_type=target_type,
                target_id=target_id,
                actor=actor or self._actor,
                metadata=metadata,
            )
            db.commit()
