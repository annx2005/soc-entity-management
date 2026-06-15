from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import CheckConstraint, DateTime, Enum, ForeignKey, Index, Integer, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON, Uuid

from app.database.session import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


JsonType = MutableDict.as_mutable(JSON().with_variant(JSONB, "postgresql"))


def enum_values(enum_cls: type[enum.Enum]) -> list[str]:
    return [item.value for item in enum_cls]


class TenantStatus(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DELETED = "deleted"


class AccountRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class AccountScope(str, enum.Enum):
    TENANT = "tenant"
    PLATFORM = "platform"


class AccountStatus(str, enum.Enum):
    ACTIVE = "active"
    DISABLED = "disabled"


TenantStatusType = Enum(
    TenantStatus,
    values_callable=enum_values,
    name="tenant_status",
    native_enum=True,
    create_constraint=True,
)
AccountRoleType = Enum(
    AccountRole,
    values_callable=enum_values,
    name="account_role",
    native_enum=True,
    create_constraint=True,
)
AccountScopeType = Enum(
    AccountScope,
    values_callable=enum_values,
    name="account_scope",
    native_enum=True,
    create_constraint=True,
)
AccountStatusType = Enum(
    AccountStatus,
    values_callable=enum_values,
    name="account_status",
    native_enum=True,
    create_constraint=True,
)


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    status: Mapped[TenantStatus] = mapped_column(TenantStatusType, nullable=False, default=TenantStatus.ACTIVE)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    __table_args__ = (Index("idx_tenants_status", "status"),)


class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=True,
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[AccountRole] = mapped_column(AccountRoleType, nullable=False, default=AccountRole.VIEWER)
    scope: Mapped[AccountScope] = mapped_column(AccountScopeType, nullable=False, default=AccountScope.TENANT)
    status: Mapped[AccountStatus] = mapped_column(AccountStatusType, nullable=False, default=AccountStatus.ACTIVE)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "(scope = 'platform' AND tenant_id IS NULL) OR (scope = 'tenant' AND tenant_id IS NOT NULL)",
            name="chk_accounts_scope_tenant_consistency",
        ),
        UniqueConstraint("tenant_id", "email", name="uq_accounts_tenant_id_email"),
        Index("idx_accounts_tenant_id", "tenant_id"),
        Index("idx_accounts_email", "email"),
        Index(
            "uq_accounts_platform_email",
            "email",
            unique=True,
            postgresql_where=text("scope = 'platform'"),
            sqlite_where=text("scope = 'platform'"),
        ),
    )


class IngestionBatch(Base):
    __tablename__ = "ingestion_batches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    source_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="running")
    total_records: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    normalized_records: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_records: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class IngestionHistory(Base):
    __tablename__ = "ingestion_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    batch_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    event_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    normalized_event: Mapped[dict] = mapped_column(JsonType, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class ErrorRecord(Base):
    __tablename__ = "error_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    batch_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    line_number: Mapped[int] = mapped_column(Integer, nullable=False)
    error_type: Mapped[str] = mapped_column(String(100), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    raw_line: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class JobStatus(Base):
    __tablename__ = "job_status"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    batch_id: Mapped[Optional[int]] = mapped_column(Integer, index=True, nullable=True)
    job_type: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    details: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    actor: Mapped[str] = mapped_column(String(100), nullable=False, default="system")
    target_type: Mapped[str] = mapped_column(String(100), nullable=False)
    target_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
