from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.security import hash_password, verify_password
from app.database.models import Account, AccountRole, AccountScope, AccountStatus, Tenant, TenantStatus


class AuthenticationError(ValueError):
    pass


class AmbiguousAccountError(AuthenticationError):
    pass


class RegistrationError(ValueError):
    pass


@dataclass(frozen=True)
class AuthenticatedAccount:
    account: Account
    tenant: Optional[Tenant]


def authenticate_account(db: Session, *, email: str, password: str, tenant_slug: str | None = None) -> AuthenticatedAccount:
    candidate = _find_account(db, email=email, tenant_slug=tenant_slug)
    if candidate is None:
        raise AuthenticationError("invalid credentials")

    account, tenant = candidate.account, candidate.tenant
    if account.status != AccountStatus.ACTIVE:
        raise AuthenticationError("account is disabled")
    if account.scope == AccountScope.TENANT:
        if tenant is None:
            raise AuthenticationError("tenant account is missing tenant")
        if tenant.status != TenantStatus.ACTIVE:
            raise AuthenticationError("tenant is not active")
    if not verify_password(password, account.password_hash):
        raise AuthenticationError("invalid credentials")

    account.last_login_at = datetime.now(timezone.utc)
    db.add(account)
    db.commit()
    db.refresh(account)
    return AuthenticatedAccount(account=account, tenant=tenant)


def register_tenant_account(
    db: Session,
    *,
    tenant_name: str,
    tenant_slug: str,
    email: str,
    password: str,
) -> AuthenticatedAccount:
    existing_tenant = db.execute(select(Tenant).where(Tenant.slug == tenant_slug)).scalar_one_or_none()
    if existing_tenant is not None:
        raise RegistrationError("tenant slug is already in use")

    tenant = Tenant(name=tenant_name, slug=tenant_slug, status=TenantStatus.ACTIVE)
    account = Account(
        tenant_id=None,
        email=email,
        password_hash=hash_password(password),
        role=AccountRole.ADMIN,
        scope=AccountScope.TENANT,
        status=AccountStatus.ACTIVE,
    )

    try:
        db.add(tenant)
        db.flush()
        account.tenant_id = tenant.id
        db.add(account)
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise RegistrationError("unable to create tenant account") from exc

    db.refresh(tenant)
    db.refresh(account)
    return AuthenticatedAccount(account=account, tenant=tenant)


def _find_account(db: Session, *, email: str, tenant_slug: str | None) -> AuthenticatedAccount | None:
    email_normalized = email.strip().lower()
    if tenant_slug:
        stmt = (
            select(Account, Tenant)
            .join(Tenant, Account.tenant_id == Tenant.id)
            .where(
                func.lower(Account.email) == email_normalized,
                Tenant.slug == tenant_slug,
                Account.scope == AccountScope.TENANT,
            )
        )
        row = db.execute(stmt).one_or_none()
        return AuthenticatedAccount(account=row[0], tenant=row[1]) if row else None

    stmt = (
        select(Account, Tenant)
        .outerjoin(Tenant, Account.tenant_id == Tenant.id)
        .where(func.lower(Account.email) == email_normalized)
    )
    rows = db.execute(stmt).all()
    if not rows:
        return None
    if len(rows) > 1:
        raise AmbiguousAccountError("tenant_slug is required for this email")
    account, tenant = rows[0]
    return AuthenticatedAccount(account=account, tenant=tenant)
