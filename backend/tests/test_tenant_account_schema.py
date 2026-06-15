from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database.models import Account, AccountRole, AccountScope, Tenant
from app.database.session import Base


def sqlite_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    return Session(engine)


def test_account_scope_rejects_platform_account_with_tenant_id() -> None:
    with sqlite_session() as db:
        tenant = Tenant(name="Acme", slug="acme")
        db.add(tenant)
        db.commit()

        db.add(
            Account(
                tenant_id=tenant.id,
                email="super@admin.com",
                password_hash="hash",
                role=AccountRole.ADMIN,
                scope=AccountScope.PLATFORM,
            )
        )

        try:
            db.commit()
        except IntegrityError:
            db.rollback()
        else:
            raise AssertionError("platform account with tenant_id should violate scope/tenant constraint")


def test_account_scope_rejects_tenant_account_without_tenant_id() -> None:
    with sqlite_session() as db:
        db.add(
            Account(
                email="analyst@acme.com",
                password_hash="hash",
                role=AccountRole.ANALYST,
                scope=AccountScope.TENANT,
            )
        )

        try:
            db.commit()
        except IntegrityError:
            db.rollback()
        else:
            raise AssertionError("tenant account without tenant_id should violate scope/tenant constraint")


def test_same_email_can_exist_in_different_tenants() -> None:
    with sqlite_session() as db:
        acme = Tenant(name="Acme", slug="acme")
        globex = Tenant(name="Globex", slug="globex")
        db.add_all([acme, globex])
        db.commit()

        db.add_all(
            [
                Account(
                    tenant_id=acme.id,
                    email="admin@company.com",
                    password_hash="hash1",
                    role=AccountRole.ADMIN,
                    scope=AccountScope.TENANT,
                ),
                Account(
                    tenant_id=globex.id,
                    email="admin@company.com",
                    password_hash="hash2",
                    role=AccountRole.ADMIN,
                    scope=AccountScope.TENANT,
                ),
            ]
        )
        db.commit()


def test_platform_email_is_unique_globally() -> None:
    with sqlite_session() as db:
        db.add_all(
            [
                Account(
                    email="platform@admin.com",
                    password_hash="hash1",
                    role=AccountRole.ADMIN,
                    scope=AccountScope.PLATFORM,
                ),
                Account(
                    email="platform@admin.com",
                    password_hash="hash2",
                    role=AccountRole.ADMIN,
                    scope=AccountScope.PLATFORM,
                ),
            ]
        )

        try:
            db.commit()
        except IntegrityError:
            db.rollback()
        else:
            raise AssertionError("platform account email should be globally unique")
