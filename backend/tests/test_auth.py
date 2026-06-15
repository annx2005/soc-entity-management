from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.auth import router as auth_router
from app.auth.security import decode_access_token, hash_password
from app.database.models import Account, AccountRole, AccountScope, Tenant
from app.database.session import Base, get_db


def test_login_returns_jwt_and_tenant_context() -> None:
    client = auth_test_client()

    response = client.post(
        "/api/auth/login",
        json={"email": "analyst@acme.com", "password": "correct-password", "tenant_slug": "acme"},
    )

    assert response.status_code == 200
    body = response.json()
    claims = decode_access_token(body["access_token"])

    assert body["token_type"] == "bearer"
    assert body["context"]["tenant_slug"] == "acme"
    assert body["context"]["role"] == "analyst"
    assert claims["tenant_slug"] == "acme"
    assert claims["scope"] == "tenant"

    me_response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me_response.status_code == 200
    assert me_response.json()["email"] == "analyst@acme.com"
    assert me_response.json()["tenant_id"] == body["context"]["tenant_id"]


def test_login_rejects_invalid_password() -> None:
    client = auth_test_client()

    response = client.post(
        "/api/auth/login",
        json={"email": "analyst@acme.com", "password": "wrong-password", "tenant_slug": "acme"},
    )

    assert response.status_code == 401


def test_login_requires_tenant_slug_for_ambiguous_tenant_email() -> None:
    client = auth_test_client(include_duplicate_email=True)

    response = client.post(
        "/api/auth/login",
        json={"email": "analyst@acme.com", "password": "correct-password"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "tenant_slug is required for this email"


def test_platform_login_returns_context_without_tenant() -> None:
    client = auth_test_client()

    response = client.post(
        "/api/auth/login",
        json={"email": "platform@admin.com", "password": "correct-password"},
    )

    assert response.status_code == 200
    body = response.json()
    claims = decode_access_token(body["access_token"])

    assert body["context"]["scope"] == "platform"
    assert body["context"]["tenant_id"] is None
    assert claims["tenant_id"] is None


def auth_test_client(*, include_duplicate_email: bool = False) -> TestClient:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    with TestingSessionLocal() as db:
        seed_auth_data(db, include_duplicate_email=include_duplicate_email)

    app = FastAPI()
    app.include_router(auth_router)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def seed_auth_data(db: Session, *, include_duplicate_email: bool) -> None:
    acme = Tenant(name="Acme", slug="acme")
    db.add(acme)
    db.flush()

    db.add(
        Account(
            tenant_id=acme.id,
            email="analyst@acme.com",
            password_hash=hash_password("correct-password"),
            role=AccountRole.ANALYST,
            scope=AccountScope.TENANT,
        )
    )
    db.add(
        Account(
            email="platform@admin.com",
            password_hash=hash_password("correct-password"),
            role=AccountRole.ADMIN,
            scope=AccountScope.PLATFORM,
        )
    )

    if include_duplicate_email:
        globex = Tenant(name="Globex", slug="globex")
        db.add(globex)
        db.flush()
        db.add(
            Account(
                tenant_id=globex.id,
                email="analyst@acme.com",
                password_hash=hash_password("correct-password"),
                role=AccountRole.VIEWER,
                scope=AccountScope.TENANT,
            )
        )

    db.commit()
