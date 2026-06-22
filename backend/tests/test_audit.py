from __future__ import annotations

import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.audit import router as audit_router
from app.auth.dependencies import TenantContext, get_tenant_context
from app.audit.service import record_audit_log
from app.database.session import Base, get_db


TENANT_ID = "00000000-0000-0000-0000-000000000001"
OTHER_TENANT_ID = "00000000-0000-0000-0000-000000000002"


def test_audit_logs_endpoint_is_tenant_scoped() -> None:
    client = audit_test_client()

    response = client.get("/api/audit-logs", headers={"Authorization": "Bearer test"})

    assert response.status_code == 200
    body = response.json()
    assert [item["target_id"] for item in body] == ["entity-a"]
    assert body[0]["action"] == "entity_created"


def audit_test_client() -> TestClient:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    with TestingSessionLocal() as db:
        record_audit_log(
            db,
            tenant_id=TENANT_ID,
            action="entity_created",
            actor="system",
            target_type="entity",
            target_id="entity-a",
        )
        record_audit_log(
            db,
            tenant_id=OTHER_TENANT_ID,
            action="entity_created",
            actor="system",
            target_type="entity",
            target_id="entity-b",
        )
        db.commit()

    app = FastAPI()
    app.include_router(audit_router)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_tenant_context] = lambda: TenantContext(
        account_id=uuid.uuid4(),
        tenant_id=uuid.UUID(TENANT_ID),
        tenant_slug="workspace",
        email="analyst@example.com",
        role="analyst",
        scope="tenant",
    )
    return TestClient(app)
