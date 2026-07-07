from __future__ import annotations

import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.audit import router as audit_router
from app.auth.dependencies import TenantContext, get_tenant_context
from app.audit.service import AuditLogger, list_audit_logs, record_audit_log
from app.database.models import AuditLog
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


def test_audit_service_filters_and_logger_records_many() -> None:
    TestingSessionLocal = audit_session_factory()
    with TestingSessionLocal() as db:
        record_audit_log(
            db,
            tenant_id=TENANT_ID,
            action="entity_created",
            actor="alice",
            target_type="entity",
            target_id="entity-a",
            metadata={"entity_type": "ip"},
        )
        record_audit_log(
            db,
            tenant_id=TENANT_ID,
            action="relationship_created",
            actor="alice",
            target_type="relationship",
            target_id="rel-a",
        )
        record_audit_log(
            db,
            tenant_id=OTHER_TENANT_ID,
            action="entity_created",
            actor="bob",
            target_type="entity",
            target_id="entity-b",
        )
        db.commit()

        filtered = list_audit_logs(db, tenant_id=TENANT_ID, action="entity_created", target_type="entity", target_id="entity-a")

    assert [item.target_id for item in filtered] == ["entity-a"]
    assert filtered[0].metadata_json == {"entity_type": "ip"}

    logger = AuditLogger(TestingSessionLocal, actor="system-test")
    logger.record(tenant_id=TENANT_ID, action="entity_updated", target_type="entity", target_id="entity-a", metadata={"count": 2})
    logger.record_many([])
    logger.record_many(
        [
            {"tenant_id": TENANT_ID, "action": "bulk_created", "target_type": "entity", "target_id": "entity-c"},
            {
                "tenant_id": TENANT_ID,
                "action": "bulk_updated",
                "actor": "worker",
                "target_type": "entity",
                "target_id": "entity-d",
                "metadata": {"batch": 1},
            },
        ]
    )

    with TestingSessionLocal() as db:
        logs = db.scalars(select(AuditLog).where(AuditLog.tenant_id == TENANT_ID).order_by(AuditLog.id)).all()

    assert [log.action for log in logs] == [
        "entity_created",
        "relationship_created",
        "entity_updated",
        "bulk_created",
        "bulk_updated",
    ]
    assert logs[-2].actor == "system-test"
    assert logs[-1].actor == "worker"
    assert logs[-1].metadata_json == {"batch": 1}


def audit_test_client() -> TestClient:
    TestingSessionLocal = audit_session_factory()
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


def audit_session_factory():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    return TestingSessionLocal
