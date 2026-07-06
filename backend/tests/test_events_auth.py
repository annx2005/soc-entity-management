from __future__ import annotations

import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.events import router as events_router
from app.auth.dependencies import TenantContext, get_tenant_context
from app.database.session import Base, get_db


def test_ingest_file_requires_bearer_token() -> None:
    client = events_test_client()

    response = client.post("/api/events/ingest-file-async", data={"file_path": "/missing.jsonl"})

    assert response.status_code == 401


def test_ingest_file_rejects_viewer_role() -> None:
    client = events_test_client(context=tenant_context(role="viewer"))

    response = client.post("/api/events/ingest-file-async", data={"file_path": "/missing.jsonl"})

    assert response.status_code == 403
    assert response.json()["detail"] == "insufficient role for ingest"


def test_ingest_file_allows_analyst_role() -> None:
    client = events_test_client(context=tenant_context(role="analyst"))

    response = client.post("/api/events/ingest-file-async", data={"file_path": "/missing.jsonl"})

    assert response.status_code == 404


def test_sync_ingest_route_is_removed() -> None:
    client = events_test_client(context=tenant_context(role="analyst"))

    response = client.post("/api/events/ingest-file", data={"file_path": "/missing.jsonl"})

    assert response.status_code == 404


def events_test_client(context: TenantContext | None = None) -> TestClient:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    app = FastAPI()
    app.include_router(events_router)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    if context is not None:
        app.dependency_overrides[get_tenant_context] = lambda: context
    return TestClient(app)


def tenant_context(role: str) -> TenantContext:
    return TenantContext(
        account_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        tenant_slug="workspace",
        email="analyst@example.com",
        role=role,
        scope="tenant",
    )
