from __future__ import annotations

import uuid
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import events as events_api
from app.api.events import router as events_router
from app.auth.dependencies import TenantContext, get_tenant_context
from app.database.models import ErrorRecord, IngestionBatch, IngestionHistory
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


def test_ingest_file_requires_input_and_maps_file_not_found(monkeypatch) -> None:
    client = events_test_client(context=tenant_context(role="analyst"))

    response = client.post("/api/events/ingest-file-async")
    assert response.status_code == 400

    monkeypatch.setattr(events_api, "enqueue_jsonl_path", lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError("missing")))
    response = client.post("/api/events/ingest-file-async", data={"file_path": "/missing.jsonl"})
    assert response.status_code == 404
    assert response.json()["detail"] == "missing"


def test_ingest_file_upload_uses_authenticated_actor_and_parser(monkeypatch) -> None:
    captured = {}

    async def fake_enqueue_jsonl_bytes(db, content, source_name, *, tenant_id, actor, parser_id):
        captured.update(
            {
                "content": content,
                "source_name": source_name,
                "tenant_id": tenant_id,
                "actor": actor,
                "parser_id": parser_id,
            }
        )
        return SimpleNamespace(
            id=7,
            source_name=source_name,
            parser_id=parser_id,
            status="queued",
            total_records=1,
            normalized_records=0,
            error_records=0,
        )

    monkeypatch.setattr(events_api, "enqueue_jsonl_bytes", fake_enqueue_jsonl_bytes)
    client = events_test_client(context=tenant_context(role="analyst"))

    response = client.post(
        "/api/events/ingest-file-async",
        data={"parser_id": "wazuh-archive"},
        files={"file": ("events.jsonl", b'{"id":"1"}\n', "application/json")},
    )

    assert response.status_code == 200
    assert response.json()["batch_id"] == 7
    assert captured["content"] == b'{"id":"1"}\n'
    assert captured["source_name"] == "events.jsonl"
    assert captured["parser_id"] == "wazuh-archive"


def test_events_read_endpoints_return_rows_and_404_for_missing_batch() -> None:
    client = events_test_client(context=tenant_context(role="analyst"), seed_rows=True)

    errors = client.get("/api/events/errors")
    normalized = client.get("/api/events/normalized")
    batch = client.get("/api/events/batches/1")
    missing = client.get("/api/events/batches/999")

    assert errors.status_code == 200
    assert errors.json()[0]["error_type"] == "json_parse_error"
    assert normalized.status_code == 200
    assert normalized.json()[0]["event_id"] == "evt-1"
    assert batch.status_code == 200
    assert batch.json()["batch_id"] == 1
    assert missing.status_code == 404


def events_test_client(context: TenantContext | None = None, *, seed_rows: bool = False) -> TestClient:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    if seed_rows:
        with TestingSessionLocal() as db:
            batch = IngestionBatch(
                source_name="events.jsonl",
                parser_id="wazuh-archive",
                status="completed",
                total_records=2,
                normalized_records=1,
                error_records=1,
            )
            db.add(batch)
            db.flush()
            db.add(
                IngestionHistory(
                    batch_id=batch.id,
                    event_id="evt-1",
                    event_type="process_execution",
                    source="sysmon",
                    normalized_event={"event_id": "evt-1"},
                )
            )
            db.add(
                ErrorRecord(
                    batch_id=batch.id,
                    line_number=2,
                    error_type="json_parse_error",
                    message="bad json",
                    raw_line="{bad",
                )
            )
            db.commit()

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
