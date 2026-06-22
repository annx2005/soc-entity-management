from __future__ import annotations

import asyncio
import io
import json

from pydantic import BaseModel
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.database.models import AuditLog, ErrorRecord, IngestionBatch, IngestionHistory
from app.database.session import Base
from app.ingestion.kafka_messages import DeadLetterMessage, OCSFEventMessage, RawEventMessage
from app.ingestion.kafka_service import enqueue_jsonl_stream, process_raw_event_message


class FakePublisher:
    def __init__(self) -> None:
        self.sent: list[tuple[str, BaseModel, str | None, dict[str, str] | None]] = []

    async def send(self, topic: str, payload: BaseModel, key: str | None = None, headers: dict[str, str] | None = None) -> None:
        self.sent.append((topic, payload, key, headers))


def sqlite_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    return Session(engine)


def sysmon_dns_record(event_id: str = "evt-1") -> dict:
    return {
        "id": event_id,
        "timestamp": "2026-07-02T14:50:01.005+0000",
        "tenant_id": "tenant-acme",
        "agent": {"name": "acme-ws-01", "ip": "10.10.1.24"},
        "data": {
            "win": {
                "system": {
                    "eventID": "22",
                    "systemTime": "2026-07-02T14:50:00.000Z",
                    "computer": "acme-ws-01",
                },
                "eventdata": {
                    "user": r"ACME\alice",
                    "queryName": "Example.COM.",
                    "queryResults": "type: 1 example.com;198.51.100.23;",
                    "image": r"C:\Windows\System32\curl.exe",
                },
            }
        },
    }


def test_enqueue_jsonl_stream_publishes_raw_events_and_tracks_batch() -> None:
    publisher = FakePublisher()
    content = io.StringIO("\n".join([json.dumps(sysmon_dns_record("evt-1")), "", json.dumps(sysmon_dns_record("evt-2"))]))

    with sqlite_session() as db:
        batch = asyncio.run(enqueue_jsonl_stream(db, content, "events.jsonl", publisher, tenant_id="trusted-tenant"))

        assert batch.status == "queued"
        assert batch.total_records == 2
        assert len(publisher.sent) == 2
        assert all(sent[2] == str(batch.id) for sent in publisher.sent)
        assert all(sent[1].tenant_id == "trusted-tenant" for sent in publisher.sent)
        assert [sent[1].line_number for sent in publisher.sent] == [1, 3]
        audit_actions = db.scalars(select(AuditLog.action).order_by(AuditLog.id)).all()
        assert audit_actions == ["ingest_batch_started", "ingest_batch_queued"]


def test_process_raw_event_message_persists_normalized_event_and_publishes_downstream() -> None:
    publisher = FakePublisher()

    with sqlite_session() as db:
        batch = IngestionBatch(source_name="events.jsonl", status="queued", total_records=1)
        db.add(batch)
        db.commit()
        db.refresh(batch)

        message = RawEventMessage(
            batch_id=batch.id,
            tenant_id="trusted-tenant",
            source_name=batch.source_name,
            line_number=1,
            raw_line=json.dumps(sysmon_dns_record()),
        )
        asyncio.run(process_raw_event_message(db, message, publisher))

        history = db.scalar(select(IngestionHistory))
        updated_batch = db.get(IngestionBatch, batch.id)

        assert history is not None
        assert history.event_type == "dns_query"
        assert history.normalized_event["tenant_id"] == "trusted-tenant"
        assert history.normalized_event["unmapped"]["raw_tenant_id"] == "tenant-acme"
        assert history.normalized_event["class_uid"] == 4003
        assert history.normalized_event["query"]["hostname"] == "example.com"
        assert updated_batch is not None
        assert updated_batch.status == "completed"
        assert updated_batch.normalized_records == 1
        assert len(publisher.sent) == 1
        assert isinstance(publisher.sent[0][1], OCSFEventMessage)
        assert publisher.sent[0][1].tenant_id == "trusted-tenant"
        assert publisher.sent[0][1].ocsf_event["tenant_id"] == "trusted-tenant"
        assert publisher.sent[0][0] == "soc.ocsf-events.v1"
        audit_actions = db.scalars(select(AuditLog.action).order_by(AuditLog.id)).all()
        assert audit_actions == ["tenant_mismatch_detected", "ingest_batch_completed"]


def test_process_raw_event_message_records_error_and_publishes_dlq() -> None:
    publisher = FakePublisher()

    with sqlite_session() as db:
        batch = IngestionBatch(source_name="events.jsonl", status="queued", total_records=1)
        db.add(batch)
        db.commit()
        db.refresh(batch)

        message = RawEventMessage(batch_id=batch.id, source_name=batch.source_name, line_number=1, raw_line="{bad json")
        asyncio.run(process_raw_event_message(db, message, publisher))

        error = db.scalar(select(ErrorRecord))
        updated_batch = db.get(IngestionBatch, batch.id)

        assert error is not None
        assert error.error_type == "json_parse_error"
        assert updated_batch is not None
        assert updated_batch.status == "completed"
        assert updated_batch.error_records == 1
        assert len(publisher.sent) == 1
        assert isinstance(publisher.sent[0][1], DeadLetterMessage)
        completed = db.scalar(select(AuditLog).where(AuditLog.action == "ingest_batch_completed"))
        assert completed is not None


def test_process_raw_event_message_records_unsupported_event_and_publishes_dlq() -> None:
    publisher = FakePublisher()

    with sqlite_session() as db:
        batch = IngestionBatch(source_name="events.jsonl", status="queued", total_records=1)
        db.add(batch)
        db.commit()
        db.refresh(batch)

        unsupported_record = {"id": "evt-unsupported", "timestamp": "2026-07-02T14:50:01.005+0000", "data": {}}
        message = RawEventMessage(batch_id=batch.id, source_name=batch.source_name, line_number=1, raw_line=json.dumps(unsupported_record))
        asyncio.run(process_raw_event_message(db, message, publisher))

        error = db.scalar(select(ErrorRecord))
        updated_batch = db.get(IngestionBatch, batch.id)

        assert error is not None
        assert error.error_type == "unsupported_event"
        assert updated_batch is not None
        assert updated_batch.status == "completed"
        assert updated_batch.error_records == 1
        assert len(publisher.sent) == 1
        assert isinstance(publisher.sent[0][1], DeadLetterMessage)


def test_process_raw_event_message_counts_duplicate_event_as_processed_without_republishing() -> None:
    publisher = FakePublisher()

    with sqlite_session() as db:
        batch = IngestionBatch(source_name="events.jsonl", status="queued", total_records=2)
        db.add(batch)
        db.commit()
        db.refresh(batch)

        message = RawEventMessage(
            batch_id=batch.id,
            tenant_id="trusted-tenant",
            source_name=batch.source_name,
            line_number=1,
            raw_line=json.dumps(sysmon_dns_record("evt-dup")),
        )
        asyncio.run(process_raw_event_message(db, message, publisher))

        duplicate_message = RawEventMessage(
            batch_id=batch.id,
            tenant_id="trusted-tenant",
            source_name=batch.source_name,
            line_number=2,
            raw_line=json.dumps(sysmon_dns_record("evt-dup")),
        )
        asyncio.run(process_raw_event_message(db, duplicate_message, publisher))

        history = db.scalars(select(IngestionHistory)).all()
        updated_batch = db.get(IngestionBatch, batch.id)

        assert len(history) == 1
        assert updated_batch is not None
        assert updated_batch.normalized_records == 2
        assert updated_batch.error_records == 0
        assert updated_batch.status == "completed"
        assert len(publisher.sent) == 1
        assert isinstance(publisher.sent[0][1], OCSFEventMessage)
