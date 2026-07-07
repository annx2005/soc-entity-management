from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path

from pydantic import BaseModel
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.database.models import AuditLog, ErrorRecord, IngestionBatch, IngestionHistory
from app.database.session import Base
from app.ingestion.kafka_messages import DeadLetterMessage, OCSFEventMessage, RawEventMessage
from app.ingestion.kafka_service import enqueue_jsonl_stream, process_raw_event_message
from app.ingestion.kafka_service import process_raw_event_messages


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
        batch = asyncio.run(enqueue_jsonl_stream(db, content, "events.jsonl", publisher, tenant_id="trusted-tenant", parser_id="auto"))

        assert batch.status == "queued"
        assert batch.parser_id == "auto"
        assert batch.total_records == 2
        assert len(publisher.sent) == 2
        assert all(sent[2] == str(batch.id) for sent in publisher.sent)
        assert all(sent[1].tenant_id == "trusted-tenant" for sent in publisher.sent)
        assert all(sent[1].parser_id == "auto" for sent in publisher.sent)
        assert [sent[1].line_number for sent in publisher.sent] == [1, 3]
        audit_actions = db.scalars(select(AuditLog.action).order_by(AuditLog.id)).all()
        assert audit_actions == ["ingest_batch_started", "ingest_batch_queued"]


def test_enqueue_json_bytes_accepts_utf16_json_array() -> None:
    from app.ingestion.kafka_service import enqueue_jsonl_bytes

    publisher = FakePublisher()
    content = (Path(__file__).resolve().parents[2] / "sysmon_events.json").read_bytes()

    with sqlite_session() as db:
        batch = asyncio.run(enqueue_jsonl_bytes(db, content, "sysmon_events.json", publisher, tenant_id="trusted-tenant", parser_id="sysmon"))

        assert batch.status == "queued"
        assert batch.total_records == 100
        assert len(publisher.sent) == 100
        assert all(sent[1].parser_id == "sysmon" for sent in publisher.sent)


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


def test_process_raw_event_message_uses_explicit_config_parser() -> None:
    publisher = FakePublisher()
    record = {
        "TimeCreated": "/Date(1783002881751)/",
        "Id": 1,
        "ProviderName": "Microsoft-Windows-Sysmon",
        "Message": (
            "Process Create:\r\n"
            "UtcTime: 2026-07-02 14:34:41.749\r\n"
            "Image: C:\\Windows\\System32\\cmd.exe\r\n"
            "CommandLine: cmd.exe /c whoami\r\n"
            "User: NT AUTHORITY\\SYSTEM\r\n"
            "Hashes: SHA256=642A07EEEA4D3132426E673FB3C88BE8CEAD3D03CA1F019C7E7D0000ED2122BE"
        ),
    }

    with sqlite_session() as db:
        batch = IngestionBatch(source_name="sysmon_events.json", parser_id="sysmon", status="queued", total_records=1)
        db.add(batch)
        db.commit()
        db.refresh(batch)

        message = RawEventMessage(
            batch_id=batch.id,
            tenant_id="trusted-tenant",
            source_name=batch.source_name,
            parser_id=batch.parser_id,
            line_number=1,
            raw_line=json.dumps(record),
        )
        asyncio.run(process_raw_event_message(db, message, publisher))

        history = db.scalar(select(IngestionHistory))
        assert history is not None
        assert history.event_type == "process_execution"
        assert history.source == "sysmon"
        assert history.normalized_event["actor"]["user"]["name"] == "NT AUTHORITY\\SYSTEM"
        assert history.normalized_event["tenant_id"] == "trusted-tenant"


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


def ocsf_auth_event(event_id: str = "ocsf-evt-1", tenant_id: str = "raw-tenant") -> dict:
    return {
        "metadata": {"version": "1.2.0", "uid": event_id},
        "time": 1783000000000,
        "class_uid": 3002,
        "class_name": "Authentication",
        "category_uid": 3,
        "category_name": "Identity & Access Management",
        "activity_id": 1,
        "activity_name": "Logon",
        "type_uid": 300201,
        "type_name": "Authentication: Logon",
        "severity_id": 1,
        "tenant_id": tenant_id,
        "event_id": event_id,
        "source_name": "ocsf-direct",
        "raw_data": {},
        "unmapped": {"event_type": "ocsf_auth"},
        "actor": {"user": {"name": "alice", "email": "alice@example.com"}},
        "device": {"hostname": "host-a"},
    }


def test_process_raw_event_message_accepts_ocsf_passthrough_and_overrides_tenant() -> None:
    publisher = FakePublisher()

    with sqlite_session() as db:
        batch = IngestionBatch(source_name="ocsf.jsonl", status="queued", total_records=1)
        db.add(batch)
        db.commit()
        db.refresh(batch)

        message = RawEventMessage(
            batch_id=batch.id,
            tenant_id="trusted-tenant",
            source_name=batch.source_name,
            line_number=1,
            raw_line=json.dumps(ocsf_auth_event()),
        )
        asyncio.run(process_raw_event_message(db, message, publisher))

        history = db.scalar(select(IngestionHistory))
        assert history is not None
        assert history.event_id == "ocsf-evt-1"
        assert history.normalized_event["tenant_id"] == "trusted-tenant"
        assert history.normalized_event["unmapped"]["raw_tenant_id"] == "raw-tenant"
        assert publisher.sent[0][1].ocsf_event["source_name"] == "ocsf-direct"


def test_process_raw_event_messages_batches_success_errors_duplicates_and_dlq() -> None:
    publisher = FakePublisher()

    with sqlite_session() as db:
        batch = IngestionBatch(source_name="batch.jsonl", status="queued", total_records=4)
        db.add(batch)
        db.commit()
        db.refresh(batch)

        messages = [
            RawEventMessage(batch_id=batch.id, tenant_id="trusted-tenant", source_name=batch.source_name, line_number=1, raw_line=json.dumps(sysmon_dns_record("batch-1"))),
            RawEventMessage(batch_id=batch.id, tenant_id="trusted-tenant", source_name=batch.source_name, line_number=2, raw_line=json.dumps(sysmon_dns_record("batch-1"))),
            RawEventMessage(batch_id=batch.id, tenant_id="trusted-tenant", source_name=batch.source_name, line_number=3, raw_line="{bad json"),
            RawEventMessage(batch_id=batch.id, tenant_id="trusted-tenant", source_name=batch.source_name, line_number=4, raw_line=json.dumps({"id": "unsupported", "data": {}})),
        ]

        asyncio.run(process_raw_event_messages(db, messages, publisher))

        histories = db.scalars(select(IngestionHistory)).all()
        errors = db.scalars(select(ErrorRecord).order_by(ErrorRecord.line_number)).all()
        updated_batch = db.get(IngestionBatch, batch.id)
        payload_types = [type(sent[1]) for sent in publisher.sent]

        assert len(histories) == 1
        assert [error.error_type for error in errors] == ["json_parse_error", "unsupported_event"]
        assert updated_batch is not None
        assert updated_batch.status == "completed"
        assert updated_batch.normalized_records == 2
        assert updated_batch.error_records == 2
        assert payload_types.count(OCSFEventMessage) == 1
        assert payload_types.count(DeadLetterMessage) == 2
