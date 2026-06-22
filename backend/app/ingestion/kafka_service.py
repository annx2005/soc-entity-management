from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Protocol, TextIO

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.service import record_audit_log
from app.core.config import get_settings
from app.database.models import ErrorRecord, IngestionBatch, IngestionHistory, JobStatus
from app.ingestion.kafka_client import KafkaJsonProducer
from app.ingestion.kafka_messages import DeadLetterMessage, OCSFEventMessage, RawEventMessage
from app.normalization.helpers import get_nested, normalize_empty
from app.normalization.normalizer import normalize_event
from app.normalization.schemas import UnsupportedEventError


class EventPublisher(Protocol):
    async def send(self, topic: str, payload: BaseModel, key: Optional[str] = None, headers: Optional[dict[str, str]] = None) -> None:
        ...


async def enqueue_jsonl_path(
    db: Session,
    file_path: str,
    publisher: Optional[EventPublisher] = None,
    tenant_id: str = "default",
    actor: str = "system",
) -> IngestionBatch:
    path = Path(file_path).expanduser().resolve()
    with path.open("r", encoding="utf-8") as stream:
        return await enqueue_jsonl_stream(db, stream, str(path), publisher=publisher, tenant_id=tenant_id, actor=actor)


async def enqueue_jsonl_bytes(
    db: Session,
    content: bytes,
    source_name: str,
    publisher: Optional[EventPublisher] = None,
    tenant_id: str = "default",
    actor: str = "system",
) -> IngestionBatch:
    text = content.decode("utf-8")
    return await enqueue_jsonl_stream(db, io.StringIO(text), source_name, publisher=publisher, tenant_id=tenant_id, actor=actor)


async def enqueue_jsonl_stream(
    db: Session,
    stream: TextIO,
    source_name: str,
    publisher: Optional[EventPublisher] = None,
    tenant_id: str = "default",
    actor: str = "system",
) -> IngestionBatch:
    batch = IngestionBatch(source_name=source_name, status="publishing")
    db.add(batch)
    db.flush()
    record_audit_log(
        db,
        tenant_id=tenant_id,
        action="ingest_batch_started",
        actor=actor,
        target_type="ingestion_batch",
        target_id=str(batch.id),
        metadata={"source_name": source_name, "mode": "async"},
    )

    job = JobStatus(batch_id=batch.id, job_type="kafka_publish_raw_events", status="running", details={"source_name": source_name})
    db.add(job)
    db.commit()
    db.refresh(batch)

    managed_publisher: Optional[KafkaJsonProducer] = None
    if publisher is None:
        managed_publisher = KafkaJsonProducer()
        await managed_publisher.start()
        publisher = managed_publisher

    total_records = 0
    settings = get_settings()
    try:
        for line_number, raw_line in enumerate(stream, start=1):
            raw_line = raw_line.strip()
            if not raw_line:
                continue

            total_records += 1
            message = RawEventMessage(
                batch_id=batch.id,
                tenant_id=tenant_id,
                source_name=source_name,
                line_number=line_number,
                raw_line=raw_line,
            )
            await publisher.send(
                settings.kafka_raw_events_topic,
                message,
                key=str(batch.id),
                headers={
                    "schema_version": message.schema_version,
                    "batch_id": str(batch.id),
                    "tenant_id": tenant_id,
                    "source_name": source_name,
                },
            )

        db.add(batch)
        batch.total_records = total_records
        batch.status = _batch_status_after_publish(batch)
        job.status = "completed"
        job.details = {"source_name": source_name, "published_records": total_records}
        job.updated_at = datetime.now(timezone.utc)
        record_audit_log(
            db,
            tenant_id=tenant_id,
            action="ingest_batch_queued",
            actor=actor,
            target_type="ingestion_batch",
            target_id=str(batch.id),
            metadata={"source_name": source_name, "mode": "async", "published_records": total_records},
        )
        db.commit()
        db.refresh(batch)
        return batch
    except Exception as exc:
        db.add(batch)
        batch.status = "failed"
        job.status = "failed"
        job.details = {"source_name": source_name, "published_records": total_records, "error": str(exc)}
        job.updated_at = datetime.now(timezone.utc)
        record_audit_log(
            db,
            tenant_id=tenant_id,
            action="ingest_batch_failed",
            actor=actor,
            target_type="ingestion_batch",
            target_id=str(batch.id),
            metadata={"source_name": source_name, "mode": "async", "published_records": total_records, "error": str(exc)},
        )
        db.commit()
        raise
    finally:
        if managed_publisher is not None:
            await managed_publisher.stop()


async def process_raw_event_message(db: Session, message: RawEventMessage, publisher: Optional[EventPublisher] = None) -> None:
    try:
        record = json.loads(message.raw_line)
        raw_tenant_id = _declared_raw_tenant_id(record)
        event = _with_trusted_tenant(normalize_event(record), message.tenant_id, raw_tenant_id)
        _record_tenant_mismatch_audit(db, message, event.event_id, raw_tenant_id)
    except json.JSONDecodeError as exc:
        await _record_processing_error(db, message, "json_parse_error", str(exc), publisher)
        return
    except UnsupportedEventError as exc:
        await _record_processing_error(db, message, "unsupported_event", str(exc), publisher)
        return

    if _normalized_event_exists(db, message.batch_id, event.event_id):
        # Count duplicate event ids as processed so the batch can complete,
        # but do not persist or republish the same normalized event again.
        _mark_batch_progress(db, message.batch_id, tenant_id=message.tenant_id, normalized_delta=1, error_delta=0)
        db.commit()
        return

    db.add(
        IngestionHistory(
            batch_id=message.batch_id,
            event_id=event.event_id,
            event_type=event.event_type,
            source=event.source_name,
            normalized_event=event.model_dump(mode="json"),
        )
    )
    _mark_batch_progress(db, message.batch_id, tenant_id=message.tenant_id, normalized_delta=1, error_delta=0)

    if publisher is not None:
        ocsf_message = OCSFEventMessage(
            source_message_id=message.message_id,
            batch_id=message.batch_id,
            event_id=event.event_id,
            tenant_id=event.tenant_id,
            class_uid=event.class_uid,
            class_name=event.class_name,
            activity_id=event.activity_id,
            activity_name=event.activity_name,
            ocsf_version=str(event.metadata.get("version", "1.2.0")),
            ocsf_event=event.model_dump(mode="json"),
        )
        settings = get_settings()
        await publisher.send(
            settings.kafka_ocsf_events_topic,
            ocsf_message,
            key=f"{event.tenant_id}:{event.event_id}",
            headers={
                "schema_version": ocsf_message.schema_version,
                "tenant_id": event.tenant_id,
                "class_uid": str(event.class_uid),
            },
        )

    db.commit()


def _with_trusted_tenant(event, tenant_id: str, raw_tenant_id: str | None = None):
    unmapped = dict(event.unmapped)
    if raw_tenant_id is not None and raw_tenant_id != tenant_id:
        unmapped["raw_tenant_id"] = raw_tenant_id
        unmapped["tenant_id_source"] = "authenticated_context"
    return event.model_copy(update={"tenant_id": tenant_id, "unmapped": unmapped})


def _declared_raw_tenant_id(record: dict) -> str | None:
    return (
        normalize_empty(record.get("tenant_id"))
        or normalize_empty(get_nested(record, "tenant.id"))
        or normalize_empty(get_nested(record, "organization.id"))
    )


def _record_tenant_mismatch_audit(db: Session, message: RawEventMessage, event_id: str, raw_tenant_id: str | None) -> None:
    if raw_tenant_id is None or raw_tenant_id == message.tenant_id:
        return
    record_audit_log(
        db,
        tenant_id=message.tenant_id,
        action="tenant_mismatch_detected",
        actor="system",
        target_type="raw_event",
        target_id=event_id,
        metadata={
            "batch_id": message.batch_id,
            "source_name": message.source_name,
            "line_number": message.line_number,
            "raw_tenant_id": raw_tenant_id,
            "trusted_tenant_id": message.tenant_id,
        },
    )


def _normalized_event_exists(db: Session, batch_id: int, event_id: str) -> bool:
    stmt = select(IngestionHistory.id).where(IngestionHistory.batch_id == batch_id, IngestionHistory.event_id == event_id)
    return db.scalar(stmt) is not None


async def _record_processing_error(
    db: Session,
    message: RawEventMessage,
    error_type: str,
    error_message: str,
    publisher: Optional[EventPublisher],
) -> None:
    db.add(
        ErrorRecord(
            batch_id=message.batch_id,
            line_number=message.line_number,
            error_type=error_type,
            message=error_message,
            raw_line=message.raw_line[:5000],
        )
    )
    _mark_batch_progress(db, message.batch_id, tenant_id=message.tenant_id, normalized_delta=0, error_delta=1)

    if publisher is not None:
        dlq_message = DeadLetterMessage(
            source_message_id=message.message_id,
            batch_id=message.batch_id,
            source_name=message.source_name,
            line_number=message.line_number,
            error_type=error_type,
            message=error_message,
            raw_line=message.raw_line[:5000],
        )
        settings = get_settings()
        await publisher.send(
            settings.kafka_dead_letter_topic,
            dlq_message,
            key=str(message.batch_id),
            headers={"schema_version": dlq_message.schema_version, "error_type": error_type},
        )

    db.commit()


def _mark_batch_progress(db: Session, batch_id: int, tenant_id: str, normalized_delta: int, error_delta: int) -> None:
    batch = db.get(IngestionBatch, batch_id)
    if batch is None:
        return
    previous_status = batch.status
    batch.normalized_records += normalized_delta
    batch.error_records += error_delta

    processed = batch.normalized_records + batch.error_records
    if batch.total_records > 0 and processed >= batch.total_records:
        batch.status = "completed"
        batch.completed_at = datetime.now(timezone.utc)
        if previous_status != "completed":
            record_audit_log(
                db,
                tenant_id=tenant_id,
                action="ingest_batch_completed",
                actor="system",
                target_type="ingestion_batch",
                target_id=str(batch.id),
                metadata={
                    "source_name": batch.source_name,
                    "mode": "async",
                    "total_records": batch.total_records,
                    "normalized_records": batch.normalized_records,
                    "error_records": batch.error_records,
                },
            )
    else:
        batch.status = "running"


def _batch_status_after_publish(batch: IngestionBatch) -> str:
    processed = batch.normalized_records + batch.error_records
    if batch.total_records > 0 and processed >= batch.total_records:
        batch.completed_at = datetime.now(timezone.utc)
        return "completed"
    if processed > 0:
        return "running"
    return "queued"
