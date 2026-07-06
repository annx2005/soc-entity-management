from __future__ import annotations

import io
import json
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.service import record_audit_log
from app.database.models import ErrorRecord, IngestionBatch, IngestionHistory, JobStatus
from app.normalization.helpers import get_nested, normalize_empty
from app.normalization.normalizer import normalize_event
from app.normalization.schemas import UnsupportedEventError


def ingest_jsonl_stream(
    db: Session,
    stream: TextIO,
    source_name: str,
    tenant_id: str = "default",
    actor: str = "system",
) -> IngestionBatch:
    batch = IngestionBatch(source_name=source_name, status="running")
    db.add(batch)
    db.flush()
    record_audit_log(
        db,
        tenant_id=tenant_id,
        action="ingest_batch_started",
        actor=actor,
        target_type="ingestion_batch",
        target_id=str(batch.id),
        metadata={"source_name": source_name, "mode": "sync"},
    )

    job = JobStatus(batch_id=batch.id, job_type="ingest_file", status="running", details={"source_name": source_name})
    db.add(job)
    db.flush()

    total = normalized = errors = 0
    for line_number, raw_line in enumerate(stream, start=1):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        total += 1
        try:
            record = json.loads(raw_line)
            raw_tenant_id = _declared_raw_tenant_id(record)
            event = _with_trusted_tenant(normalize_event(record), tenant_id, raw_tenant_id)
            _record_tenant_mismatch_audit(
                db,
                tenant_id=tenant_id,
                actor=actor,
                batch_id=batch.id,
                source_name=source_name,
                line_number=line_number,
                event_id=event.event_id,
                raw_tenant_id=raw_tenant_id,
            )
            db.add(
                IngestionHistory(
                    batch_id=batch.id,
                    event_id=event.event_id,
                    event_type=event.event_type,
                    source=event.source,
                    normalized_event=event.model_dump(mode="json"),
                )
            )
            normalized += 1
        except json.JSONDecodeError as exc:
            db.add(_error_record(batch.id, line_number, "json_parse_error", str(exc), raw_line))
            errors += 1
        except UnsupportedEventError as exc:
            db.add(_error_record(batch.id, line_number, "unsupported_event", str(exc), raw_line))
            errors += 1
        except Exception as exc:  # pragma: no cover - defensive boundary for real-world logs
            db.add(_error_record(batch.id, line_number, "normalization_error", str(exc), raw_line))
            errors += 1

    batch.total_records = total
    batch.normalized_records = normalized
    batch.error_records = errors
    batch.status = "completed"
    batch.completed_at = datetime.now(timezone.utc)

    job.status = "completed"
    job.details = {"source_name": source_name, "total_records": total, "normalized_records": normalized, "error_records": errors}
    job.updated_at = datetime.now(timezone.utc)
    record_audit_log(
        db,
        tenant_id=tenant_id,
        action="ingest_batch_completed",
        actor=actor,
        target_type="ingestion_batch",
        target_id=str(batch.id),
        metadata={
            "source_name": source_name,
            "mode": "sync",
            "total_records": total,
            "normalized_records": normalized,
            "error_records": errors,
        },
    )

    db.commit()
    db.refresh(batch)
    return batch


def ingest_jsonl_path(db: Session, file_path: str, tenant_id: str = "default", actor: str = "system") -> IngestionBatch:
    path = Path(file_path).expanduser().resolve()
    with path.open("r", encoding="utf-8") as stream:
        return ingest_jsonl_stream(db, stream, str(path), tenant_id=tenant_id, actor=actor)


def ingest_jsonl_bytes(db: Session, content: bytes, source_name: str, tenant_id: str = "default", actor: str = "system") -> IngestionBatch:
    text = content.decode("utf-8")
    return ingest_jsonl_stream(db, io.StringIO(text), source_name, tenant_id=tenant_id, actor=actor)


def list_errors(db: Session, limit: int = 100, batch_id: int | None = None) -> Iterable[ErrorRecord]:
    stmt = select(ErrorRecord).order_by(ErrorRecord.id.desc()).limit(limit)
    if batch_id is not None:
        stmt = select(ErrorRecord).where(ErrorRecord.batch_id == batch_id).order_by(ErrorRecord.id.desc()).limit(limit)
    return db.scalars(stmt).all()


def list_normalized_events(db: Session, limit: int = 100, batch_id: int | None = None) -> Iterable[IngestionHistory]:
    return list_normalized_events_page(db, limit=limit, offset=0, batch_id=batch_id)


def list_normalized_events_page(
    db: Session,
    *,
    limit: int = 100,
    offset: int = 0,
    batch_id: int | None = None,
) -> Iterable[IngestionHistory]:
    stmt = (
        select(IngestionHistory)
        .order_by(IngestionHistory.created_at.desc(), IngestionHistory.id.desc())
        .offset(offset)
        .limit(limit)
    )
    if batch_id is not None:
        stmt = (
            select(IngestionHistory)
            .where(IngestionHistory.batch_id == batch_id)
            .order_by(IngestionHistory.created_at.desc(), IngestionHistory.id.desc())
            .offset(offset)
            .limit(limit)
        )
    return db.scalars(stmt).all()


def get_batch(db: Session, batch_id: int) -> IngestionBatch | None:
    return db.get(IngestionBatch, batch_id)


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


def _record_tenant_mismatch_audit(
    db: Session,
    *,
    tenant_id: str,
    actor: str,
    batch_id: int,
    source_name: str,
    line_number: int,
    event_id: str,
    raw_tenant_id: str | None,
) -> None:
    if raw_tenant_id is None or raw_tenant_id == tenant_id:
        return
    record_audit_log(
        db,
        tenant_id=tenant_id,
        action="tenant_mismatch_detected",
        actor=actor,
        target_type="raw_event",
        target_id=event_id,
        metadata={
            "batch_id": batch_id,
            "source_name": source_name,
            "line_number": line_number,
            "raw_tenant_id": raw_tenant_id,
            "trusted_tenant_id": tenant_id,
        },
    )


def _error_record(batch_id: int, line_number: int, error_type: str, message: str, raw_line: str) -> ErrorRecord:
    return ErrorRecord(
        batch_id=batch_id,
        line_number=line_number,
        error_type=error_type,
        message=message,
        raw_line=raw_line[:5000],
    )
