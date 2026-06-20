from __future__ import annotations

import io
import json
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import ErrorRecord, IngestionBatch, IngestionHistory, JobStatus
from app.normalization.normalizer import normalize_event
from app.normalization.schemas import UnsupportedEventError


def ingest_jsonl_stream(db: Session, stream: TextIO, source_name: str, tenant_id: str = "default") -> IngestionBatch:
    batch = IngestionBatch(source_name=source_name, status="running")
    db.add(batch)
    db.flush()

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
            event = _with_trusted_tenant(normalize_event(record), tenant_id)
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

    db.commit()
    db.refresh(batch)
    return batch


def ingest_jsonl_path(db: Session, file_path: str, tenant_id: str = "default") -> IngestionBatch:
    path = Path(file_path).expanduser().resolve()
    with path.open("r", encoding="utf-8") as stream:
        return ingest_jsonl_stream(db, stream, str(path), tenant_id=tenant_id)


def ingest_jsonl_bytes(db: Session, content: bytes, source_name: str, tenant_id: str = "default") -> IngestionBatch:
    text = content.decode("utf-8")
    return ingest_jsonl_stream(db, io.StringIO(text), source_name, tenant_id=tenant_id)


def list_errors(db: Session, limit: int = 100, batch_id: int | None = None) -> Iterable[ErrorRecord]:
    stmt = select(ErrorRecord).order_by(ErrorRecord.id.desc()).limit(limit)
    if batch_id is not None:
        stmt = select(ErrorRecord).where(ErrorRecord.batch_id == batch_id).order_by(ErrorRecord.id.desc()).limit(limit)
    return db.scalars(stmt).all()


def list_normalized_events(db: Session, limit: int = 100, batch_id: int | None = None) -> Iterable[IngestionHistory]:
    stmt = select(IngestionHistory).order_by(IngestionHistory.id.desc()).limit(limit)
    if batch_id is not None:
        stmt = select(IngestionHistory).where(IngestionHistory.batch_id == batch_id).order_by(IngestionHistory.id.desc()).limit(limit)
    return db.scalars(stmt).all()


def get_batch(db: Session, batch_id: int) -> IngestionBatch | None:
    return db.get(IngestionBatch, batch_id)


def _with_trusted_tenant(event, tenant_id: str):
    raw_tenant_id = event.tenant_id
    unmapped = dict(event.unmapped)
    if raw_tenant_id != tenant_id:
        unmapped["raw_tenant_id"] = raw_tenant_id
        unmapped["tenant_id_source"] = "authenticated_context"
    return event.model_copy(update={"tenant_id": tenant_id, "unmapped": unmapped})


def _error_record(batch_id: int, line_number: int, error_type: str, message: str, raw_line: str) -> ErrorRecord:
    return ErrorRecord(
        batch_id=batch_id,
        line_number=line_number,
        error_type=error_type,
        message=message,
        raw_line=raw_line[:5000],
    )
