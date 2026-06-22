import io

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.database.models import AuditLog, ErrorRecord, IngestionBatch, IngestionHistory
from app.database.session import Base
from app.ingestion.service import ingest_jsonl_stream


def test_ingest_jsonl_stream_records_success_and_errors() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)

    content = "\n".join(
        [
            '{"id":"evt-1","data":{"win":{"system":{"eventID":"22","systemTime":"2026-07-02T14:50:00Z","computer":"Xuan-An"},"eventdata":{"queryName":"github.com","queryResults":"::ffff:20.205.243.166;","image":"C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\curl.exe","user":"Xuan-An\\\\\\\\XuanAn"}}}}',
            "{bad json",
            '{"id":"evt-2","data":{"win":{"system":{"eventID":"999","systemTime":"2026-07-02T14:50:00Z","computer":"Xuan-An"},"eventdata":{}}}}',
        ]
    )

    with Session(engine) as db:
        batch = ingest_jsonl_stream(db, io.StringIO(content), "test.jsonl", tenant_id="trusted-tenant")

        assert batch.total_records == 3
        assert batch.normalized_records == 1
        assert batch.error_records == 2
        assert db.scalar(select(IngestionBatch).where(IngestionBatch.id == batch.id)) is not None
        history = db.scalar(select(IngestionHistory))
        assert history is not None
        assert history.normalized_event["tenant_id"] == "trusted-tenant"
        errors = db.scalars(select(ErrorRecord).order_by(ErrorRecord.id)).all()
        assert [error.error_type for error in errors] == ["json_parse_error", "unsupported_event"]
        audit_actions = db.scalars(select(AuditLog.action).order_by(AuditLog.id)).all()
        assert audit_actions == ["ingest_batch_started", "ingest_batch_completed"]


def test_ingest_jsonl_stream_audits_declared_tenant_mismatch() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)

    content = '{"id":"evt-1","tenant_id":"raw-tenant","data":{"win":{"system":{"eventID":"22","systemTime":"2026-07-02T14:50:00Z","computer":"Xuan-An"},"eventdata":{"queryName":"github.com","queryResults":"20.205.243.166","user":"Xuan-An\\\\XuanAn"}}}}'

    with Session(engine) as db:
        ingest_jsonl_stream(db, io.StringIO(content), "test.jsonl", tenant_id="trusted-tenant", actor="analyst@example.com")

        mismatch = db.scalar(select(AuditLog).where(AuditLog.action == "tenant_mismatch_detected"))
        assert mismatch is not None
        assert mismatch.tenant_id == "trusted-tenant"
        assert mismatch.actor == "analyst@example.com"
        assert mismatch.target_type == "raw_event"
        assert mismatch.target_id == "evt-1"
        assert mismatch.metadata_json["raw_tenant_id"] == "raw-tenant"
        assert mismatch.metadata_json["trusted_tenant_id"] == "trusted-tenant"
