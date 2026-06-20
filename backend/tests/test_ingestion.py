import io

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.database.models import ErrorRecord, IngestionBatch, IngestionHistory
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
