from __future__ import annotations

from typing import Annotated, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.ingestion.schemas import ErrorRecordResponse, IngestFileResponse, NormalizedEventResponse
from app.ingestion.kafka_service import enqueue_jsonl_bytes, enqueue_jsonl_path
from app.ingestion.service import ingest_jsonl_bytes, ingest_jsonl_path, list_errors, list_normalized_events

router = APIRouter(prefix="/api/events", tags=["events"])


@router.post("/ingest-file", response_model=IngestFileResponse)
async def ingest_file(
    db: Annotated[Session, Depends(get_db)],
    file_path: Annotated[Optional[str], Form()] = None,
    file: Annotated[Optional[UploadFile], File()] = None,
) -> IngestFileResponse:
    if file is None and not file_path:
        raise HTTPException(status_code=400, detail="Provide either file_path or file upload")
    if file is not None:
        content = await file.read()
        batch = ingest_jsonl_bytes(db, content, file.filename or "uploaded.jsonl")
    else:
        try:
            batch = ingest_jsonl_path(db, file_path or "")
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
    return IngestFileResponse(
        batch_id=batch.id,
        source_name=batch.source_name,
        status=batch.status,
        total_records=batch.total_records,
        normalized_records=batch.normalized_records,
        error_records=batch.error_records,
    )


@router.post("/ingest-file-async", response_model=IngestFileResponse)
async def ingest_file_async(
    db: Annotated[Session, Depends(get_db)],
    file_path: Annotated[Optional[str], Form()] = None,
    file: Annotated[Optional[UploadFile], File()] = None,
) -> IngestFileResponse:
    if file is None and not file_path:
        raise HTTPException(status_code=400, detail="Provide either file_path or file upload")
    try:
        if file is not None:
            content = await file.read()
            batch = await enqueue_jsonl_bytes(db, content, file.filename or "uploaded.jsonl")
        else:
            batch = await enqueue_jsonl_path(db, file_path or "")
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return IngestFileResponse(
        batch_id=batch.id,
        source_name=batch.source_name,
        status=batch.status,
        total_records=batch.total_records,
        normalized_records=batch.normalized_records,
        error_records=batch.error_records,
    )


@router.get("/errors", response_model=list[ErrorRecordResponse])
def get_errors(
    db: Annotated[Session, Depends(get_db)],
    batch_id: Annotated[Optional[int], Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[ErrorRecordResponse]:
    return list(list_errors(db, limit=limit, batch_id=batch_id))


@router.get("/normalized", response_model=list[NormalizedEventResponse])
def get_normalized_events(
    db: Annotated[Session, Depends(get_db)],
    batch_id: Annotated[Optional[int], Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[NormalizedEventResponse]:
    return list(list_normalized_events(db, limit=limit, batch_id=batch_id))
