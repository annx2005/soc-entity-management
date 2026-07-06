from __future__ import annotations

from typing import Annotated, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from sqlalchemy.orm import Session

from app.auth.dependencies import TenantContext, get_tenant_context
from app.database.session import get_db
from app.ingestion.schemas import ErrorRecordResponse, IngestFileResponse, NormalizedEventResponse
from app.ingestion.kafka_service import enqueue_jsonl_bytes, enqueue_jsonl_path
from app.ingestion.service import get_batch, list_errors, list_normalized_events_page

router = APIRouter(prefix="/api/events", tags=["events"])


@router.post("/ingest-file-async", response_model=IngestFileResponse)
async def ingest_file_async(
    context: Annotated[TenantContext, Depends(get_tenant_context)],
    db: Annotated[Session, Depends(get_db)],
    file_path: Annotated[Optional[str], Form()] = None,
    file: Annotated[Optional[UploadFile], File()] = None,
) -> IngestFileResponse:
    tenant_id = _ingest_tenant_id_or_forbidden(context)
    if file is None and not file_path:
        raise HTTPException(status_code=400, detail="Provide either file_path or file upload")
    try:
        if file is not None:
            content = await file.read()
            batch = await enqueue_jsonl_bytes(db, content, file.filename or "uploaded.jsonl", tenant_id=tenant_id, actor=context.email)
        else:
            batch = await enqueue_jsonl_path(db, file_path or "", tenant_id=tenant_id, actor=context.email)
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


def _ingest_tenant_id_or_forbidden(context: TenantContext) -> str:
    if context.tenant_id is None or context.scope != "tenant":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="platform ingest is not supported")
    if context.role not in {"admin", "analyst"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient role for ingest")
    return str(context.tenant_id)


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
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[NormalizedEventResponse]:
    return list(list_normalized_events_page(db, limit=limit, offset=offset, batch_id=batch_id))


@router.get("/batches/{batch_id}", response_model=IngestFileResponse)
def get_ingestion_batch(
    batch_id: int,
    db: Annotated[Session, Depends(get_db)],
) -> IngestFileResponse:
    batch = get_batch(db, batch_id)
    if batch is None:
        raise HTTPException(status_code=404, detail="batch not found")
    return IngestFileResponse(
        batch_id=batch.id,
        source_name=batch.source_name,
        status=batch.status,
        total_records=batch.total_records,
        normalized_records=batch.normalized_records,
        error_records=batch.error_records,
    )
