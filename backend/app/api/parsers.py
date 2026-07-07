from __future__ import annotations

from typing import Annotated, Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.auth.dependencies import TenantContext, get_tenant_context
from app.normalization.schemas import UnsupportedEventError
from app.parsers import list_parsers, preview_parser


router = APIRouter(prefix="/api/parsers", tags=["parsers"])


class ParserSummaryResponse(BaseModel):
    id: str
    display_name: str
    category: str
    description: Optional[str] = None


class ParserPreviewRequest(BaseModel):
    parser_id: Optional[str] = "auto"
    record: dict[str, Any] = Field(default_factory=dict)


class ParserPreviewResponse(BaseModel):
    parser_id: Optional[str]
    ocsf_event: dict[str, Any]


@router.get("", response_model=list[ParserSummaryResponse])
def get_parsers(_: Annotated[TenantContext, Depends(get_tenant_context)]) -> list[ParserSummaryResponse]:
    return [ParserSummaryResponse(**parser.__dict__) for parser in list_parsers()]


@router.post("/preview", response_model=ParserPreviewResponse)
def preview_parser_mapping(
    payload: ParserPreviewRequest,
    context: Annotated[TenantContext, Depends(get_tenant_context)],
) -> ParserPreviewResponse:
    if context.role not in {"admin", "analyst"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient role for parser preview")
    try:
        event = preview_parser(payload.record, payload.parser_id)
    except UnsupportedEventError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return ParserPreviewResponse(parser_id=event.unmapped.get("parser_id"), ocsf_event=event.model_dump(mode="json"))
