from __future__ import annotations

from typing import Any

from app.ocsf.adapters import normalize_to_ocsf
from app.ocsf.schemas import OCSFEvent
from app.normalization.schemas import UnsupportedEventError
from app.parsers.registry import normalize_with_parser


def normalize_event(record: dict[str, Any], parser_id: str | None = None, source_hint: str | None = None) -> OCSFEvent:
    if parser_id and parser_id != "auto":
        return normalize_with_parser(record, parser_id=parser_id)

    config_error: UnsupportedEventError | None = None
    try:
        return normalize_with_parser(record, parser_id=parser_id or "auto")
    except UnsupportedEventError as exc:
        config_error = exc

    try:
        return normalize_to_ocsf(record)
    except UnsupportedEventError:
        raise config_error
    return normalize_to_ocsf(record)
