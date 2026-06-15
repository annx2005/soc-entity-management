from __future__ import annotations

from typing import Any

from app.ocsf.adapters import normalize_to_ocsf
from app.ocsf.schemas import OCSFEvent


def normalize_event(record: dict[str, Any]) -> OCSFEvent:
    return normalize_to_ocsf(record)
