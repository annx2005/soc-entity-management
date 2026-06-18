from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

from app.entities.schemas import EntityType
from app.enrichment.schemas import EnrichmentResult


class EnrichmentProvider(Protocol):
    def lookup(self, entity_type: EntityType, value: str) -> EnrichmentResult | None:
        ...


class OfflineJsonEnrichmentProvider:
    def __init__(self, ip_source_path: str, file_hash_source_path: str) -> None:
        self._ip_source_path = ip_source_path
        self._file_hash_source_path = file_hash_source_path
        self._ip_data: dict[str, dict[str, Any]] | None = None
        self._file_hash_data: dict[str, dict[str, Any]] | None = None

    def lookup(self, entity_type: EntityType, value: str) -> EnrichmentResult | None:
        if entity_type == EntityType.IP:
            data = self._ip_entries().get(value)
        elif entity_type == EntityType.FILE_HASH:
            data = self._file_hash_entries().get(value.lower())
        else:
            return None

        if data is None:
            return None
        return EnrichmentResult(
            entity_type=entity_type.value,
            value=value,
            data=dict(data),
            source=str(data.get("provider") or "offline-json"),
            cache_status="miss",
        )

    def _ip_entries(self) -> dict[str, dict[str, Any]]:
        if self._ip_data is None:
            self._ip_data = _load_json_map(self._ip_source_path)
        return self._ip_data

    def _file_hash_entries(self) -> dict[str, dict[str, Any]]:
        if self._file_hash_data is None:
            raw_entries = _load_json_map(self._file_hash_source_path)
            self._file_hash_data = {key.lower(): value for key, value in raw_entries.items()}
        return self._file_hash_data


def _load_json_map(path: str) -> dict[str, dict[str, Any]]:
    with Path(path).expanduser().open("r", encoding="utf-8") as stream:
        payload = json.load(stream)
    if not isinstance(payload, dict):
        return {}
    return {str(key): value for key, value in payload.items() if isinstance(value, dict)}
