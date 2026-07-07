from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml

from app.core.config import get_settings
from app.normalization.helpers import get_nested, normalize_domain, normalize_empty, parse_first_ip, parse_sha256, process_name_from_path
from app.normalization.schemas import UnsupportedEventError
from app.ocsf.schemas import OCSF_VERSION, OCSFEvent


@dataclass(frozen=True)
class ParserSummary:
    id: str
    display_name: str
    category: str
    description: str | None = None


class ConfigParser:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.id = str(config["id"])
        self.display_name = str(config.get("display_name") or self.id)
        self.category = str(config.get("category") or "custom")
        self.description = config.get("description")
        self.enabled = bool(config.get("enabled", True))
        self.public = bool(config.get("public", True))
        self.priority = int(config.get("priority", 0))
        dispatch = config.get("dispatch") or {}
        self.dispatch_parser_ids = [str(parser_id) for parser_id in dispatch.get("parsers", [])]

    def summary(self) -> ParserSummary:
        return ParserSummary(
            id=self.id,
            display_name=self.display_name,
            category=self.category,
            description=str(self.description) if self.description else None,
        )

    def matches(self, record: dict[str, Any]) -> bool:
        match = self.config.get("match") or {}
        conditions = match.get("all") or []
        return all(_condition_matches(record, condition) for condition in conditions)

    def normalize(self, record: dict[str, Any]) -> OCSFEvent:
        ocsf = self.config.get("ocsf")
        if not isinstance(ocsf, dict):
            raise UnsupportedEventError(f"parser_misconfigured: {self.id} missing ocsf block")

        event_id = _resolve_required(record, ocsf.get("event_id"), "event_id")
        event_time = _event_time_ms(_resolve(record, ocsf.get("time")))
        class_uid = int(_resolve_required(record, ocsf.get("class_uid"), "class_uid"))
        class_name = str(_resolve_required(record, ocsf.get("class_name"), "class_name"))
        category_uid = int(_resolve_required(record, ocsf.get("category_uid"), "category_uid"))
        category_name = str(_resolve_required(record, ocsf.get("category_name"), "category_name"))
        activity_id = int(_resolve_required(record, ocsf.get("activity_id"), "activity_id"))
        activity_name = str(_resolve_required(record, ocsf.get("activity_name"), "activity_name"))
        source_name = str(_resolve_required(record, ocsf.get("source_name"), "source_name"))
        event_type = str(_resolve_required(record, ocsf.get("event_type"), "event_type"))
        severity_id = int(_resolve(record, ocsf.get("severity_id")) or 1)

        payload: dict[str, Any] = {
            "metadata": {
                "version": OCSF_VERSION,
                "uid": event_id,
                "product": {"name": "SOC Entity Management"},
            },
            "time": event_time,
            "class_uid": class_uid,
            "class_name": class_name,
            "category_uid": category_uid,
            "category_name": category_name,
            "activity_id": activity_id,
            "activity_name": activity_name,
            "type_uid": (class_uid * 100) + activity_id,
            "type_name": f"{class_name}: {activity_name}",
            "severity_id": severity_id,
            "tenant_id": _resolve(record, ocsf.get("tenant_id")) or get_settings().tenant_id_default,
            "event_id": event_id,
            "source_name": source_name,
            "raw_data": record,
            "unmapped": {
                "event_type": event_type,
                "source": source_name,
                "original_time": _resolve(record, ocsf.get("time")),
                "parser_id": self.id,
            },
        }

        for target, spec in (ocsf.get("fields") or {}).items():
            value = _resolve(record, spec)
            if value not in (None, "", [], {}):
                _set_path(payload, str(target), value)

        for target, spec in (ocsf.get("unmapped") or {}).items():
            value = _resolve(record, spec)
            if value not in (None, "", [], {}):
                _set_path(payload["unmapped"], str(target), value)

        return OCSFEvent(**payload)


class ParserRegistry:
    def __init__(self, parsers: Iterable[ConfigParser]):
        enabled = [parser for parser in parsers if parser.enabled]
        self._parsers = sorted([parser for parser in enabled if parser.public], key=lambda parser: parser.priority, reverse=True)
        self._by_id = {parser.id: parser for parser in enabled}

    def list(self) -> list[ParserSummary]:
        return [parser.summary() for parser in self._parsers]

    def normalize(self, record: dict[str, Any], parser_id: str | None = None) -> OCSFEvent:
        parser_id = normalize_empty(parser_id)
        if parser_id and parser_id != "auto":
            parser = self._by_id.get(parser_id)
            if parser is None:
                raise UnsupportedEventError(f"parser_not_found: {parser_id}")
            if not parser.matches(record):
                raise UnsupportedEventError(f"parser_no_match: {parser_id}")
            return self._normalize_with_parser(record, parser)

        for parser in self._parsers:
            if parser.matches(record):
                return self._normalize_with_parser(record, parser)
        raise UnsupportedEventError("parser_no_match: auto")

    def _normalize_with_parser(self, record: dict[str, Any], parser: ConfigParser) -> OCSFEvent:
        if not parser.dispatch_parser_ids:
            return parser.normalize(record)

        for parser_id in parser.dispatch_parser_ids:
            target = self._by_id.get(parser_id)
            if target is None or not target.matches(record):
                continue
            event = self._normalize_with_parser(record, target)
            event.unmapped["parser_id"] = parser.id
            event.unmapped["dispatched_parser_id"] = target.id
            return event
        raise UnsupportedEventError(f"parser_no_match: {parser.id}")


_REGISTRY: ParserRegistry | None = None


def list_parsers() -> list[ParserSummary]:
    return _registry().list()


def normalize_with_parser(record: dict[str, Any], parser_id: str | None = None) -> OCSFEvent:
    return _registry().normalize(record, parser_id=parser_id)


def preview_parser(record: dict[str, Any], parser_id: str | None = None) -> OCSFEvent:
    return normalize_with_parser(record, parser_id=parser_id or "auto")


def _registry() -> ParserRegistry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = ParserRegistry(_load_parsers(Path(get_settings().parser_config_dir)))
    return _REGISTRY


def _load_parsers(config_dir: Path) -> list[ConfigParser]:
    if not config_dir.exists():
        return []
    parsers: list[ConfigParser] = []
    for path in sorted(config_dir.glob("*.y*ml")):
        with path.open("r", encoding="utf-8") as stream:
            loaded = yaml.safe_load(stream) or {}
        configs = loaded if isinstance(loaded, list) else [loaded]
        for config in configs:
            if isinstance(config, dict) and config.get("id"):
                parsers.append(ConfigParser(config))
    return parsers


def _condition_matches(record: dict[str, Any], condition: dict[str, Any]) -> bool:
    if "exists" in condition:
        return _resolve(record, {"path": condition["exists"]}) is not None
    if "equals" in condition:
        equals = condition["equals"] or {}
        return str(_resolve(record, {"path": equals.get("path")})) == str(equals.get("value"))
    if "in" in condition:
        in_condition = condition["in"] or {}
        value = _resolve(record, {"path": in_condition.get("path")})
        return str(value) in {str(item) for item in in_condition.get("values", [])}
    return False


def _resolve_required(record: dict[str, Any], spec: Any, name: str) -> Any:
    value = _resolve(record, spec)
    if value in (None, "", [], {}):
        raise UnsupportedEventError(f"missing_required_field: {name}")
    return value


def _resolve(record: dict[str, Any], spec: Any) -> Any:
    if spec is None:
        return None
    if not isinstance(spec, dict):
        return spec
    if "value" in spec:
        value = spec["value"]
    elif "hash_paths" in spec:
        values = [_resolve(record, {"path": path}) for path in spec.get("hash_paths", [])]
        value = hashlib.sha256(json.dumps(values, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
    elif "first" in spec:
        value = None
        for option in spec.get("first", []):
            value = _resolve(record, option)
            if value not in (None, "", [], {}):
                break
    else:
        path = spec.get("path")
        value = get_nested(record, str(path)) if path else None
        if value in (None, "", [], {}) and "default" in spec:
            value = spec["default"]
    for transform in spec.get("transforms", []):
        value = _transform(value, str(transform))
    return value


def _transform(value: Any, transform: str) -> Any:
    if transform.startswith("message_field:"):
        return _message_field(value, transform.split(":", 1)[1])
    if transform == "normalize_empty":
        return normalize_empty(value)
    if transform == "dotnet_json_date":
        return _dotnet_json_date(value)
    if transform == "normalize_domain":
        return normalize_domain(value)
    if transform == "first_ip":
        return parse_first_ip(value)
    if transform == "sha256":
        return parse_sha256(value)
    if transform == "sha256_hashes":
        sha256 = parse_sha256(value)
        return [{"algorithm": "SHA256", "value": sha256}] if sha256 else None
    if transform == "wazuh_vulnerability":
        return _wazuh_vulnerability(value)
    if transform == "process_name":
        return process_name_from_path(str(value)) if value else None
    if transform == "severity_id":
        return _severity_id(value)
    if transform == "sysmon_class_uid":
        return _sysmon_field(value, "class_uid")
    if transform == "sysmon_class_name":
        return _sysmon_field(value, "class_name")
    if transform == "sysmon_category_uid":
        return _sysmon_field(value, "category_uid")
    if transform == "sysmon_category_name":
        return _sysmon_field(value, "category_name")
    if transform == "sysmon_activity_id":
        return _sysmon_field(value, "activity_id")
    if transform == "sysmon_activity_name":
        return _sysmon_field(value, "activity_name")
    if transform == "sysmon_event_type":
        return _sysmon_field(value, "event_type")
    if transform == "string":
        return str(value) if value is not None else None
    return value


def _set_path(payload: dict[str, Any], target: str, value: Any) -> None:
    cursor = payload
    parts = target.split(".")
    for part in parts[:-1]:
        existing = cursor.get(part)
        if not isinstance(existing, dict):
            existing = {}
            cursor[part] = existing
        cursor = existing
    cursor[parts[-1]] = value


def _event_time_ms(value: Any) -> int:
    if isinstance(value, (int, float)):
        return int(value)
    parsed = _parse_datetime(str(value)) if value else datetime.now(timezone.utc)
    return int(parsed.timestamp() * 1000)


def _parse_datetime(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    if len(normalized) >= 5 and normalized[-5] in {"+", "-"} and normalized[-3] != ":":
        normalized = f"{normalized[:-2]}:{normalized[-2:]}"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _message_field(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    pattern = re.compile(rf"(?im)^{re.escape(field_name)}:\s*(.*)$")
    match = pattern.search(str(value))
    if match is None:
        return None
    return normalize_empty(match.group(1).strip())


def _dotnet_json_date(value: Any) -> str | None:
    if value is None:
        return None
    match = re.search(r"/Date\((\d+)\)/", str(value))
    if match is None:
        return normalize_empty(value)
    timestamp_ms = int(match.group(1))
    return datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc).isoformat()


def _wazuh_vulnerability(value: Any) -> list[dict[str, Any]] | None:
    if not isinstance(value, dict):
        return None
    vulnerability = {
        "cve": normalize_empty(value.get("cve")),
        "package_name": normalize_empty(get_nested(value, "package.name")),
        "severity": normalize_empty(value.get("severity")),
        "status": normalize_empty(value.get("status")),
        "title": normalize_empty(value.get("title")),
        "description": normalize_empty(value.get("reference")),
    }
    cleaned = {key: item for key, item in vulnerability.items() if item not in (None, "", [], {})}
    return [cleaned] if cleaned else None


SYSMON_EVENT_MAP: dict[int, dict[str, Any]] = {
    1: {
        "class_uid": 1007,
        "class_name": "Process Activity",
        "category_uid": 1,
        "category_name": "System Activity",
        "activity_id": 1,
        "activity_name": "Launch",
        "event_type": "process_execution",
    },
    3: {
        "class_uid": 4001,
        "class_name": "Network Activity",
        "category_uid": 4,
        "category_name": "Network Activity",
        "activity_id": 1,
        "activity_name": "Connection",
        "event_type": "network_connection",
    },
    10: {
        "class_uid": 1007,
        "class_name": "Process Activity",
        "category_uid": 1,
        "category_name": "System Activity",
        "activity_id": 6,
        "activity_name": "Access",
        "event_type": "process_access",
    },
    11: {
        "class_uid": 1001,
        "class_name": "File System Activity",
        "category_uid": 1,
        "category_name": "System Activity",
        "activity_id": 1,
        "activity_name": "Create",
        "event_type": "file_created",
    },
    22: {
        "class_uid": 4003,
        "class_name": "DNS Activity",
        "category_uid": 4,
        "category_name": "Network Activity",
        "activity_id": 1,
        "activity_name": "Query",
        "event_type": "dns_query",
    },
}


def _sysmon_field(value: Any, field_name: str) -> Any:
    try:
        event_id = int(value)
    except (TypeError, ValueError):
        event_id = 0
    return SYSMON_EVENT_MAP.get(event_id, SYSMON_EVENT_MAP[1])[field_name]


def _severity_id(value: Any) -> int:
    if value is None:
        return 1
    if isinstance(value, str):
        severity = value.strip().lower()
        if severity == "critical":
            return 5
        if severity == "high":
            return 4
        if severity == "medium":
            return 3
        if severity == "low":
            return 2
        if severity in {"informational", "info", "none"}:
            return 1
    try:
        level = int(value)
    except (TypeError, ValueError):
        return 1
    if level >= 12:
        return 5
    if level >= 7:
        return 4
    if level >= 4:
        return 3
    if level >= 1:
        return 2
    return 1
