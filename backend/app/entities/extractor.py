from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Iterable

from app.entities.schemas import Entity, EntityType
from app.ocsf.schemas import OCSFEvent


PLACEHOLDER_VALUES = {
    "",
    "-",
    "n/a",
    "na",
    "none",
    "null",
    "(null)",
    "undefined",
    "unknown",
    "unknown user",
    "unknown host",
    "not available",
    "not_available",
}

HASH_ALGORITHMS_BY_LENGTH = {
    32: "md5",
    40: "sha1",
    64: "sha256",
}
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def extract_entities(event: OCSFEvent) -> list[Entity]:
    entities: dict[tuple[str, EntityType, str], Entity] = {}

    def add_entity(entity_type: EntityType, value: str | None, properties: dict[str, Any] | None = None) -> None:
        if not value:
            return
        key = (event.tenant_id, entity_type, value)
        if key in entities:
            return
        entities[key] = Entity(
            id=_entity_id(event.tenant_id, entity_type, value),
            type=entity_type,
            value=value,
            tenant_id=event.tenant_id,
            first_seen=_event_time_iso(event),
            last_seen=_event_time_iso(event),
            source=event.source_name,
            properties=properties or {},
        )

    actor = _as_dict(event.actor)
    actor_user = _as_dict(actor.get("user"))
    add_entity(
        EntityType.USER,
        _normalize_user_or_host(actor_user.get("name")),
        {"source_field": "actor.user.name"},
    )

    for source_field, endpoint in (
        ("device.hostname", event.device),
        ("dst_endpoint.hostname", event.dst_endpoint),
    ):
        add_entity(
            EntityType.HOST,
            _normalize_user_or_host(_as_dict(endpoint).get("hostname"), strip_trailing_dot=True),
            {"source_field": source_field},
        )

    for source_field, endpoint in (
        ("src_endpoint.ip", event.src_endpoint),
        ("dst_endpoint.ip", event.dst_endpoint),
    ):
        ip_value = _normalize_ip(_as_dict(endpoint).get("ip"))
        add_entity(
            EntityType.IP,
            ip_value,
            {"source_field": source_field, "version": _ip_version(ip_value)},
        )

    add_entity(
        EntityType.DOMAIN,
        _normalize_domain(_as_dict(event.query).get("hostname")),
        {"source_field": "query.hostname"},
    )

    for source_field, process in _iter_processes(event):
        process_entity = _normalize_process(process)
        if process_entity is not None:
            add_entity(
                EntityType.PROCESS,
                process_entity["value"],
                {
                    "source_field": source_field,
                    "name": process_entity.get("name"),
                    "path": process_entity.get("path"),
                    "cmd_line": process_entity.get("cmd_line"),
                },
            )

    for source_field, hash_object in _iter_hashes(event):
        hash_entity = _normalize_file_hash(hash_object)
        if hash_entity is not None:
            add_entity(
                EntityType.FILE_HASH,
                hash_entity["value"],
                {"source_field": source_field, "algorithm": hash_entity["algorithm"]},
            )

    return list(entities.values())


def _entity_id(tenant_id: str, entity_type: EntityType, value: str) -> str:
    key = f"{tenant_id}:{entity_type.value}:{value}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _event_time_iso(event: OCSFEvent) -> str:
    return datetime.fromtimestamp(event.time / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _clean_text(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip().strip("\"'")
    if cleaned.lower() in PLACEHOLDER_VALUES:
        return None
    return cleaned or None


def _normalize_user_or_host(value: Any, *, strip_trailing_dot: bool = False) -> str | None:
    cleaned = _clean_text(value)
    if cleaned is None:
        return None
    if strip_trailing_dot:
        cleaned = cleaned.rstrip(".")
    normalized = cleaned.lower()
    return normalized if normalized and normalized not in PLACEHOLDER_VALUES else None


def _normalize_ip(value: Any) -> str | None:
    cleaned = _clean_text(value)
    if cleaned is None:
        return None
    try:
        parsed = ipaddress.ip_address(cleaned)
    except ValueError:
        return None
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return str(parsed.ipv4_mapped)
    return str(parsed)


def _ip_version(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return ipaddress.ip_address(value).version
    except ValueError:
        return None


def _normalize_domain(value: Any) -> str | None:
    cleaned = _clean_text(value)
    if cleaned is None:
        return None
    normalized = cleaned.rstrip(".").lower()
    if not normalized or normalized in PLACEHOLDER_VALUES or len(normalized) > 253:
        return None
    try:
        ipaddress.ip_address(normalized)
        return None
    except ValueError:
        pass
    labels = normalized.split(".")
    if any(not DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        return None
    return normalized


def _iter_processes(event: OCSFEvent) -> Iterable[tuple[str, dict[str, Any]]]:
    process = _as_dict(event.process)
    if process:
        yield "process", process

    actor_process = _as_dict(_as_dict(event.actor).get("process"))
    if actor_process:
        yield "actor.process", actor_process


def _normalize_process(process: dict[str, Any]) -> dict[str, str | None] | None:
    file_obj = _as_dict(process.get("file"))
    path = _normalize_process_path(file_obj.get("path"))
    name = _normalize_process_name(process.get("name") or file_obj.get("name") or _name_from_path(path))
    cmd_line = _clean_text(process.get("cmd_line"))
    if cmd_line is not None:
        cmd_line = cmd_line.strip()

    value = path or name
    if value is None:
        return None
    return {"value": value, "name": name, "path": path, "cmd_line": cmd_line}


def _normalize_process_path(value: Any) -> str | None:
    cleaned = _clean_text(value)
    if cleaned is None:
        return None
    return cleaned.replace("/", "\\").lower()


def _normalize_process_name(value: Any) -> str | None:
    cleaned = _clean_text(value)
    if cleaned is None:
        return None
    return cleaned.lower()


def _name_from_path(path: str | None) -> str | None:
    if not path:
        return None
    parts = re.split(r"[\\/]+", path)
    return parts[-1] if parts and parts[-1] else path


def _iter_hashes(event: OCSFEvent) -> Iterable[tuple[str, dict[str, Any]]]:
    for hash_object in _hashes_from_file(_as_dict(event.file)):
        yield "file.hashes", hash_object

    for process_source, process in _iter_processes(event):
        for hash_object in _hashes_from_file(_as_dict(process.get("file"))):
            yield f"{process_source}.file.hashes", hash_object


def _hashes_from_file(file_obj: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for hash_object in _as_list(file_obj.get("hashes")):
        if isinstance(hash_object, dict):
            yield hash_object


def _normalize_file_hash(hash_object: dict[str, Any]) -> dict[str, str] | None:
    value = _clean_text(hash_object.get("value"))
    if value is None:
        return None
    normalized = value.lower()
    if not re.fullmatch(r"[0-9a-f]+", normalized):
        return None

    inferred_algorithm = HASH_ALGORITHMS_BY_LENGTH.get(len(normalized))
    if inferred_algorithm is None:
        return None

    algorithm = _clean_text(hash_object.get("algorithm"))
    if algorithm is not None:
        algorithm = algorithm.lower().replace("-", "")
        if algorithm not in set(HASH_ALGORITHMS_BY_LENGTH.values()):
            return None
        if algorithm != inferred_algorithm:
            return None

    return {"value": normalized, "algorithm": inferred_algorithm}
