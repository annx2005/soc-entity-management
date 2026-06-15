from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Protocol

from app.core.config import get_settings
from app.normalization.helpers import (
    get_nested,
    normalize_domain,
    normalize_empty,
    parse_first_ip,
    parse_sha256,
    process_name_from_path,
)
from app.normalization.schemas import UnsupportedEventError
from app.ocsf.schemas import OCSF_VERSION, OCSFEvent


class OCSFAdapter(Protocol):
    def normalize(self, record: dict[str, Any], event_id: str) -> OCSFEvent:
        ...


ADAPTER_REGISTRY: dict[tuple[str, str], OCSFAdapter] = {}


def register_adapter(source_name: str, event_key: str, adapter: OCSFAdapter) -> None:
    ADAPTER_REGISTRY[(source_name, event_key)] = adapter


def normalize_to_ocsf(record: dict[str, Any]) -> OCSFEvent:
    event_id = str(record.get("id") or record.get("_id") or "")
    if not event_id:
        raise UnsupportedEventError("missing event id")

    source_name, event_key = _adapter_key(record)
    adapter = ADAPTER_REGISTRY.get((source_name, event_key))
    if adapter is None:
        raise UnsupportedEventError(f"unsupported event type: source={source_name}, event_key={event_key}")

    return adapter.normalize(record, event_id)


class AuthenticationAdapter:
    def normalize(self, record: dict[str, Any], event_id: str) -> OCSFEvent:
        event_id_raw = str(get_nested(record, "data.win.system.eventID", ""))
        is_success = event_id_raw == "4624"
        process_path = normalize_empty(get_nested(record, "data.win.eventdata.processName"))
        event_type = "windows_logon_success" if is_success else "windows_logon_failure"
        activity_id = 1 if is_success else 2
        activity_name = "Logon" if is_success else "Logon Failure"
        host = _host(record)
        user_name = normalize_empty(get_nested(record, "data.win.eventdata.targetUserName"))
        src_ip = normalize_empty(get_nested(record, "data.win.eventdata.ipAddress"))

        return _base_event(
            record,
            event_id,
            source_name="windows_security",
            event_type=event_type,
            class_uid=3002,
            class_name="Authentication",
            category_uid=3,
            category_name="Identity & Access Management",
            activity_id=activity_id,
            activity_name=activity_name,
            severity_id=1 if is_success else 3,
            actor=_actor(user_name=user_name, process_path=process_path),
            device=_hostname_object(host),
            src_endpoint=_ip_object(src_ip),
            dst_endpoint=_hostname_object(host),
            process=_process_object(process_path=process_path),
            unmapped_fields={"windows_event_id": event_id_raw},
        )


class ProcessActivityAdapter:
    def normalize(self, record: dict[str, Any], event_id: str) -> OCSFEvent:
        process_path = normalize_empty(get_nested(record, "data.win.eventdata.image"))
        sha256 = parse_sha256(get_nested(record, "data.win.eventdata.hashes"))
        file_obj = _file_object(process_path=process_path, sha256=sha256)
        process_obj = _process_object(
            process_path=process_path,
            command_line=normalize_empty(get_nested(record, "data.win.eventdata.commandLine")),
            file_obj=file_obj,
        )

        return _base_event(
            record,
            event_id,
            source_name="sysmon",
            event_type="process_execution",
            class_uid=1007,
            class_name="Process Activity",
            category_uid=1,
            category_name="System Activity",
            activity_id=1,
            activity_name="Launch",
            actor=_actor(user_name=normalize_empty(get_nested(record, "data.win.eventdata.user")), process_obj=process_obj),
            device=_hostname_object(_host(record)),
            process=process_obj,
            file=file_obj,
            unmapped_fields={"windows_event_id": "1"},
        )


class NetworkActivityAdapter:
    def normalize(self, record: dict[str, Any], event_id: str) -> OCSFEvent:
        process_path = normalize_empty(get_nested(record, "data.win.eventdata.image"))

        return _base_event(
            record,
            event_id,
            source_name="sysmon",
            event_type="network_connection",
            class_uid=4001,
            class_name="Network Activity",
            category_uid=4,
            category_name="Network Activity",
            activity_id=1,
            activity_name="Connection",
            actor=_actor(user_name=normalize_empty(get_nested(record, "data.win.eventdata.user"))),
            device=_hostname_object(_host(record)),
            src_endpoint=_ip_object(normalize_empty(get_nested(record, "data.win.eventdata.sourceIp"))),
            dst_endpoint=_ip_object(normalize_empty(get_nested(record, "data.win.eventdata.destinationIp"))),
            process=_process_object(process_path=process_path),
            unmapped_fields={"windows_event_id": "3"},
        )


class DnsActivityAdapter:
    def normalize(self, record: dict[str, Any], event_id: str) -> OCSFEvent:
        process_path = normalize_empty(get_nested(record, "data.win.eventdata.image"))
        domain = normalize_domain(get_nested(record, "data.win.eventdata.queryName"))

        return _base_event(
            record,
            event_id,
            source_name="sysmon",
            event_type="dns_query",
            class_uid=4003,
            class_name="DNS Activity",
            category_uid=4,
            category_name="Network Activity",
            activity_id=1,
            activity_name="Query",
            actor=_actor(user_name=normalize_empty(get_nested(record, "data.win.eventdata.user"))),
            device=_hostname_object(_host(record)),
            dst_endpoint=_ip_object(parse_first_ip(get_nested(record, "data.win.eventdata.queryResults"))),
            query={"hostname": domain} if domain else None,
            process=_process_object(process_path=process_path),
            unmapped_fields={"windows_event_id": "22"},
        )


class SecurityFindingAdapter:
    def normalize(self, record: dict[str, Any], event_id: str) -> OCSFEvent:
        rule = record.get("rule") if isinstance(record.get("rule"), dict) else {}

        return _base_event(
            record,
            event_id,
            source_name="wazuh",
            event_type="wazuh_alert",
            class_uid=2001,
            class_name="Security Finding",
            category_uid=2,
            category_name="Findings",
            activity_id=1,
            activity_name="Create",
            severity_id=_severity_id(rule.get("level")),
            device=_hostname_object(_host(record)),
            src_endpoint=_ip_object(normalize_empty(get_nested(record, "agent.ip"))),
            finding={
                "uid": str(rule.get("id")) if rule.get("id") is not None else None,
                "title": normalize_empty(rule.get("description")),
                "desc": normalize_empty(rule.get("description")),
                "severity_id": _severity_id(rule.get("level")),
                "mitre_ids": get_nested(rule, "mitre.id", []) or [],
            },
        )


class VulnerabilityFindingAdapter:
    def normalize(self, record: dict[str, Any], event_id: str) -> OCSFEvent:
        vulnerability = get_nested(record, "data.vulnerability", {}) or {}
        severity = normalize_empty(vulnerability.get("severity"))

        return _base_event(
            record,
            event_id,
            source_name="wazuh",
            event_type="vulnerability_event",
            class_uid=2002,
            class_name="Vulnerability Finding",
            category_uid=2,
            category_name="Findings",
            activity_id=1,
            activity_name="Create",
            severity_id=_severity_id(severity),
            device=_hostname_object(_host(record)),
            src_endpoint=_ip_object(normalize_empty(get_nested(record, "agent.ip"))),
            vulnerabilities=[
                {
                    "cve": normalize_empty(vulnerability.get("cve")),
                    "package_name": normalize_empty(get_nested(vulnerability, "package.name")),
                    "severity": severity,
                    "status": normalize_empty(vulnerability.get("status")),
                }
            ],
        )


def _adapter_key(record: dict[str, Any]) -> tuple[str, str]:
    if get_nested(record, "data.vulnerability"):
        return ("wazuh", "vulnerability")

    event_id_raw = str(get_nested(record, "data.win.system.eventID", ""))
    if event_id_raw in {"4624", "4625"}:
        return ("windows_security", event_id_raw)
    if event_id_raw in {"1", "3", "22"}:
        return ("sysmon", event_id_raw)
    if record.get("rule"):
        return ("wazuh", "alert")

    return ("unknown", event_id_raw or "n/a")


def _base_event(
    record: dict[str, Any],
    event_id: str,
    *,
    source_name: str,
    event_type: str,
    class_uid: int,
    class_name: str,
    category_uid: int,
    category_name: str,
    activity_id: int,
    activity_name: str,
    severity_id: int = 1,
    unmapped_fields: dict[str, Any] | None = None,
    **class_fields: Any,
) -> OCSFEvent:
    event_time = _event_time_ms(record)
    unmapped = {
        "event_type": event_type,
        "source": source_name,
        "original_time": _event_timestamp(record),
    }
    if unmapped_fields:
        unmapped.update(unmapped_fields)

    payload = {
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
        "tenant_id": _tenant_id(record),
        "event_id": event_id,
        "source_name": source_name,
        "raw_data": record,
        "unmapped": unmapped,
    }
    payload.update({key: value for key, value in class_fields.items() if value is not None})
    return OCSFEvent(**payload)


def _tenant_id(record: dict[str, Any]) -> str:
    return (
        normalize_empty(record.get("tenant_id"))
        or normalize_empty(get_nested(record, "tenant.id"))
        or normalize_empty(get_nested(record, "organization.id"))
        or get_settings().tenant_id_default
    )


def _event_timestamp(record: dict[str, Any]) -> str:
    return (
        normalize_empty(get_nested(record, "data.win.eventdata.utcTime"))
        or normalize_empty(get_nested(record, "data.win.system.systemTime"))
        or normalize_empty(record.get("timestamp"))
        or datetime.now(timezone.utc).isoformat()
    )


def _event_time_ms(record: dict[str, Any]) -> int:
    value = _event_timestamp(record)
    parsed = _parse_datetime(value)
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


def _host(record: dict[str, Any]) -> str | None:
    return normalize_empty(get_nested(record, "data.win.system.computer") or get_nested(record, "agent.name"))


def _actor(
    *,
    user_name: str | None = None,
    process_path: str | None = None,
    process_obj: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    actor: dict[str, Any] = {}
    if user_name:
        actor["user"] = {"name": user_name}
    if process_obj:
        actor["process"] = process_obj
    elif process_path:
        actor["process"] = _process_object(process_path=process_path)
    return actor or None


def _hostname_object(hostname: str | None) -> dict[str, Any] | None:
    return {"hostname": hostname} if hostname else None


def _ip_object(ip: str | None) -> dict[str, Any] | None:
    return {"ip": ip} if ip else None


def _file_object(process_path: str | None, sha256: str | None = None) -> dict[str, Any] | None:
    file_obj: dict[str, Any] = {}
    if process_path:
        file_obj["path"] = process_path
        file_obj["name"] = process_name_from_path(process_path)
    if sha256:
        file_obj["hashes"] = [{"algorithm": "SHA256", "value": sha256}]
    return file_obj or None


def _process_object(
    *,
    process_path: str | None,
    command_line: str | None = None,
    file_obj: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    process_obj: dict[str, Any] = {}
    if process_path:
        process_obj["name"] = process_name_from_path(process_path)
        process_obj["file"] = file_obj or _file_object(process_path=process_path)
    if command_line:
        process_obj["cmd_line"] = command_line
    return process_obj or None


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


register_adapter("windows_security", "4624", AuthenticationAdapter())
register_adapter("windows_security", "4625", AuthenticationAdapter())
register_adapter("sysmon", "1", ProcessActivityAdapter())
register_adapter("sysmon", "3", NetworkActivityAdapter())
register_adapter("sysmon", "22", DnsActivityAdapter())
register_adapter("wazuh", "alert", SecurityFindingAdapter())
register_adapter("wazuh", "vulnerability", VulnerabilityFindingAdapter())
