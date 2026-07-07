from __future__ import annotations

import json
from pathlib import Path

from app.normalization.normalizer import normalize_event
from app.parsers import list_parsers, preview_parser
from app.entities.extractor import extract_entities
from app.entities.schemas import EntityType


def sysmon_records() -> list[dict]:
    path = Path(__file__).resolve().parents[2] / "sysmon_events.json"
    return json.loads(path.read_bytes().decode("utf-16"))


def test_lists_config_parsers() -> None:
    parser_ids = {parser.id for parser in list_parsers()}

    assert {"wazuh-archive", "sysmon"}.issubset(parser_ids)
    assert "wazuh-alert" not in parser_ids


def test_normalizes_sysmon_json_process_event() -> None:
    record = next(item for item in sysmon_records() if item["Id"] == 1)
    event = normalize_event(record, parser_id="sysmon")

    assert event.source_name == "sysmon"
    assert event.event_type == "process_execution"
    assert event.class_uid == 1007
    assert event.actor["user"]["name"]
    assert event.process["name"].lower().endswith(".exe")
    assert event.process["file"]["hashes"][0]["algorithm"] == "SHA256"
    assert event.unmapped["parser_id"] == "sysmon"


def test_normalizes_sysmon_json_network_and_dns_events() -> None:
    network = normalize_event(next(item for item in sysmon_records() if item["Id"] == 3), parser_id="sysmon")
    dns = normalize_event(next(item for item in sysmon_records() if item["Id"] == 22), parser_id="sysmon")

    assert network.event_type == "network_connection"
    assert network.class_uid == 4001
    assert network.src_endpoint["ip"]
    assert network.dst_endpoint["ip"]
    assert dns.event_type == "dns_query"
    assert dns.class_uid == 4003
    assert dns.query["hostname"]


def test_preview_uses_explicit_sysmon_parser() -> None:
    event = preview_parser(sysmon_records()[0], "sysmon")

    assert event.source_name == "sysmon"
    assert event.unmapped["windows_event_id"] == "11"


def test_wazuh_archive_dispatches_alert_records() -> None:
    event = normalize_event(
        {
            "id": "alert-1",
            "timestamp": "2026-07-02T14:50:01.005+0000",
            "agent": {"name": "acme-ws-01", "ip": "10.10.1.24"},
            "decoder": {"name": "windows_eventchannel"},
            "rule": {"id": "100001", "level": 12, "description": "Suspicious process", "groups": ["sysmon"]},
        },
        parser_id="wazuh-archive",
    )

    assert event.source_name == "wazuh"
    assert event.event_type == "wazuh_alert"
    assert event.finding["uid"] == "100001"
    assert event.unmapped["parser_id"] == "wazuh-archive"
    assert event.unmapped["dispatched_parser_id"] == "wazuh-alert"


def test_wazuh_archive_dispatches_vulnerability_records_and_extracts_cve() -> None:
    event = normalize_event(
        {
            "id": "vuln-1",
            "timestamp": "2026-06-16T15:08:49.163+0000",
            "rule": {
                "level": 3,
                "description": "The CVE-2026-41611 that affected Microsoft Visual Studio Code (User) was solved.",
                "id": "23502",
                "groups": ["vulnerability-detector"],
            },
            "agent": {"id": "001", "name": "Xuan-An", "ip": "192.168.0.119"},
            "decoder": {"name": "json"},
            "data": {
                "vulnerability": {
                    "cve": "CVE-2026-41611",
                    "package": {"name": "Microsoft Visual Studio Code (User)", "version": "1.118.1"},
                    "severity": "High",
                    "status": "Solved",
                    "title": "CVE-2026-41611 affecting Microsoft Visual Studio Code (User) was solved",
                }
            },
            "location": "vulnerability-detector",
        },
        parser_id="wazuh-archive",
    )

    cve_entities = {entity.value for entity in extract_entities(event) if entity.type == EntityType.CVE}

    assert event.source_name == "wazuh"
    assert event.event_type == "vulnerability_event"
    assert event.class_uid == 2002
    assert event.vulnerabilities is not None
    assert event.vulnerabilities[0]["cve"] == "CVE-2026-41611"
    assert cve_entities == {"CVE-2026-41611"}
    assert event.unmapped["parser_id"] == "wazuh-archive"
    assert event.unmapped["dispatched_parser_id"] == "wazuh-vulnerability"


def test_wazuh_archive_dispatches_wrapped_sysmon_records() -> None:
    event = normalize_event(
        {
            "id": "archive-1",
            "timestamp": "2026-06-16T15:09:20.663+0000",
            "agent": {"name": "Xuan-An", "ip": "192.168.0.119"},
            "decoder": {"name": "windows_eventchannel"},
            "data": {
                "win": {
                    "system": {
                        "providerName": "Microsoft-Windows-Sysmon",
                        "eventID": "10",
                        "systemTime": "2026-06-16T15:09:19.7168289Z",
                        "eventRecordID": "12312",
                        "computer": "Xuan-An",
                        "channel": "Microsoft-Windows-Sysmon/Operational",
                    },
                    "eventdata": {
                        "utcTime": "2026-06-16 15:09:19.715",
                        "sourceImage": r"C:\WINDOWS\system32\taskhostw.exe",
                        "targetImage": r"C:\Program Files\Docker\Docker\frontend\Docker Desktop.exe",
                        "sourceUser": r"NT AUTHORITY\SYSTEM",
                    },
                }
            },
        },
        parser_id="wazuh-archive",
    )

    assert event.source_name == "wazuh_sysmon"
    assert event.event_type == "process_access"
    assert event.class_uid == 1007
    assert event.process["name"] == "taskhostw.exe"
    assert event.file["name"] == "Docker Desktop.exe"
    assert event.unmapped["parser_id"] == "wazuh-archive"
    assert event.unmapped["dispatched_parser_id"] == "wazuh-sysmon"


def test_wazuh_archive_dispatches_syscollector_process_records() -> None:
    event = normalize_event(
        {
            "id": "inventory-1",
            "timestamp": "2026-06-16T15:09:20.716+0000",
            "agent": {"name": "Xuan-An", "ip": "192.168.0.119"},
            "decoder": {"name": "syscollector"},
            "data": {
                "type": "dbsync_processes",
                "operation_type": "MODIFIED",
                "process": {
                    "pid": "18828",
                    "name": "wslhost.exe",
                    "ppid": "17764",
                    "cmd": "--vm-id demo --handle 2684",
                },
            },
        },
        parser_id="wazuh-archive",
    )

    assert event.source_name == "wazuh_syscollector"
    assert event.event_type == "process_inventory"
    assert event.process["name"] == "wslhost.exe"
    assert event.unmapped["parser_id"] == "wazuh-archive"
    assert event.unmapped["dispatched_parser_id"] == "wazuh-syscollector-process"


def test_wazuh_archive_uses_generic_fallback_for_other_wazuh_records() -> None:
    event = normalize_event(
        {
            "id": "generic-1",
            "timestamp": "2026-06-16T15:09:20.716+0000",
            "agent": {"name": "Xuan-An", "ip": "192.168.0.119"},
            "decoder": {"name": "rootcheck"},
            "location": "rootcheck",
            "full_log": "Rootcheck sample",
        },
        parser_id="wazuh-archive",
    )

    assert event.source_name == "wazuh"
    assert event.event_type == "rootcheck"
    assert event.device["hostname"] == "Xuan-An"
    assert event.unmapped["parser_id"] == "wazuh-archive"
    assert event.unmapped["dispatched_parser_id"] == "wazuh-generic"
