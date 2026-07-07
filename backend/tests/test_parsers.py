from __future__ import annotations

import json
from pathlib import Path

from app.normalization.normalizer import normalize_event
from app.parsers import list_parsers, preview_parser


def sysmon_records() -> list[dict]:
    path = Path(__file__).resolve().parents[2] / "sysmon_events.json"
    return json.loads(path.read_bytes().decode("utf-16"))


def test_lists_config_parsers() -> None:
    parser_ids = {parser.id for parser in list_parsers()}

    assert {"wazuh-alert", "sysmon"}.issubset(parser_ids)


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
