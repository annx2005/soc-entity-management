from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "raw"
ENRICHMENT_DIR = ROOT / "data" / "enrichment"

TENANTS = [
    {
        "id": "tenant-acme",
        "org": "Acme Manufacturing",
        "hosts": [
            {"agent_id": "101", "host": "acme-ws-01", "ip": "10.10.1.24", "user": r"ACME\alice"},
            {"agent_id": "102", "host": "acme-srv-01", "ip": "10.10.1.40", "user": r"ACME\bob"},
            {"agent_id": "103", "host": "acme-dc-01", "ip": "10.10.1.10", "user": r"ACME\svc-backup"},
        ],
    },
    {
        "id": "tenant-globex",
        "org": "Globex Retail",
        "hosts": [
            {"agent_id": "201", "host": "globex-ws-07", "ip": "10.20.7.31", "user": r"GLOBEX\maya"},
            {"agent_id": "202", "host": "globex-app-02", "ip": "10.20.7.52", "user": r"GLOBEX\noah"},
            {"agent_id": "203", "host": "globex-dc-01", "ip": "10.20.7.10", "user": r"GLOBEX\svc-deploy"},
        ],
    },
]

BENIGN_HASH = "1111111111111111111111111111111111111111111111111111111111111111"
LOLBIN_HASH = "2222222222222222222222222222222222222222222222222222222222222222"
SHARED_MALWARE_HASH = "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"


def main() -> None:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    ENRICHMENT_DIR.mkdir(parents=True, exist_ok=True)

    all_records: list[dict[str, Any]] = []
    records_by_tenant: dict[str, list[dict[str, Any]]] = {}
    base_time = datetime(2026, 7, 3, 2, 0, tzinfo=timezone.utc)

    counter = 1
    for tenant_index, tenant in enumerate(TENANTS):
        tenant_records: list[dict[str, Any]] = []
        for host_index, host in enumerate(tenant["hosts"]):
            t = base_time + timedelta(minutes=(tenant_index * 60) + (host_index * 8))
            generated = _host_story(tenant, host, t, counter)
            counter += len(generated)
            tenant_records.extend(generated)

        records_by_tenant[tenant["id"]] = tenant_records
        all_records.extend(tenant_records)

    _write_jsonl(RAW_DIR / "fake-multitenant-wazuh.jsonl", all_records)
    _write_json(RAW_DIR / "fake-multitenant-summary.json", _summary(records_by_tenant))

    for tenant_id, records in records_by_tenant.items():
        _write_jsonl(RAW_DIR / f"fake-{tenant_id}.jsonl", records)

    _write_json(ENRICHMENT_DIR / "ip_enrichment.json", _ip_enrichment())
    _write_json(ENRICHMENT_DIR / "file_hash_enrichment.json", _file_hash_enrichment())


def _host_story(tenant: dict[str, Any], host: dict[str, str], start: datetime, start_counter: int) -> list[dict[str, Any]]:
    user = host["user"]
    host_name = host["host"]
    host_ip = host["ip"]
    tenant_id = tenant["id"]
    agent = {"id": host["agent_id"], "name": host_name, "ip": host_ip}
    c = start_counter

    records = [
        _windows_event(
            tenant_id,
            agent,
            c,
            start,
            "4624",
            {
                "targetUserName": user.split("\\")[-1],
                "ipAddress": host_ip,
                "processName": r"C:\Windows\System32\lsass.exe",
            },
        ),
        _windows_event(
            tenant_id,
            agent,
            c + 1,
            start + timedelta(seconds=40),
            "1",
            {
                "user": user,
                "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "commandLine": r'powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\update.ps1',
                "hashes": f"MD5=abc,SHA256={LOLBIN_HASH},IMPHASH=def",
            },
        ),
        _windows_event(
            tenant_id,
            agent,
            c + 2,
            start + timedelta(seconds=75),
            "22",
            {
                "user": user,
                "queryName": "update-check.example.",
                "queryResults": "type: 1 update-check.example;198.51.100.23;",
                "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            },
        ),
        _windows_event(
            tenant_id,
            agent,
            c + 3,
            start + timedelta(seconds=90),
            "3",
            {
                "user": user,
                "sourceIp": host_ip,
                "destinationIp": "198.51.100.23",
                "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            },
        ),
        _windows_event(
            tenant_id,
            agent,
            c + 4,
            start + timedelta(seconds=115),
            "1",
            {
                "user": user,
                "image": r"C:\Users\Public\svhost.exe",
                "commandLine": r"C:\Users\Public\svhost.exe --beacon update-check.example",
                "hashes": f"SHA256={SHARED_MALWARE_HASH},MD5=bad",
            },
        ),
        _windows_event(
            tenant_id,
            agent,
            c + 5,
            start + timedelta(seconds=135),
            "3",
            {
                "user": user,
                "sourceIp": host_ip,
                "destinationIp": "8.8.8.8",
                "image": r"C:\Users\Public\svhost.exe",
            },
        ),
        _wazuh_alert(
            tenant_id,
            agent,
            c + 6,
            start + timedelta(seconds=150),
            "92200",
            10,
            "Suspicious PowerShell download and execution pattern",
            ["T1059.001", "T1105"],
        ),
        _vulnerability_event(
            tenant_id,
            agent,
            c + 7,
            start + timedelta(seconds=180),
            "CVE-2026-41611",
            "Microsoft Visual Studio Code (User)",
            "High",
        ),
    ]

    if host_name.endswith("01"):
        records.append(
            _windows_event(
                tenant_id,
                agent,
                c + 8,
                start + timedelta(seconds=210),
                "4625",
                {
                    "targetUserName": "admin",
                    "ipAddress": "203.0.113.77",
                    "processName": r"C:\Windows\System32\svchost.exe",
                },
            )
        )
    else:
        records.append(
            _windows_event(
                tenant_id,
                agent,
                c + 8,
                start + timedelta(seconds=210),
                "22",
                {
                    "user": user,
                    "queryName": "github.com.",
                    "queryResults": "type: 1 github.com;140.82.113.3;",
                    "image": r"C:\Windows\System32\curl.exe",
                },
            )
        )

    return records


def _windows_event(
    tenant_id: str,
    agent: dict[str, str],
    counter: int,
    timestamp: datetime,
    event_id: str,
    eventdata: dict[str, str],
) -> dict[str, Any]:
    system_time = timestamp.isoformat().replace("+00:00", "Z")
    return {
        "tenant_id": tenant_id,
        "timestamp": system_time,
        "agent": agent,
        "manager": {"name": "wazuh.manager"},
        "id": f"fake-{tenant_id}-{counter:05d}",
        "decoder": {"name": "windows_eventchannel"},
        "location": "EventChannel",
        "data": {
            "win": {
                "system": {
                    "providerName": _provider_name(event_id),
                    "eventID": event_id,
                    "systemTime": system_time,
                    "computer": agent["name"],
                    "channel": _channel(event_id),
                    "severityValue": "INFORMATION",
                },
                "eventdata": eventdata,
            }
        },
    }


def _wazuh_alert(
    tenant_id: str,
    agent: dict[str, str],
    counter: int,
    timestamp: datetime,
    rule_id: str,
    level: int,
    description: str,
    mitre_ids: list[str],
) -> dict[str, Any]:
    return {
        "tenant_id": tenant_id,
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "agent": agent,
        "manager": {"name": "wazuh.manager"},
        "id": f"fake-{tenant_id}-{counter:05d}",
        "decoder": {"name": "wazuh-alert"},
        "location": "alerts",
        "rule": {
            "id": rule_id,
            "level": level,
            "description": description,
            "mitre": {"id": mitre_ids},
        },
    }


def _vulnerability_event(
    tenant_id: str,
    agent: dict[str, str],
    counter: int,
    timestamp: datetime,
    cve: str,
    package_name: str,
    severity: str,
) -> dict[str, Any]:
    return {
        "tenant_id": tenant_id,
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "agent": agent,
        "manager": {"name": "wazuh.manager"},
        "id": f"fake-{tenant_id}-{counter:05d}",
        "decoder": {"name": "vulnerability-detector"},
        "location": "vulnerability-detector",
        "data": {
            "vulnerability": {
                "cve": cve,
                "package": {"name": package_name},
                "severity": severity,
                "status": "Active",
            }
        },
    }


def _provider_name(event_id: str) -> str:
    if event_id in {"1", "3", "22"}:
        return "Microsoft-Windows-Sysmon"
    return "Microsoft-Windows-Security-Auditing"


def _channel(event_id: str) -> str:
    if event_id in {"1", "3", "22"}:
        return "Microsoft-Windows-Sysmon/Operational"
    return "Security"


def _summary(records_by_tenant: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    tenants = []
    for tenant_id, records in records_by_tenant.items():
        hosts = sorted({record["agent"]["name"] for record in records})
        event_types = {}
        for record in records:
            event_id = record.get("data", {}).get("win", {}).get("system", {}).get("eventID")
            key = event_id or ("vulnerability" if record.get("data", {}).get("vulnerability") else "wazuh_alert")
            event_types[key] = event_types.get(key, 0) + 1
        tenants.append({"tenant_id": tenant_id, "records": len(records), "hosts": hosts, "event_types": event_types})
    return {
        "dataset": "fake-multitenant-wazuh",
        "purpose": "Demo tenant isolation for SOC entity management MVP",
        "shared_iocs": {
            "domains": ["update-check.example", "github.com"],
            "ips": ["198.51.100.23", "8.8.8.8", "203.0.113.77", "140.82.113.3"],
            "file_hashes": [SHARED_MALWARE_HASH],
        },
        "tenants": tenants,
    }


def _ip_enrichment() -> dict[str, dict[str, Any]]:
    return {
        "198.51.100.23": {"country": "US", "asn": "AS64501", "reputation": "suspicious", "provider": "offline-demo"},
        "203.0.113.77": {"country": "SG", "asn": "AS64502", "reputation": "scanner", "provider": "offline-demo"},
        "140.82.113.3": {"country": "US", "asn": "AS36459", "reputation": "benign", "provider": "offline-demo"},
        "8.8.8.8": {"country": "US", "asn": "AS15169", "reputation": "benign", "provider": "offline-demo"},
    }


def _file_hash_enrichment() -> dict[str, dict[str, Any]]:
    return {
        BENIGN_HASH: {"malware_family": None, "reputation": "benign", "provider": "offline-demo"},
        LOLBIN_HASH: {"malware_family": None, "reputation": "known_lolbin", "provider": "offline-demo"},
        SHARED_MALWARE_HASH: {
            "malware_family": "DemoLoader",
            "reputation": "malicious",
            "provider": "offline-demo",
        },
    }


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as stream:
        for record in records:
            stream.write(json.dumps(record, sort_keys=True) + "\n")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
