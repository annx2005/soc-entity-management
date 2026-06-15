from app.normalization.normalizer import normalize_event


def base_record(event_id: str, eventdata: dict) -> dict:
    return {
        "id": "evt-1",
        "timestamp": "2026-07-02T14:50:01.005+0000",
        "agent": {"name": "Xuan-An", "ip": "192.168.0.119"},
        "data": {
            "win": {
                "system": {
                    "eventID": event_id,
                    "systemTime": "2026-07-02T14:50:00.000Z",
                    "computer": "Xuan-An",
                },
                "eventdata": eventdata,
            }
        },
    }


def test_normalize_windows_logon_success() -> None:
    event = normalize_event(
        base_record(
            "4624",
            {"targetUserName": "XuanAn", "ipAddress": "127.0.0.1", "processName": r"C:\Windows\System32\services.exe"},
        )
    )

    assert event.class_uid == 3002
    assert event.class_name == "Authentication"
    assert event.event_type == "windows_logon_success"
    assert event.source_name == "windows_security"
    assert event.actor["user"]["name"] == "XuanAn"
    assert event.device["hostname"] == "Xuan-An"
    assert event.dst_endpoint["hostname"] == "Xuan-An"


def test_normalize_uses_record_tenant_id() -> None:
    record = base_record(
        "4624",
        {"targetUserName": "alice", "ipAddress": "10.10.1.24", "processName": r"C:\Windows\System32\lsass.exe"},
    )
    record["tenant_id"] = "tenant-acme"

    event = normalize_event(record)

    assert event.tenant_id == "tenant-acme"


def test_normalize_windows_logon_failure() -> None:
    event = normalize_event(
        base_record(
            "4625",
            {"targetUserName": "fakeuser", "ipAddress": "::1", "processName": r"C:\Windows\System32\svchost.exe"},
        )
    )

    assert event.class_uid == 3002
    assert event.activity_name == "Logon Failure"
    assert event.event_type == "windows_logon_failure"
    assert event.actor["user"]["name"] == "fakeuser"
    assert event.src_endpoint["ip"] == "::1"


def test_normalize_sysmon_network_connection() -> None:
    event = normalize_event(
        base_record(
            "3",
            {
                "user": r"NT AUTHORITY\SYSTEM",
                "sourceIp": "172.20.208.1",
                "destinationIp": "224.0.0.251",
                "image": r"C:\Program Files\App\agent.exe",
            },
        )
    )

    assert event.class_uid == 4001
    assert event.class_name == "Network Activity"
    assert event.event_type == "network_connection"
    assert event.dst_endpoint["ip"] == "224.0.0.251"
    assert event.process["name"] == "agent.exe"


def test_normalize_sysmon_dns_query() -> None:
    event = normalize_event(
        base_record(
            "22",
            {
                "user": r"Xuan-An\XuanAn",
                "queryName": "GitHub.COM.",
                "queryResults": "::ffff:20.205.243.166;",
                "image": r"C:\Windows\System32\curl.exe",
            },
        )
    )

    assert event.class_uid == 4003
    assert event.class_name == "DNS Activity"
    assert event.event_type == "dns_query"
    assert event.query["hostname"] == "github.com"
    assert event.dst_endpoint["ip"] == "20.205.243.166"


def test_normalize_sysmon_process_execution() -> None:
    event = normalize_event(
        base_record(
            "1",
            {
                "user": r"Xuan-An\XuanAn",
                "image": r"C:\Windows\System32\curl.exe",
                "commandLine": r'"C:\Windows\system32\curl.exe" https://github.com',
                "hashes": "MD5=abc,SHA256=642A07EEEA4D3132426E673FB3C88BE8CEAD3D03CA1F019C7E7D0000ED2122BE",
            },
        )
    )

    assert event.class_uid == 1007
    assert event.class_name == "Process Activity"
    assert event.event_type == "process_execution"
    assert event.process["name"] == "curl.exe"
    assert event.process["file"]["hashes"][0]["value"] == "642A07EEEA4D3132426E673FB3C88BE8CEAD3D03CA1F019C7E7D0000ED2122BE"


def test_normalize_wazuh_alert() -> None:
    event = normalize_event(
        {
            "id": "alert-1",
            "timestamp": "2026-07-02T14:53:53.633+0000",
            "agent": {"name": "Xuan-An", "ip": "192.168.0.119"},
            "rule": {"id": "92200", "level": 6, "description": "Scripting file created", "mitre": {"id": ["T1059"]}},
        }
    )

    assert event.class_uid == 2001
    assert event.class_name == "Security Finding"
    assert event.event_type == "wazuh_alert"
    assert event.finding is not None
    assert event.finding["uid"] == "92200"


def test_normalize_vulnerability_event() -> None:
    event = normalize_event(
        {
            "id": "vuln-1",
            "timestamp": "2026-07-02T15:08:49.163+0000",
            "agent": {"name": "Xuan-An", "ip": "192.168.0.119"},
            "data": {
                "vulnerability": {
                    "cve": "CVE-2026-41611",
                    "package": {"name": "Microsoft Visual Studio Code (User)"},
                    "severity": "High",
                    "status": "Solved",
                }
            },
        }
    )

    assert event.class_uid == 2002
    assert event.class_name == "Vulnerability Finding"
    assert event.event_type == "vulnerability_event"
    assert event.vulnerabilities is not None
    assert event.vulnerabilities[0]["cve"] == "CVE-2026-41611"
