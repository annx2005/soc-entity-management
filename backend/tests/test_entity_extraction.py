from app.entities import EntityType, extract_entities
from app.normalization.normalizer import normalize_event
from app.ocsf.schemas import OCSFEvent


def base_record(event_id: str, eventdata: dict) -> dict:
    return {
        "id": "evt-1",
        "tenant_id": "tenant-acme",
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


def entity_values(event: OCSFEvent, entity_type: EntityType) -> set[str]:
    return {entity.value for entity in extract_entities(event) if entity.type == entity_type}


def make_empty_event(**overrides: object) -> OCSFEvent:
    payload = {
        "metadata": {"version": "1.2.0", "uid": "evt-empty", "product": {"name": "SOC Entity Management"}},
        "time": 1783003800000,
        "class_uid": 9999,
        "class_name": "Unknown Event",
        "category_uid": 0,
        "category_name": "Unknown",
        "activity_id": 0,
        "activity_name": "Unknown",
        "type_uid": 999900,
        "type_name": "Unknown Event: Unknown",
        "severity_id": 1,
        "tenant_id": "tenant-acme",
        "event_id": "evt-empty",
        "source_name": "unit_test",
        "raw_data": {},
        "unmapped": {},
    }
    payload.update(overrides)
    return OCSFEvent(**payload)


def test_extract_auth_event_user_host_ip_from_ocsf_fields() -> None:
    event = normalize_event(
        base_record(
            "4624",
            {"targetUserName": "XuanAn", "ipAddress": "127.0.0.1", "processName": r"C:\Windows\System32\services.exe"},
        )
    )

    assert entity_values(event, EntityType.USER) == {"xuanan"}
    assert entity_values(event, EntityType.HOST) == {"xuan-an"}
    assert entity_values(event, EntityType.IP) == {"127.0.0.1"}


def test_extract_sysmon_process_event_user_host_process_and_file_hash() -> None:
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

    assert entity_values(event, EntityType.USER) == {r"xuan-an\xuanan"}
    assert entity_values(event, EntityType.HOST) == {"xuan-an"}
    assert entity_values(event, EntityType.PROCESS) == {r"c:\windows\system32\curl.exe"}
    assert entity_values(event, EntityType.FILE_HASH) == {
        "642a07eeea4d3132426e673fb3c88be8cead3d03ca1f019c7e7d0000ed2122be"
    }


def test_extract_network_and_dns_entities() -> None:
    network_event = normalize_event(
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
    dns_event = normalize_event(
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

    assert entity_values(network_event, EntityType.IP) == {"172.20.208.1", "224.0.0.251"}
    assert entity_values(dns_event, EntityType.DOMAIN) == {"github.com"}
    assert entity_values(dns_event, EntityType.IP) == {"20.205.243.166"}


def test_file_hash_extracts_canonical_lowercase() -> None:
    event = normalize_event(
        base_record(
            "1",
            {
                "image": r"C:\Windows\System32\curl.exe",
                "hashes": "SHA256=DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
            },
        )
    )

    assert entity_values(event, EntityType.FILE_HASH) == {
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    }


def test_dedupes_duplicate_host_sources_in_same_event() -> None:
    event = normalize_event(
        base_record(
            "4624",
            {"targetUserName": "XuanAn", "ipAddress": "127.0.0.1", "processName": r"C:\Windows\System32\services.exe"},
        )
    )

    hosts = [entity for entity in extract_entities(event) if entity.type == EntityType.HOST]

    assert len(hosts) == 1
    assert hosts[0].value == "xuan-an"


def test_invalid_null_and_placeholder_values_are_filtered() -> None:
    event = make_empty_event(
        actor={"user": {"name": "unknown"}},
        device={"hostname": "-"},
        src_endpoint={"ip": "999.999.999.999"},
        dst_endpoint={"ip": None},
        query={"hostname": "bad_domain.example"},
        process={"name": "n/a", "file": {"path": "", "hashes": [{"algorithm": "SHA256", "value": "not-a-hash"}]}},
    )

    assert extract_entities(event) == []


def test_extractor_does_not_read_raw_data_or_unmapped() -> None:
    event = make_empty_event(
        raw_data={
            "actor": {"user": {"name": "raw-user"}},
            "device": {"hostname": "raw-host"},
            "src_endpoint": {"ip": "1.2.3.4"},
        },
        unmapped={"query": {"hostname": "raw.example.com"}},
    )

    assert extract_entities(event) == []


def test_entity_id_deterministic() -> None:
    event = normalize_event(
        base_record(
            "4624",
            {"targetUserName": "XuanAn", "ipAddress": "127.0.0.1", "processName": r"C:\Windows\System32\services.exe"},
        )
    )

    first = extract_entities(event)
    second = extract_entities(event)

    assert [entity.id for entity in first] == [entity.id for entity in second]


def test_entity_id_tenant_isolation() -> None:
    event_a = make_empty_event(tenant_id="tenant-a", src_endpoint={"ip": "1.2.3.4"})
    event_b = make_empty_event(tenant_id="tenant-b", src_endpoint={"ip": "1.2.3.4"})

    id_a = extract_entities(event_a)[0].id
    id_b = extract_entities(event_b)[0].id

    assert id_a != id_b


def test_extract_returns_empty_for_unrecognized_event() -> None:
    event = make_empty_event()

    assert extract_entities(event) == []
