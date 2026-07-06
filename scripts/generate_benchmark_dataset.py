from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "data" / "generated" / "benchmark-ocsf.jsonl"
DEFAULT_MANIFEST = ROOT / "data" / "generated" / "benchmark-ocsf-manifest.json"
ENTITY_TYPES = (
    "user",
    "host",
    "ip",
    "domain",
    "file_hash",
    "process",
    "url",
    "email",
    "cve",
    "cloud_resource",
)
RELATIONSHIP_TYPES = (
    "LOGGED_IN_TO",
    "FAILED_LOGON_TO",
    "AUTHENTICATED_TO",
    "ATTEMPTED_LOGON_TO",
    "CONNECTED_TO",
    "USED_IP",
    "RESOLVED_DOMAIN",
    "RESOLVED_TO",
    "EXECUTED_ON",
    "HAS_HASH",
    "RAN_AS",
    "USER_HAS_EMAIL",
    "PROCESS_ACCESSED_URL",
    "EMAIL_SENT_TO",
    "ACCESSED_CLOUD_RESOURCE",
    "AFFECTED_BY_CVE",
)


def main() -> None:
    args = _parse_args()
    manifest = generate_dataset(
        output_path=args.output,
        manifest_path=args.manifest,
        seed=args.seed,
        tenants=args.tenants,
        entity_target=args.entity_target,
        relationship_target=args.relationship_target,
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "manifest": str(args.manifest),
                "entities": manifest["unique_entities"],
                "relationships": manifest["unique_relationships"],
                "events": manifest["events"],
            },
            indent=2,
            sort_keys=True,
        )
    )


def generate_dataset(
    *,
    output_path: Path = DEFAULT_OUTPUT,
    manifest_path: Path = DEFAULT_MANIFEST,
    seed: int = 424242,
    tenants: int = 2,
    entity_target: int = 12000,
    relationship_target: int = 1_000_000,
) -> dict[str, Any]:
    if tenants < 1:
        raise ValueError("tenants must be >= 1")
    rng = random.Random(seed)
    tenant_ids = [f"tenant-bench-{index + 1:02d}" for index in range(tenants)]
    pools = _build_entity_pools(tenant_ids, entity_target, rng)
    capacity = _relationship_capacity(pools)
    if capacity < relationship_target:
        raise ValueError(f"relationship target {relationship_target} exceeds generated pool capacity {capacity}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    entity_keys = {(tenant_id, entity_type, value) for tenant_id, by_type in pools.items() for entity_type, values in by_type.items() for value in values}
    relationship_keys: set[tuple[str, str, str, str]] = set()
    entity_counts = Counter({entity_type: 0 for entity_type in ENTITY_TYPES})
    relationship_counts = Counter({relationship_type: 0 for relationship_type in RELATIONSHIP_TYPES})
    for _, entity_type, _ in entity_keys:
        entity_counts[entity_type] += 1

    base_time = datetime(2026, 7, 7, tzinfo=timezone.utc)
    attempts = 0
    event_index = 0
    with output_path.open("w", encoding="utf-8") as stream:
        while len(relationship_keys) < relationship_target:
            relationship_type = RELATIONSHIP_TYPES[event_index % len(RELATIONSHIP_TYPES)]
            tenant_id = tenant_ids[event_index % len(tenant_ids)]
            source_type, target_type = _relationship_entity_types(relationship_type)
            source = _pick(pools[tenant_id][source_type], event_index, 17)
            target = _pick(pools[tenant_id][target_type], event_index, 43)
            if source == target:
                attempts += 1
                event_index += 1
                continue

            key = (tenant_id, relationship_type, f"{source_type}:{source}", f"{target_type}:{target}")
            if key in relationship_keys:
                attempts += 1
                if attempts > relationship_target * 20:
                    raise ValueError("relationship target could not be reached with deterministic pool selection")
                event_index += 1
                continue

            relationship_keys.add(key)
            relationship_counts[relationship_type] += 1
            event = _event_for_relationship(
                tenant_id=tenant_id,
                event_id=f"bench-{event_index:09d}",
                relationship_type=relationship_type,
                source=source,
                target=target,
                observed_at=base_time + timedelta(seconds=event_index),
            )
            stream.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
            event_index += 1

    manifest = {
        "seed": seed,
        "tenants": tenant_ids,
        "output": str(output_path),
        "events": event_index,
        "unique_entities": len(entity_keys),
        "unique_relationships": len(relationship_keys),
        "entity_counts": dict(sorted(entity_counts.items())),
        "relationship_counts": dict(sorted(relationship_counts.items())),
    }
    if manifest["unique_entities"] < 10_000 or manifest["unique_relationships"] < 1_000_000:
        if entity_target >= 10_000 or relationship_target >= 1_000_000:
            raise ValueError("benchmark manifest failed minimum scale requirements")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def _build_entity_pools(tenant_ids: list[str], entity_target: int, rng: random.Random) -> dict[str, dict[str, list[str]]]:
    per_type = max(8, (entity_target + (len(tenant_ids) * len(ENTITY_TYPES)) - 1) // (len(tenant_ids) * len(ENTITY_TYPES)))
    pools: dict[str, dict[str, list[str]]] = {}
    for tenant_index, tenant_id in enumerate(tenant_ids):
        pools[tenant_id] = {
            "user": [f"user{tenant_index:02d}-{index:05d}" for index in range(per_type)],
            "host": [f"host-{tenant_index:02d}-{index:05d}.corp.local" for index in range(per_type)],
            "ip": [f"10.{tenant_index % 200}.{index // 250}.{index % 250 + 1}" for index in range(per_type)],
            "domain": [f"service-{tenant_index:02d}-{index:05d}.example.net" for index in range(per_type)],
            "file_hash": [_hash_value(tenant_index, index, rng) for index in range(per_type)],
            "process": [rf"c:\program files\bench\proc-{tenant_index:02d}-{index:05d}.exe" for index in range(per_type)],
            "url": [f"https://service-{tenant_index:02d}-{index:05d}.example.net/api/{index}" for index in range(per_type)],
            "email": [f"user{tenant_index:02d}-{index:05d}@example.net" for index in range(per_type)],
            "cve": [f"CVE-2026-{10000 + index}" for index in range(per_type)],
            "cloud_resource": [
                f"arn:aws:ec2:us-east-1:{100000000000 + tenant_index}:instance/i-{tenant_index:02d}{index:010d}"
                for index in range(per_type)
            ],
        }
    return pools


def _relationship_capacity(pools: dict[str, dict[str, list[str]]]) -> int:
    total = 0
    for by_type in pools.values():
        for relationship_type in RELATIONSHIP_TYPES:
            source_type, target_type = _relationship_entity_types(relationship_type)
            total += len(by_type[source_type]) * len(by_type[target_type])
    return total


def _relationship_entity_types(relationship_type: str) -> tuple[str, str]:
    return {
        "LOGGED_IN_TO": ("user", "host"),
        "FAILED_LOGON_TO": ("user", "host"),
        "AUTHENTICATED_TO": ("ip", "host"),
        "ATTEMPTED_LOGON_TO": ("ip", "host"),
        "CONNECTED_TO": ("host", "ip"),
        "USED_IP": ("host", "ip"),
        "RESOLVED_DOMAIN": ("host", "domain"),
        "RESOLVED_TO": ("domain", "ip"),
        "EXECUTED_ON": ("process", "host"),
        "HAS_HASH": ("process", "file_hash"),
        "RAN_AS": ("process", "user"),
        "USER_HAS_EMAIL": ("user", "email"),
        "PROCESS_ACCESSED_URL": ("process", "url"),
        "EMAIL_SENT_TO": ("email", "email"),
        "ACCESSED_CLOUD_RESOURCE": ("process", "cloud_resource"),
        "AFFECTED_BY_CVE": ("host", "cve"),
    }[relationship_type]


def _event_for_relationship(
    *,
    tenant_id: str,
    event_id: str,
    relationship_type: str,
    source: str,
    target: str,
    observed_at: datetime,
) -> dict[str, Any]:
    event = _base_ocsf_event(tenant_id, event_id, observed_at)
    if relationship_type in {"LOGGED_IN_TO", "FAILED_LOGON_TO"}:
        event.update(_auth_fields(source, target, relationship_type == "LOGGED_IN_TO"))
    elif relationship_type in {"AUTHENTICATED_TO", "ATTEMPTED_LOGON_TO"}:
        event.update(_auth_fields(None, target, relationship_type == "AUTHENTICATED_TO", source_ip=source))
    elif relationship_type in {"CONNECTED_TO", "USED_IP"}:
        event.update(_network_fields(source, src_ip=target if relationship_type == "USED_IP" else None, dst_ip=target if relationship_type == "CONNECTED_TO" else None))
    elif relationship_type == "RESOLVED_DOMAIN":
        event.update(_dns_fields(source, target, None))
    elif relationship_type == "RESOLVED_TO":
        event.update(_dns_fields(None, source, target))
    elif relationship_type == "EXECUTED_ON":
        event.update(_process_fields(source, host=target))
    elif relationship_type == "HAS_HASH":
        event.update(_process_fields(source, file_hash=target))
    elif relationship_type == "RAN_AS":
        event.update(_process_fields(source, user=target))
    elif relationship_type == "USER_HAS_EMAIL":
        event.update(_auth_fields(source, None, True, email=target))
    elif relationship_type == "PROCESS_ACCESSED_URL":
        event.update(_process_fields(source, url=target))
    elif relationship_type == "EMAIL_SENT_TO":
        event.update(_finding_fields(email_from=source, email_to=target))
    elif relationship_type == "ACCESSED_CLOUD_RESOURCE":
        event.update(_process_fields(source, cloud_resource=target))
    elif relationship_type == "AFFECTED_BY_CVE":
        event.update(_vulnerability_fields(source, target))
    return event


def _base_ocsf_event(tenant_id: str, event_id: str, observed_at: datetime) -> dict[str, Any]:
    return {
        "metadata": {"version": "1.2.0", "uid": event_id, "product": {"name": "SOC Entity Management Benchmark"}},
        "time": int(observed_at.timestamp() * 1000),
        "class_uid": 2001,
        "class_name": "Security Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": 1,
        "activity_name": "Create",
        "type_uid": 200101,
        "type_name": "Security Finding: Create",
        "severity_id": 1,
        "tenant_id": tenant_id,
        "event_id": event_id,
        "source_name": "benchmark",
        "raw_data": {},
        "unmapped": {"event_type": "benchmark"},
    }


def _auth_fields(user: str | None, host: str | None, successful: bool, *, source_ip: str | None = None, email: str | None = None) -> dict[str, Any]:
    actor_user = {"name": user} if user else {}
    if email:
        actor_user["email"] = email
    return {
        "class_uid": 3002,
        "class_name": "Authentication",
        "category_uid": 3,
        "category_name": "Identity & Access Management",
        "activity_id": 1 if successful else 2,
        "activity_name": "Logon" if successful else "Logon Failure",
        "type_uid": 300201 if successful else 300202,
        "type_name": "Authentication: Logon" if successful else "Authentication: Logon Failure",
        "actor": {"user": actor_user} if actor_user else None,
        "device": {"hostname": host} if host else None,
        "dst_endpoint": {"hostname": host} if host else None,
        "src_endpoint": {"ip": source_ip} if source_ip else None,
    }


def _network_fields(host: str, *, src_ip: str | None, dst_ip: str | None) -> dict[str, Any]:
    return {
        "class_uid": 4001,
        "class_name": "Network Activity",
        "category_uid": 4,
        "category_name": "Network Activity",
        "activity_id": 1,
        "activity_name": "Connection",
        "type_uid": 400101,
        "type_name": "Network Activity: Connection",
        "device": {"hostname": host},
        "src_endpoint": {"ip": src_ip} if src_ip else None,
        "dst_endpoint": {"ip": dst_ip} if dst_ip else None,
    }


def _dns_fields(host: str | None, domain: str, ip: str | None) -> dict[str, Any]:
    return {
        "class_uid": 4003,
        "class_name": "DNS Activity",
        "category_uid": 4,
        "category_name": "Network Activity",
        "activity_id": 1,
        "activity_name": "Query",
        "type_uid": 400301,
        "type_name": "DNS Activity: Query",
        "device": {"hostname": host} if host else None,
        "query": {"hostname": domain},
        "dst_endpoint": {"ip": ip} if ip else None,
    }


def _process_fields(
    process: str,
    *,
    host: str | None = None,
    user: str | None = None,
    file_hash: str | None = None,
    url: str | None = None,
    cloud_resource: str | None = None,
) -> dict[str, Any]:
    process_obj: dict[str, Any] = {"file": {"path": process, "name": Path(process).name}}
    if url:
        process_obj["cmd_line"] = f'"{process}" {url}'
    if file_hash:
        process_obj["file"]["hashes"] = [{"algorithm": "SHA256", "value": file_hash}]
    event = {
        "class_uid": 1007,
        "class_name": "Process Activity",
        "category_uid": 1,
        "category_name": "System Activity",
        "activity_id": 1,
        "activity_name": "Launch",
        "type_uid": 100701,
        "type_name": "Process Activity: Launch",
        "device": {"hostname": host} if host else None,
        "actor": {"user": {"name": user}, "process": process_obj} if user else {"process": process_obj},
        "process": process_obj,
    }
    if cloud_resource:
        event["resource"] = {"arn": cloud_resource, "provider": "aws", "service": "ec2", "type": "instance", "region": "us-east-1"}
    return event


def _finding_fields(*, email_from: str, email_to: str) -> dict[str, Any]:
    return {"email": {"from": email_from, "to": [email_to]}}


def _vulnerability_fields(host: str, cve: str) -> dict[str, Any]:
    return {
        "class_uid": 2002,
        "class_name": "Vulnerability Finding",
        "type_uid": 200201,
        "type_name": "Vulnerability Finding: Create",
        "device": {"hostname": host},
        "vulnerabilities": [{"cve": cve, "severity": "High", "status": "open"}],
    }


def _pick(values: list[str], index: int, salt: int) -> str:
    return values[(index * salt + index // max(1, len(values))) % len(values)]


def _hash_value(tenant_index: int, index: int, rng: random.Random) -> str:
    return f"{tenant_index:02x}{index:014x}{rng.getrandbits(192):048x}"[:64]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a reproducible large OCSF benchmark dataset.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--seed", type=int, default=424242)
    parser.add_argument("--tenants", type=int, default=2)
    parser.add_argument("--entity-target", type=int, default=12000)
    parser.add_argument("--relationship-target", type=int, default=1_000_000)
    return parser.parse_args()


if __name__ == "__main__":
    main()
