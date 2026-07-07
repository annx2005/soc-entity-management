from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import math
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
                "tenant_outputs": manifest.get("tenant_outputs", {}),
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
    tenants: int = 1,
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
    tenant_output_paths = _tenant_output_paths(output_path, tenant_ids)

    entity_keys = {(tenant_id, entity_type, value) for tenant_id, by_type in pools.items() for entity_type, values in by_type.items() for value in values}
    relationship_keys: set[tuple[str, str, str, str]] = set()
    entity_counts = Counter({entity_type: 0 for entity_type in ENTITY_TYPES})
    relationship_counts = Counter({relationship_type: 0 for relationship_type in RELATIONSHIP_TYPES})
    for _, entity_type, _ in entity_keys:
        entity_counts[entity_type] += 1

    base_time = datetime(2026, 7, 7, tzinfo=timezone.utc)
    relationship_target_by_tenant = _allocate_targets(
        relationship_target,
        tenant_ids,
        {tenant_id: _tenant_relationship_capacity(pools[tenant_id]) for tenant_id in tenant_ids},
    )
    relationship_target_by_tenant_type = {
        tenant_id: _allocate_targets(
            relationship_target_by_tenant[tenant_id],
            list(RELATIONSHIP_TYPES),
            {
                relationship_type: _relationship_type_capacity(pools[tenant_id], relationship_type)
                for relationship_type in RELATIONSHIP_TYPES
            },
        )
        for tenant_id in tenant_ids
    }
    event_index = 0
    tenant_event_counts = {tenant_id: 0 for tenant_id in tenant_ids}
    with ExitStack() as stack:
        combined_stream = stack.enter_context(output_path.open("w", encoding="utf-8"))
        tenant_streams = {
            tenant_id: combined_stream
            if tenant_output_paths[tenant_id] == output_path
            else stack.enter_context(tenant_output_paths[tenant_id].open("w", encoding="utf-8"))
            for tenant_id in tenant_ids
        }
        for tenant_id in tenant_ids:
            for relationship_type in RELATIONSHIP_TYPES:
                target_count = relationship_target_by_tenant_type[tenant_id][relationship_type]
                if target_count == 0:
                    continue
                source_type, target_type = _relationship_entity_types(relationship_type)
                pairs = _unique_relationship_pairs(
                    pools[tenant_id][source_type],
                    pools[tenant_id][target_type],
                    count=target_count,
                    same_pool=source_type == target_type,
                    seed=seed + _stable_seed_offset(tenant_id, relationship_type),
                )
                for source, target in pairs:
                    key = (tenant_id, relationship_type, f"{source_type}:{source}", f"{target_type}:{target}")
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
                    line = json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
                    combined_stream.write(line)
                    if tenant_streams[tenant_id] is not combined_stream:
                        tenant_streams[tenant_id].write(line)
                    event_index += 1
                    tenant_event_counts[tenant_id] += 1

    manifest = {
        "seed": seed,
        "tenants": tenant_ids,
        "output": str(output_path),
        "tenant_outputs": {tenant_id: str(path) for tenant_id, path in tenant_output_paths.items()},
        "tenant_event_counts": tenant_event_counts,
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
        }
    return pools


def _relationship_capacity(pools: dict[str, dict[str, list[str]]]) -> int:
    return sum(_tenant_relationship_capacity(by_type) for by_type in pools.values())


def _tenant_relationship_capacity(by_type: dict[str, list[str]]) -> int:
    return sum(_relationship_type_capacity(by_type, relationship_type) for relationship_type in RELATIONSHIP_TYPES)


def _relationship_type_capacity(by_type: dict[str, list[str]], relationship_type: str) -> int:
    source_type, target_type = _relationship_entity_types(relationship_type)
    source_count = len(by_type[source_type])
    target_count = len(by_type[target_type])
    if source_type == target_type:
        return source_count * max(target_count - 1, 0)
    return source_count * target_count


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


def _stable_seed_offset(*parts: str) -> int:
    return sum((index + 1) * sum(ord(char) for char in part) for index, part in enumerate(parts))


def _tenant_output_paths(output_path: Path, tenant_ids: list[str]) -> dict[str, Path]:
    if len(tenant_ids) == 1:
        return {tenant_ids[0]: output_path}
    return {
        tenant_id: output_path.with_name(f"{output_path.stem}-{tenant_id}{output_path.suffix}")
        for tenant_id in tenant_ids
    }


def _allocate_targets(total: int, keys: list[str], capacities: dict[str, int]) -> dict[str, int]:
    if total < 0:
        raise ValueError("target must be >= 0")
    if total > sum(capacities[key] for key in keys):
        raise ValueError(f"target {total} exceeds available capacity {sum(capacities[key] for key in keys)}")
    if not keys:
        return {}

    targets = {key: 0 for key in keys}
    remaining = total
    while remaining > 0:
        progressed = False
        for key in keys:
            if remaining == 0:
                break
            if targets[key] >= capacities[key]:
                continue
            targets[key] += 1
            remaining -= 1
            progressed = True
        if not progressed:
            break
    return targets


def _unique_relationship_pairs(
    sources: list[str],
    targets: list[str],
    *,
    count: int,
    same_pool: bool,
    seed: int,
) -> list[tuple[str, str]]:
    if count == 0:
        return []
    if same_pool:
        capacity = len(sources) * max(len(sources) - 1, 0)
        if count > capacity:
            raise ValueError(f"relationship target {count} exceeds same-pool capacity {capacity}")
        return _unique_same_pool_pairs(sources, count, seed)

    capacity = len(sources) * len(targets)
    if count > capacity:
        raise ValueError(f"relationship target {count} exceeds pair capacity {capacity}")
    step = _coprime_step(capacity, seed)
    start = seed % capacity
    pairs: list[tuple[str, str]] = []
    for ordinal in range(count):
        flat_index = (start + (ordinal * step)) % capacity
        source_index = flat_index // len(targets)
        target_index = flat_index % len(targets)
        pairs.append((sources[source_index], targets[target_index]))
    return pairs


def _unique_same_pool_pairs(values: list[str], count: int, seed: int) -> list[tuple[str, str]]:
    size = len(values)
    if size < 2:
        raise ValueError("same-pool relationships require at least 2 values")
    offset_step = _coprime_step(size - 1, seed + size)
    source_step = _coprime_step(size, seed + (size * 3))
    start = seed % size
    pairs: list[tuple[str, str]] = []
    for ordinal in range(count):
        source_index = (start + (ordinal * source_step)) % size
        offset = 1 + (((ordinal // size) * offset_step) % (size - 1))
        target_index = (source_index + offset) % size
        pairs.append((values[source_index], values[target_index]))
    return pairs


def _coprime_step(modulus: int, seed: int) -> int:
    if modulus <= 1:
        return 1
    candidate = max(1, seed % modulus)
    while math.gcd(candidate, modulus) != 1:
        candidate += 1
        if candidate >= modulus:
            candidate = 1
    return candidate


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a reproducible large OCSF benchmark dataset.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--seed", type=int, default=424242)
    parser.add_argument("--tenants", type=int, default=1)
    parser.add_argument("--entity-target", type=int, default=12000)
    parser.add_argument("--relationship-target", type=int, default=1_000_000)
    return parser.parse_args()


if __name__ == "__main__":
    main()
