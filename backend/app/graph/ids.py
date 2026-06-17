from __future__ import annotations

import hashlib


def stable_hash(*parts: object) -> str:
    key = ":".join(str(part) for part in parts)
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def graph_event_id(tenant_id: str, event_id: str) -> str:
    return stable_hash(tenant_id, event_id)


def observation_id(tenant_id: str, event_id: str, entity_id: str, field_path: str) -> str:
    return stable_hash(tenant_id, event_id, entity_id, field_path)


def relationship_fact_id(tenant_id: str, relationship_type: str, from_id: str, to_id: str) -> str:
    return stable_hash(tenant_id, relationship_type, from_id, to_id)
