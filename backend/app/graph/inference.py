from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from app.entities.schemas import Entity, EntityType
from app.graph.constants import validate_relationship_type
from app.graph.schemas import RelationshipCandidate
from app.ocsf.schemas import OCSFEvent


def infer_relationships(event: OCSFEvent, entities: list[Entity]) -> list[RelationshipCandidate]:
    candidates: list[RelationshipCandidate] = []
    observed_at = _event_time_from_entities(event, entities)

    def add(relationship_type: str, from_entity: Entity | None, to_entity: Entity | None) -> None:
        if from_entity is None or to_entity is None:
            return
        candidates.append(
            RelationshipCandidate(
                relationship_type=validate_relationship_type(relationship_type),
                from_id=from_entity.id,
                to_id=to_entity.id,
                evidence_ref=event.event_id,
                observed_at=observed_at,
            )
        )

    if event.class_uid == 3002:
        user = _first_by_type(entities, EntityType.USER, "actor.user.name")
        host = _first_by_type(entities, EntityType.HOST, "device.hostname") or _first_by_type(
            entities, EntityType.HOST, "dst_endpoint.hostname"
        )
        source_ip = _first_by_type(entities, EntityType.IP, "src_endpoint.ip")
        successful_auth = _is_successful_auth(event)
        user_relationship_type = "LOGGED_IN_TO" if successful_auth else "FAILED_LOGON_TO"
        ip_relationship_type = "AUTHENTICATED_TO" if successful_auth else "ATTEMPTED_LOGON_TO"
        add(user_relationship_type, user, host)
        add(ip_relationship_type, source_ip, host)
        _add_user_email_relationships(add, user, entities)

    elif event.class_uid == 4001:
        host = _first_by_type(entities, EntityType.HOST, "device.hostname")
        for ip_entity in _by_type_and_field(entities, EntityType.IP, "src_endpoint.ip"):
            add("USED_IP", host, ip_entity)
        for ip_entity in _by_type_and_field(entities, EntityType.IP, "dst_endpoint.ip"):
            add("CONNECTED_TO", host, ip_entity)

    elif event.class_uid == 4003:
        host = _first_by_type(entities, EntityType.HOST, "device.hostname")
        domain = _first_by_type(entities, EntityType.DOMAIN, "query.hostname")
        add("RESOLVED_DOMAIN", host, domain)
        for ip_entity in _by_type_and_field(entities, EntityType.IP, "dst_endpoint.ip"):
            add("RESOLVED_TO", domain, ip_entity)

    elif event.class_uid == 1007:
        process = _first_by_type(entities, EntityType.PROCESS, "process") or _first_by_type(
            entities, EntityType.PROCESS, "actor.process"
        )
        host = _first_by_type(entities, EntityType.HOST, "device.hostname")
        user = _first_by_type(entities, EntityType.USER, "actor.user.name")
        add("EXECUTED_ON", process, host)
        add("RAN_AS", process, user)
        for file_hash in _by_type(entities, EntityType.FILE_HASH):
            add("HAS_HASH", process, file_hash)
        for url in _by_type(entities, EntityType.URL):
            add("PROCESS_ACCESSED_URL", process, url)
        _add_user_email_relationships(add, user, entities)

    elif event.class_uid in {2001, 2002}:
        host = _first_by_type(entities, EntityType.HOST, "device.hostname")
        for cve in _by_type(entities, EntityType.CVE):
            add("AFFECTED_BY_CVE", host, cve)

    if _by_type(entities, EntityType.EMAIL):
        sender = _first_by_type(entities, EntityType.EMAIL, "email.from") or _first_by_type(entities, EntityType.EMAIL, "email.sender")
        recipients = _by_type_and_field(entities, EntityType.EMAIL, "email.to") + _by_type_and_field(entities, EntityType.EMAIL, "email.recipients")
        for recipient in recipients:
            add("EMAIL_SENT_TO", sender, recipient)

    return _dedupe_candidates(candidates)


def group_entities_by_type(entities: Iterable[Entity]) -> dict[EntityType, list[Entity]]:
    grouped: dict[EntityType, list[Entity]] = defaultdict(list)
    for entity in entities:
        grouped[entity.type].append(entity)
    return dict(grouped)


def _is_successful_auth(event: OCSFEvent) -> bool:
    if event.activity_name.lower() == "logon":
        return True
    if event.event_type == "windows_logon_success":
        return True
    return event.activity_id == 1 and "failure" not in event.activity_name.lower()


def _event_time_from_entities(event: OCSFEvent, entities: list[Entity]) -> str:
    if entities:
        return entities[0].first_seen
    from datetime import datetime, timezone

    return datetime.fromtimestamp(event.time / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _source_field(entity: Entity) -> str | None:
    value = entity.properties.get("source_field")
    return str(value) if value else None


def _by_type(entities: Iterable[Entity], entity_type: EntityType) -> list[Entity]:
    return [entity for entity in entities if entity.type == entity_type]


def _by_type_and_field(entities: Iterable[Entity], entity_type: EntityType, source_field: str) -> list[Entity]:
    return [entity for entity in entities if entity.type == entity_type and _source_field(entity) == source_field]


def _first_by_type(entities: Iterable[Entity], entity_type: EntityType, source_field: str) -> Entity | None:
    matches = _by_type_and_field(entities, entity_type, source_field)
    return matches[0] if matches else None


def _add_user_email_relationships(add, user: Entity | None, entities: Iterable[Entity]) -> None:
    if user is None:
        return
    for email in _by_type(entities, EntityType.EMAIL):
        add("USER_HAS_EMAIL", user, email)


def _dedupe_candidates(candidates: list[RelationshipCandidate]) -> list[RelationshipCandidate]:
    seen: set[tuple[str, str, str, str]] = set()
    deduped: list[RelationshipCandidate] = []
    for candidate in candidates:
        key = (candidate.relationship_type, candidate.from_id, candidate.to_id, candidate.evidence_ref)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped
