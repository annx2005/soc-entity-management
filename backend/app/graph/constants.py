from __future__ import annotations

from app.entities.schemas import EntityType


LABEL_BY_ENTITY_TYPE: dict[EntityType, str] = {
    EntityType.USER: "User",
    EntityType.HOST: "Host",
    EntityType.IP: "IP",
    EntityType.DOMAIN: "Domain",
    EntityType.FILE_HASH: "FileHash",
    EntityType.PROCESS: "Process",
}

ALLOWED_RELATIONSHIP_TYPES = {
    "LOGGED_IN_TO",
    "FAILED_LOGON_TO",
    "CONNECTED_TO",
    "USED_IP",
    "RESOLVED_DOMAIN",
    "RESOLVED_TO",
    "EXECUTED_ON",
    "HAS_HASH",
    "RAN_AS",
}


def label_for_entity_type(entity_type: EntityType) -> str:
    try:
        return LABEL_BY_ENTITY_TYPE[entity_type]
    except KeyError as exc:
        raise ValueError(f"unsupported entity type: {entity_type}") from exc


def validate_relationship_type(relationship_type: str) -> str:
    if relationship_type not in ALLOWED_RELATIONSHIP_TYPES:
        raise ValueError(f"unsupported relationship type: {relationship_type}")
    return relationship_type
