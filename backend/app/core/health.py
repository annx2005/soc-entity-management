from __future__ import annotations

import socket

from neo4j import GraphDatabase
from redis import Redis
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import get_settings


def check_postgres(db: Session) -> dict[str, str]:
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok"}
    except Exception as exc:  # pragma: no cover - exact driver errors vary by environment
        return {"status": "error", "message": str(exc)}


def check_redis() -> dict[str, str]:
    try:
        client = Redis.from_url(get_settings().redis_url, socket_connect_timeout=1)
        client.ping()
        client.close()
        return {"status": "ok"}
    except Exception as exc:  # pragma: no cover
        return {"status": "error", "message": str(exc)}


def check_neo4j() -> dict[str, str]:
    settings = get_settings()
    try:
        driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password))
        driver.verify_connectivity()
        driver.close()
        return {"status": "ok"}
    except Exception as exc:  # pragma: no cover
        return {"status": "error", "message": str(exc)}


def check_kafka() -> dict[str, str]:
    try:
        host, port = _first_kafka_endpoint()
        with socket.create_connection((host, port), timeout=1):
            return {"status": "ok"}
    except Exception as exc:  # pragma: no cover
        return {"status": "error", "message": str(exc)}


def _first_kafka_endpoint() -> tuple[str, int]:
    endpoint = get_settings().kafka_bootstrap_servers.split(",")[0].strip()
    host, port = endpoint.rsplit(":", 1)
    return host, int(port)
