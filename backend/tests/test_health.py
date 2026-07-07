from __future__ import annotations

from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core import health


def test_health_checks_success_paths(monkeypatch) -> None:
    closed = {"redis": False, "neo4j": False}

    class FakeRedis:
        def ping(self) -> None:
            pass

        def close(self) -> None:
            closed["redis"] = True

    class FakeDriver:
        def verify_connectivity(self) -> None:
            pass

        def close(self) -> None:
            closed["neo4j"] = True

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

    monkeypatch.setattr(health.Redis, "from_url", lambda url, socket_connect_timeout: FakeRedis())
    monkeypatch.setattr(health.GraphDatabase, "driver", lambda uri, auth: FakeDriver())
    monkeypatch.setattr(health.socket, "create_connection", lambda endpoint, timeout: FakeSocket())
    monkeypatch.setattr(
        health,
        "get_settings",
        lambda: SimpleNamespace(
            redis_url="redis://example/0",
            neo4j_uri="bolt://neo4j:7687",
            neo4j_user="neo4j",
            neo4j_password="password",
            kafka_bootstrap_servers="kafka:9092,backup:9092",
        ),
    )

    engine = create_engine("sqlite:///:memory:")
    with Session(engine) as db:
        assert health.check_postgres(db) == {"status": "ok"}

    assert health.check_redis() == {"status": "ok"}
    assert health.check_neo4j() == {"status": "ok"}
    assert health.check_kafka() == {"status": "ok"}
    assert health._first_kafka_endpoint() == ("kafka", 9092)
    assert closed == {"redis": True, "neo4j": True}
