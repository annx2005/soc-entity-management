from __future__ import annotations

import asyncio
import sys
from types import ModuleType, SimpleNamespace

import pytest

from app.ingestion.kafka_messages import OCSFEventMessage, RawEventMessage
from app.workers import kafka_graph_worker, kafka_ingestion_worker


class StopWorker(Exception):
    pass


class FakeKafkaMessage:
    def __init__(self, value: str) -> None:
        self.value = value


class FakeConsumer:
    created: list["FakeConsumer"] = []
    batches: list[dict[str, list[FakeKafkaMessage]]] = []

    def __init__(self, *args, **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs
        self.started = False
        self.stopped = False
        self.commits = 0
        FakeConsumer.created.append(self)

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True

    async def commit(self) -> None:
        self.commits += 1

    async def getmany(self, **kwargs):
        self.last_getmany_kwargs = kwargs
        if not FakeConsumer.batches:
            raise StopWorker
        return FakeConsumer.batches.pop(0)


class FakeProducer:
    created: list["FakeProducer"] = []

    def __init__(self, bootstrap_servers: str) -> None:
        self.bootstrap_servers = bootstrap_servers
        self.started = False
        self.stopped = False
        FakeProducer.created.append(self)

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True


class FakeSession:
    created: list["FakeSession"] = []

    def __init__(self) -> None:
        self.rollback_called = False
        self.entered = False
        self.exited = False
        FakeSession.created.append(self)

    def __enter__(self) -> "FakeSession":
        self.entered = True
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.exited = True

    def rollback(self) -> None:
        self.rollback_called = True


class FakeCache:
    created: list["FakeCache"] = []

    def __init__(self, redis_url: str) -> None:
        self.redis_url = redis_url
        self.closed = False
        FakeCache.created.append(self)

    async def close(self) -> None:
        self.closed = True


class FakeDriver:
    created: list["FakeDriver"] = []

    def __init__(self) -> None:
        self.closed = False
        FakeDriver.created.append(self)

    async def close(self) -> None:
        self.closed = True


def install_fake_aiokafka(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeConsumer.created = []
    FakeConsumer.batches = []
    module = ModuleType("aiokafka")
    module.AIOKafkaConsumer = FakeConsumer
    monkeypatch.setitem(sys.modules, "aiokafka", module)


def worker_settings() -> SimpleNamespace:
    return SimpleNamespace(
        kafka_bootstrap_servers="kafka:9092",
        kafka_raw_events_topic="soc.raw-events.v1",
        kafka_ocsf_events_topic="soc.ocsf-events.v1",
        kafka_ingestion_group_id="ingestion-workers",
        kafka_graph_group_id="graph-workers",
        ingestion_db_batch_size=50,
        graph_batch_size=25,
        graph_batch_max_wait_seconds=1.5,
        redis_url="redis://redis:6379/0",
        enrichment_cache_ttl_seconds=300,
        enrichment_enabled=True,
    )


def test_kafka_ingestion_worker_processes_valid_messages_and_commits_invalid_offsets(monkeypatch) -> None:
    install_fake_aiokafka(monkeypatch)
    FakeProducer.created = []
    FakeSession.created = []

    settings = worker_settings()
    raw_message = RawEventMessage(batch_id=1, source_name="events.jsonl", line_number=1, raw_line='{"ok":true}')
    FakeConsumer.batches = [
        {"partition-0": [FakeKafkaMessage("{bad json")]},
        {"partition-0": [FakeKafkaMessage(raw_message.model_dump_json())]},
    ]
    calls: dict[str, object] = {"init_db": 0, "metrics": 0, "processed": []}

    async def fake_process_raw_event_messages(db, raw_messages, producer) -> None:
        calls["processed"].append((db, raw_messages, producer))

    monkeypatch.setattr(kafka_ingestion_worker, "get_settings", lambda: settings)
    monkeypatch.setattr(kafka_ingestion_worker, "init_db", lambda: calls.__setitem__("init_db", calls["init_db"] + 1))
    monkeypatch.setattr(kafka_ingestion_worker, "start_worker_metrics_server", lambda: calls.__setitem__("metrics", calls["metrics"] + 1))
    monkeypatch.setattr(kafka_ingestion_worker, "KafkaJsonProducer", FakeProducer)
    monkeypatch.setattr(kafka_ingestion_worker, "SessionLocal", FakeSession)
    monkeypatch.setattr(kafka_ingestion_worker, "process_raw_event_messages", fake_process_raw_event_messages)

    with pytest.raises(StopWorker):
        asyncio.run(kafka_ingestion_worker.run_worker())

    consumer = FakeConsumer.created[0]
    producer = FakeProducer.created[0]
    session = FakeSession.created[0]
    processed = calls["processed"]

    assert calls["init_db"] == 1
    assert calls["metrics"] == 1
    assert consumer.kwargs["group_id"] == "ingestion-workers"
    assert consumer.last_getmany_kwargs == {"timeout_ms": 1500, "max_records": 50}
    assert consumer.started is True
    assert consumer.stopped is True
    assert consumer.commits == 2
    assert producer.bootstrap_servers == "kafka:9092"
    assert producer.started is True
    assert producer.stopped is True
    assert session.entered is True
    assert session.exited is True
    assert len(processed) == 1
    assert processed[0][0] is session
    assert processed[0][1][0].batch_id == 1
    assert processed[0][2] is producer


def test_kafka_ingestion_worker_rolls_back_and_does_not_commit_failed_batch(monkeypatch) -> None:
    install_fake_aiokafka(monkeypatch)
    FakeProducer.created = []
    FakeSession.created = []

    settings = worker_settings()
    raw_message = RawEventMessage(batch_id=1, source_name="events.jsonl", line_number=1, raw_line='{"ok":true}')
    FakeConsumer.batches = [{"partition-0": [FakeKafkaMessage(raw_message.model_dump_json())]}]
    calls = {"init_db": 0, "metrics": 0}

    async def fail_processing(db, raw_messages, producer) -> None:
        raise RuntimeError("db unavailable")

    monkeypatch.setattr(kafka_ingestion_worker, "get_settings", lambda: settings)
    monkeypatch.setattr(kafka_ingestion_worker, "init_db", lambda: calls.__setitem__("init_db", calls["init_db"] + 1))
    monkeypatch.setattr(kafka_ingestion_worker, "start_worker_metrics_server", lambda: calls.__setitem__("metrics", calls["metrics"] + 1))
    monkeypatch.setattr(kafka_ingestion_worker, "KafkaJsonProducer", FakeProducer)
    monkeypatch.setattr(kafka_ingestion_worker, "SessionLocal", FakeSession)
    monkeypatch.setattr(kafka_ingestion_worker, "process_raw_event_messages", fail_processing)

    with pytest.raises(RuntimeError, match="db unavailable"):
        asyncio.run(kafka_ingestion_worker.run_worker())

    assert FakeSession.created[0].rollback_called is True
    assert FakeConsumer.created[0].commits == 0
    assert FakeProducer.created[0].stopped is True
    assert FakeConsumer.created[0].stopped is True


def test_kafka_graph_worker_processes_messages_and_cleans_up_resources(monkeypatch) -> None:
    install_fake_aiokafka(monkeypatch)
    FakeCache.created = []
    FakeDriver.created = []

    settings = worker_settings()
    message = OCSFEventMessage(
        source_message_id="raw-1",
        batch_id=1,
        event_id="evt-1",
        tenant_id="tenant-a",
        class_uid=4001,
        class_name="Network Activity",
        activity_id=1,
        activity_name="Open",
        ocsf_event={"tenant_id": "tenant-a"},
    )
    FakeConsumer.batches = [
        {"partition-0": [FakeKafkaMessage("{bad json")]},
        {"partition-0": [FakeKafkaMessage(message.model_dump_json())]},
    ]
    provider = object()
    closed_providers: list[object] = []
    processed: list[tuple[list[OCSFEventMessage], object]] = []
    calls: dict[str, int] = {"init_db": 0, "metrics": 0}

    async def fake_process_ocsf_event_messages(messages, graph) -> None:
        processed.append((messages, graph))

    async def fake_close_provider(closed_provider) -> None:
        closed_providers.append(closed_provider)

    monkeypatch.setattr(kafka_graph_worker, "get_settings", lambda: settings)
    monkeypatch.setattr(kafka_graph_worker, "init_db", lambda: calls.__setitem__("init_db", calls["init_db"] + 1))
    monkeypatch.setattr(kafka_graph_worker, "start_worker_metrics_server", lambda: calls.__setitem__("metrics", calls["metrics"] + 1))
    monkeypatch.setattr(kafka_graph_worker, "create_graph_driver", FakeDriver)
    monkeypatch.setattr(kafka_graph_worker, "RedisEnrichmentCache", FakeCache)
    monkeypatch.setattr(kafka_graph_worker, "make_enrichment_provider", lambda: provider)
    monkeypatch.setattr(kafka_graph_worker, "close_enrichment_provider", fake_close_provider)
    monkeypatch.setattr(kafka_graph_worker, "process_ocsf_event_messages", fake_process_ocsf_event_messages)

    with pytest.raises(StopWorker):
        asyncio.run(kafka_graph_worker.run_worker())

    consumer = FakeConsumer.created[0]
    assert calls["init_db"] == 1
    assert calls["metrics"] == 1
    assert consumer.kwargs["group_id"] == "graph-workers"
    assert consumer.last_getmany_kwargs == {"timeout_ms": 1500, "max_records": 25}
    assert consumer.started is True
    assert consumer.stopped is True
    assert consumer.commits == 2
    assert len(processed) == 1
    assert processed[0][0][0].event_id == "evt-1"
    assert closed_providers == [provider]
    assert FakeCache.created[0].redis_url == "redis://redis:6379/0"
    assert FakeCache.created[0].closed is True
    assert FakeDriver.created[0].closed is True


def test_kafka_graph_worker_does_not_commit_failed_batch(monkeypatch) -> None:
    install_fake_aiokafka(monkeypatch)
    FakeCache.created = []
    FakeDriver.created = []

    settings = worker_settings()
    message = OCSFEventMessage(
        source_message_id="raw-1",
        batch_id=1,
        event_id="evt-1",
        tenant_id="tenant-a",
        class_uid=4001,
        class_name="Network Activity",
        activity_id=1,
        activity_name="Open",
        ocsf_event={"tenant_id": "tenant-a"},
    )
    FakeConsumer.batches = [{"partition-0": [FakeKafkaMessage(message.model_dump_json())]}]
    provider = object()

    async def fail_processing(messages, graph) -> None:
        raise RuntimeError("neo4j unavailable")

    async def fake_close_provider(closed_provider) -> None:
        assert closed_provider is provider

    monkeypatch.setattr(kafka_graph_worker, "get_settings", lambda: settings)
    monkeypatch.setattr(kafka_graph_worker, "init_db", lambda: None)
    monkeypatch.setattr(kafka_graph_worker, "start_worker_metrics_server", lambda: None)
    monkeypatch.setattr(kafka_graph_worker, "create_graph_driver", FakeDriver)
    monkeypatch.setattr(kafka_graph_worker, "RedisEnrichmentCache", FakeCache)
    monkeypatch.setattr(kafka_graph_worker, "make_enrichment_provider", lambda: provider)
    monkeypatch.setattr(kafka_graph_worker, "close_enrichment_provider", fake_close_provider)
    monkeypatch.setattr(kafka_graph_worker, "process_ocsf_event_messages", fail_processing)

    with pytest.raises(RuntimeError, match="neo4j unavailable"):
        asyncio.run(kafka_graph_worker.run_worker())

    assert FakeConsumer.created[0].commits == 0
    assert FakeConsumer.created[0].stopped is True
    assert FakeCache.created[0].closed is True
    assert FakeDriver.created[0].closed is True


@pytest.mark.parametrize("worker_module", [kafka_graph_worker, kafka_ingestion_worker])
def test_worker_main_delegates_to_async_runner(monkeypatch, worker_module) -> None:
    worker_coro = object()
    calls: list[object] = []

    monkeypatch.setattr(worker_module, "run_worker", lambda: worker_coro)
    monkeypatch.setattr(worker_module.asyncio, "run", lambda coro: calls.append(coro))

    worker_module.main()

    assert calls == [worker_coro]
