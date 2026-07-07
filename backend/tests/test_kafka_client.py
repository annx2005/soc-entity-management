from __future__ import annotations

import asyncio
import json
import sys
from types import ModuleType

import pytest
from pydantic import BaseModel

from app.ingestion.kafka_client import KafkaJsonProducer


class Payload(BaseModel):
    event_id: str


def test_kafka_json_producer_start_stop_and_send(monkeypatch) -> None:
    class FakeAIOKafkaProducer:
        def __init__(self, bootstrap_servers: str) -> None:
            self.bootstrap_servers = bootstrap_servers
            self.started = False
            self.stopped = False
            self.sent: list[dict] = []

        async def start(self) -> None:
            self.started = True

        async def stop(self) -> None:
            self.stopped = True

        async def send_and_wait(self, topic: str, **kwargs) -> None:
            self.sent.append({"topic": topic, **kwargs})

    module = ModuleType("aiokafka")
    module.AIOKafkaProducer = FakeAIOKafkaProducer
    monkeypatch.setitem(sys.modules, "aiokafka", module)

    async def run() -> FakeAIOKafkaProducer:
        producer = KafkaJsonProducer("kafka:9092")
        await producer.start()
        fake = producer._producer
        await producer.send("topic-a", Payload(event_id="evt-1"), key="key-a", headers={"tenant": "a"})
        await producer.send("topic-b", {"created_at": object()})
        await producer.stop()
        return fake

    fake = asyncio.run(run())

    assert fake.bootstrap_servers == "kafka:9092"
    assert fake.started is True
    assert fake.stopped is True
    assert fake.sent[0]["topic"] == "topic-a"
    assert json.loads(fake.sent[0]["value"]) == {"event_id": "evt-1"}
    assert fake.sent[0]["key"] == b"key-a"
    assert fake.sent[0]["headers"] == [(b"tenant".decode("utf-8"), b"a")]
    assert json.loads(fake.sent[1]["value"])["created_at"].startswith("<object object")


def test_kafka_json_producer_requires_start() -> None:
    async def run() -> None:
        producer = KafkaJsonProducer("kafka:9092")
        with pytest.raises(RuntimeError, match="not started"):
            await producer.send("topic", {})

    asyncio.run(run())
