from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Optional

from pydantic import BaseModel

from app.core.config import get_settings


class KafkaJsonProducer:
    def __init__(self, bootstrap_servers: Optional[str] = None) -> None:
        self.bootstrap_servers = bootstrap_servers or get_settings().kafka_bootstrap_servers
        self._producer: Any = None

    async def start(self) -> None:
        from aiokafka import AIOKafkaProducer

        self._producer = AIOKafkaProducer(bootstrap_servers=self.bootstrap_servers)
        await self._producer.start()

    async def stop(self) -> None:
        if self._producer is not None:
            await self._producer.stop()
            self._producer = None

    async def send(
        self,
        topic: str,
        payload: BaseModel | Mapping[str, Any],
        key: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> None:
        if self._producer is None:
            raise RuntimeError("Kafka producer is not started")

        if isinstance(payload, BaseModel):
            value = payload.model_dump_json().encode("utf-8")
        else:
            value = json.dumps(payload, default=str, separators=(",", ":")).encode("utf-8")

        kafka_headers = [(name, header_value.encode("utf-8")) for name, header_value in (headers or {}).items()]
        await self._producer.send_and_wait(
            topic,
            value=value,
            key=key.encode("utf-8") if key else None,
            headers=kafka_headers,
        )
