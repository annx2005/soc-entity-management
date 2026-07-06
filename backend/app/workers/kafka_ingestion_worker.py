from __future__ import annotations

import asyncio
import logging

from pydantic import ValidationError

from app.core.config import get_settings
from app.database.session import SessionLocal, init_db
from app.ingestion.kafka_client import KafkaJsonProducer
from app.ingestion.kafka_messages import RawEventMessage
from app.ingestion.kafka_service import process_raw_event_message
from app.observability.metrics import start_worker_metrics_server

logger = logging.getLogger(__name__)


async def run_worker() -> None:
    from aiokafka import AIOKafkaConsumer

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    init_db()
    start_worker_metrics_server()

    consumer = AIOKafkaConsumer(
        settings.kafka_raw_events_topic,
        bootstrap_servers=settings.kafka_bootstrap_servers,
        group_id=settings.kafka_ingestion_group_id,
        enable_auto_commit=False,
        auto_offset_reset="earliest",
    )
    producer = KafkaJsonProducer(settings.kafka_bootstrap_servers)

    await consumer.start()
    await producer.start()
    logger.info("Kafka ingestion worker started")
    try:
        async for kafka_message in consumer:
            try:
                raw_message = RawEventMessage.model_validate_json(kafka_message.value)
            except ValidationError:
                logger.exception("Invalid raw event envelope; committing offset after validation failure")
                await consumer.commit()
                continue

            with SessionLocal() as db:
                try:
                    await process_raw_event_message(db, raw_message, producer)
                except Exception:
                    db.rollback()
                    logger.exception("Failed to process Kafka message; offset was not committed")
                    raise
            await consumer.commit()
    finally:
        await producer.stop()
        await consumer.stop()


def main() -> None:
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
