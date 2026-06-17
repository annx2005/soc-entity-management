from __future__ import annotations

import asyncio
import logging

from pydantic import ValidationError

from app.core.config import get_settings
from app.database.session import init_db
from app.graph.kafka_service import process_ocsf_event_message
from app.graph.repository import GraphRepository, create_graph_driver
from app.graph.service import GraphService
from app.ingestion.kafka_messages import OCSFEventMessage

logger = logging.getLogger(__name__)


async def run_worker() -> None:
    from aiokafka import AIOKafkaConsumer

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    init_db()

    consumer = AIOKafkaConsumer(
        settings.kafka_ocsf_events_topic,
        bootstrap_servers=settings.kafka_bootstrap_servers,
        group_id=settings.kafka_graph_group_id,
        enable_auto_commit=False,
        auto_offset_reset="earliest",
    )
    driver = create_graph_driver()
    graph = GraphService(GraphRepository(driver))

    await consumer.start()
    logger.info("Kafka graph worker started")
    try:
        async for kafka_message in consumer:
            try:
                message = OCSFEventMessage.model_validate_json(kafka_message.value)
            except ValidationError:
                logger.exception("Invalid OCSF event envelope; committing offset after validation failure")
                await consumer.commit()
                continue

            try:
                await process_ocsf_event_message(message, graph)
            except Exception:
                logger.exception("Failed to process OCSF event; offset was not committed")
                raise
            await consumer.commit()
    finally:
        await driver.close()
        await consumer.stop()


def main() -> None:
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
