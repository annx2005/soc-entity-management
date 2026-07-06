from __future__ import annotations

import asyncio
import logging

from pydantic import ValidationError

from app.core.config import get_settings
from app.audit.service import AuditLogger
from app.database.session import init_db
from app.database.session import SessionLocal
from app.enrichment.cache import RedisEnrichmentCache
from app.enrichment.dependencies import close_enrichment_provider, make_enrichment_provider
from app.enrichment.service import EnrichmentService
from app.graph.kafka_service import process_ocsf_event_messages
from app.graph.repository import GraphRepository, create_graph_driver
from app.graph.service import GraphService
from app.ingestion.kafka_messages import OCSFEventMessage
from app.observability.metrics import start_worker_metrics_server

logger = logging.getLogger(__name__)


async def run_worker() -> None:
    from aiokafka import AIOKafkaConsumer

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    init_db()
    start_worker_metrics_server()

    consumer = AIOKafkaConsumer(
        settings.kafka_ocsf_events_topic,
        bootstrap_servers=settings.kafka_bootstrap_servers,
        group_id=settings.kafka_graph_group_id,
        enable_auto_commit=False,
        auto_offset_reset="earliest",
    )
    driver = create_graph_driver()
    cache = RedisEnrichmentCache(settings.redis_url)
    provider = make_enrichment_provider()
    enrichment = EnrichmentService(
        provider,
        cache=cache,
        ttl_seconds=settings.enrichment_cache_ttl_seconds,
        enabled=settings.enrichment_enabled,
    )
    graph = GraphService(GraphRepository(driver), enrichment_service=enrichment, audit_logger=AuditLogger(SessionLocal))

    await consumer.start()
    logger.info("Kafka graph worker started")
    try:
        while True:
            batches = await consumer.getmany(
                timeout_ms=int(settings.graph_batch_max_wait_seconds * 1000),
                max_records=settings.graph_batch_size,
            )
            messages: list[OCSFEventMessage] = []
            for partition_messages in batches.values():
                for kafka_message in partition_messages:
                    try:
                        messages.append(OCSFEventMessage.model_validate_json(kafka_message.value))
                    except ValidationError:
                        logger.exception("Invalid OCSF event envelope; committing offset after validation failure")
            if not messages:
                if batches:
                    await consumer.commit()
                continue

            try:
                await process_ocsf_event_messages(messages, graph)
            except Exception:
                logger.exception("Failed to process OCSF event batch; offsets were not committed")
                raise
            await consumer.commit()
    finally:
        await close_enrichment_provider(provider)
        await cache.close()
        await driver.close()
        await consumer.stop()


def main() -> None:
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
