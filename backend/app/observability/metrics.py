from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, REGISTRY, start_http_server
from prometheus_client.core import GaugeMetricFamily

from app.core.config import get_settings

logger = logging.getLogger(__name__)


GRAPH_EVENTS_PROCESSED = Counter(
    "soc_graph_events_processed_total",
    "OCSF events processed by the graph worker.",
    ("tenant_id", "status"),
)
GRAPH_ENTITIES_UPSERTED = Counter(
    "soc_graph_entities_upserted_total",
    "Graph entities upserted by tenant, type, and status.",
    ("tenant_id", "entity_type", "status"),
)
GRAPH_RELATIONSHIPS_UPSERTED = Counter(
    "soc_graph_relationships_upserted_total",
    "Graph relationships upserted by tenant, relationship type, and status.",
    ("tenant_id", "relationship_type", "status"),
)
ENRICHMENT_LOOKUP_DURATION = Histogram(
    "soc_enrichment_lookup_duration_seconds",
    "Latency for enrichment lookup attempts.",
    ("entity_type", "cache_status", "outcome"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)
ENRICHMENT_REQUESTS = Counter(
    "soc_enrichment_requests_total",
    "Enrichment lookup attempts by entity type, cache status, and outcome.",
    ("entity_type", "cache_status", "outcome"),
)

_entity_collector_registered = False
_worker_metrics_started = False


@dataclass(frozen=True)
class EntityCount:
    tenant_id: str
    entity_type: str
    count: int


class EntityCountCollector:
    """Scrape-time entity count collector backed by Neo4j."""

    def __init__(self, fetch_counts: Callable[[], Iterable[EntityCount]] | None = None) -> None:
        self._fetch_counts = fetch_counts or fetch_entity_counts

    def collect(self):
        metric = GaugeMetricFamily(
            "soc_entities_total",
            "Current graph entity count by tenant and entity type.",
            labels=("tenant_id", "entity_type"),
        )
        for item in self._fetch_counts():
            metric.add_metric((item.tenant_id, item.entity_type), item.count)
        yield metric


def fetch_entity_counts() -> list[EntityCount]:
    from neo4j import GraphDatabase

    settings = get_settings()
    query = """
    MATCH (entity:Entity)
    RETURN entity.tenant_id AS tenant_id, entity.entity_type AS entity_type, count(entity) AS count
    ORDER BY tenant_id, entity_type
    """
    try:
        driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password))
        try:
            with driver.session() as session:
                result = session.run(query)
                return [
                    EntityCount(
                        tenant_id=str(record["tenant_id"] or "unknown"),
                        entity_type=str(record["entity_type"] or "unknown"),
                        count=int(record["count"] or 0),
                    )
                    for record in result
                ]
        finally:
            driver.close()
    except Exception:
        logger.exception("Failed to collect entity count metrics")
        return []


def register_entity_count_collector(registry: CollectorRegistry = REGISTRY) -> None:
    global _entity_collector_registered
    if _entity_collector_registered:
        return
    registry.register(EntityCountCollector())
    _entity_collector_registered = True


def start_worker_metrics_server() -> None:
    global _worker_metrics_started
    settings = get_settings()
    if not settings.metrics_enabled or _worker_metrics_started:
        return
    start_http_server(settings.metrics_port)
    _worker_metrics_started = True
    logger.info("Prometheus worker metrics server started on port %s", settings.metrics_port)


def record_graph_event(tenant_id: str, status: str) -> None:
    GRAPH_EVENTS_PROCESSED.labels(tenant_id=tenant_id, status=status).inc()


def record_entity_upsert(tenant_id: str, entity_type: str, status: str) -> None:
    GRAPH_ENTITIES_UPSERTED.labels(tenant_id=tenant_id, entity_type=entity_type, status=status).inc()


def record_relationship_upsert(tenant_id: str, relationship_type: str, status: str) -> None:
    GRAPH_RELATIONSHIPS_UPSERTED.labels(tenant_id=tenant_id, relationship_type=relationship_type, status=status).inc()


def record_enrichment_lookup(entity_type: str, cache_status: str, outcome: str, duration_seconds: float) -> None:
    ENRICHMENT_REQUESTS.labels(entity_type=entity_type, cache_status=cache_status, outcome=outcome).inc()
    ENRICHMENT_LOOKUP_DURATION.labels(entity_type=entity_type, cache_status=cache_status, outcome=outcome).observe(duration_seconds)
