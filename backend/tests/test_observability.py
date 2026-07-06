from __future__ import annotations

from fastapi.testclient import TestClient
from prometheus_client import CollectorRegistry, generate_latest

from app.main import app
from app.observability.metrics import EntityCount, EntityCountCollector


def test_metrics_endpoint_returns_prometheus_text_without_auth() -> None:
    with TestClient(app) as client:
        response = client.get("/metrics")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "# HELP" in response.text


def test_entity_count_collector_exports_tenant_and_type_labels() -> None:
    registry = CollectorRegistry()
    registry.register(
        EntityCountCollector(
            lambda: [
                EntityCount(tenant_id="tenant-a", entity_type="ip", count=2),
                EntityCount(tenant_id="tenant-a", entity_type="host", count=1),
            ]
        )
    )

    output = generate_latest(registry).decode("utf-8")

    assert "soc_entities_total" in output
    assert 'tenant_id="tenant-a"' in output
    assert 'entity_type="ip"' in output
    assert 'entity_type="host"' in output
