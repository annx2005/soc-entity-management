from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    args = _parse_args()
    if args.mode == "normalize-only":
        _run_normalize_only(args.input)
    elif args.mode == "graph-batch":
        asyncio.run(_run_graph_batch(args.input, args.batch_size))
    elif args.mode == "kafka-end-to-end":
        asyncio.run(_run_kafka_end_to_end(args.input))


def _run_normalize_only(path: Path) -> None:
    import sys

    sys.path.insert(0, str(ROOT / "backend"))
    from app.entities.extractor import extract_entities
    from app.graph.inference import infer_relationships
    from app.normalization.normalizer import normalize_event

    started = time.perf_counter()
    events = errors = entity_count = relationship_count = 0
    for line in path.open("r", encoding="utf-8"):
        if not line.strip():
            continue
        try:
            event = normalize_event(json.loads(line))
            entities = extract_entities(event)
            relationships = infer_relationships(event, entities)
        except Exception:
            errors += 1
            continue
        events += 1
        entity_count += len(entities)
        relationship_count += len(relationships)
    _print_result("normalize-only", started, events, entity_count, relationship_count, errors)


async def _run_graph_batch(path: Path, batch_size: int) -> None:
    import sys

    sys.path.insert(0, str(ROOT / "backend"))
    from app.enrichment.cache import RedisEnrichmentCache
    from app.enrichment.dependencies import close_enrichment_provider, make_enrichment_provider
    from app.enrichment.service import EnrichmentService
    from app.graph.repository import GraphRepository, create_graph_driver
    from app.graph.service import GraphService
    from app.ocsf.schemas import OCSFEvent
    from app.core.config import get_settings

    settings = get_settings()
    driver = create_graph_driver()
    cache = RedisEnrichmentCache(settings.redis_url)
    provider = make_enrichment_provider()
    service = GraphService(
        GraphRepository(driver),
        enrichment_service=EnrichmentService(provider, cache=cache, ttl_seconds=settings.enrichment_cache_ttl_seconds),
    )
    started = time.perf_counter()
    events = errors = entity_count = relationship_count = 0
    batch = []
    try:
        for line in path.open("r", encoding="utf-8"):
            if not line.strip():
                continue
            try:
                batch.append(OCSFEvent.model_validate_json(line))
            except Exception:
                errors += 1
                continue
            if len(batch) >= batch_size:
                results = await service.process_events_batch(batch)
                events += len(results)
                entity_count += sum(result.entities for result in results)
                relationship_count += sum(result.relationships for result in results)
                batch.clear()
        if batch:
            results = await service.process_events_batch(batch)
            events += len(results)
            entity_count += sum(result.entities for result in results)
            relationship_count += sum(result.relationships for result in results)
    finally:
        await close_enrichment_provider(provider)
        await cache.close()
        await driver.close()
    _print_result("graph-batch", started, events, entity_count, relationship_count, errors)


async def _run_kafka_end_to_end(path: Path) -> None:
    import sys

    sys.path.insert(0, str(ROOT / "backend"))
    from app.database.session import SessionLocal, init_db
    from app.ingestion.kafka_service import enqueue_jsonl_path

    init_db()
    started = time.perf_counter()
    with SessionLocal() as db:
        batch = await enqueue_jsonl_path(db, str(path), tenant_id="benchmark", actor="benchmark")
        _print_result("kafka-end-to-end", started, batch.total_records, 0, 0, batch.error_records)
        print(json.dumps({"batch_id": batch.id, "status": batch.status}, sort_keys=True))


def _print_result(mode: str, started: float, events: int, entities: int, relationships: int, errors: int) -> None:
    elapsed = time.perf_counter() - started
    print(
        json.dumps(
            {
                "mode": mode,
                "elapsed_seconds": round(elapsed, 3),
                "events": events,
                "events_per_second": round(events / elapsed, 2) if elapsed else events,
                "entity_observations": entities,
                "relationship_observations": relationships,
                "errors": errors,
            },
            indent=2,
            sort_keys=True,
        )
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark ingestion and graph paths.")
    parser.add_argument("mode", choices=("normalize-only", "graph-batch", "kafka-end-to-end"))
    parser.add_argument("--input", type=Path, default=ROOT / "data" / "generated" / "benchmark-ocsf.jsonl")
    parser.add_argument("--batch-size", type=int, default=500)
    return parser.parse_args()


if __name__ == "__main__":
    main()
