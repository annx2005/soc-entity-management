from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SOC Entity Management"
    environment: str = "local"
    tenant_id_default: str = "default"
    jwt_secret_key: str = "local-dev-change-me-32-bytes-min"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    database_url: str = "sqlite:///./soc_entity_management.db"
    redis_url: str = "redis://localhost:6379/0"
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "password"
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_raw_events_topic: str = "soc.raw-events.v1"
    kafka_normalized_events_topic: str = "soc.normalized-events.v1"
    kafka_ocsf_events_topic: str = "soc.ocsf-events.v1"
    kafka_dead_letter_topic: str = "soc.ingest-dlq.v1"
    kafka_ingestion_group_id: str = "soc-ingestion-workers"
    kafka_graph_group_id: str = "soc-graph-workers"
    enrichment_ip_source_path: str = "/data/enrichment/ip_enrichment.json"
    enrichment_file_hash_source_path: str = "/data/enrichment/file_hash_enrichment.json"
    enrichment_cache_ttl_seconds: int = 86400
    enrichment_enabled: bool = True

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


@lru_cache
def get_settings() -> Settings:
    return Settings()
