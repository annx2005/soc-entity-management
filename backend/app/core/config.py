from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_DIR = Path(__file__).resolve().parents[3]
ROOT_ENV_FILE = ROOT_DIR / ".env"


def _default_parser_config_dir() -> str:
    for candidate in (
        Path("/app/config/parsers"),
        ROOT_DIR / "config" / "parsers",
    ):
        if candidate.exists():
            return str(candidate)
    return str(ROOT_DIR / "config" / "parsers")


class Settings(BaseSettings):
    app_name: str = "SOC Entity Management"
    environment: str = "local"
    tenant_id_default: str
    jwt_secret_key: str
    jwt_algorithm: str
    access_token_expire_minutes: int

    database_url: str
    redis_url: str
    neo4j_uri: str
    neo4j_user: str
    neo4j_password: str
    kafka_bootstrap_servers: str
    kafka_raw_events_topic: str
    kafka_normalized_events_topic: str
    kafka_ocsf_events_topic: str
    kafka_dead_letter_topic: str
    kafka_ingestion_group_id: str
    kafka_graph_group_id: str
    enrichment_provider_mode: str = "ipinfo_malwarebazaar"
    enrichment_ipinfo_token: Optional[str] = None
    enrichment_ipinfo_base_url: str = "https://api.ipinfo.io/lite"
    enrichment_malware_bazaar_auth_key: Optional[str] = None
    enrichment_malware_bazaar_url: str = "https://mb-api.abuse.ch/api/v1/"
    enrichment_http_timeout_seconds: float = 5.0
    enrichment_cache_ttl_seconds: int
    enrichment_enabled: bool
    metrics_enabled: bool = True
    metrics_port: int = 9100
    parser_config_dir: str = _default_parser_config_dir()
    ingestion_db_batch_size: int = 1000
    graph_batch_size: int = 500
    graph_batch_max_wait_seconds: float = 2.0

    model_config = SettingsConfigDict(env_file=ROOT_ENV_FILE, env_file_encoding="utf-8", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
