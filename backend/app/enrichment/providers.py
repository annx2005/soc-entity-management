from __future__ import annotations

from typing import Any, Protocol
from urllib.parse import quote

import httpx

from app.entities.schemas import EntityType
from app.enrichment.schemas import EnrichmentResult


class EnrichmentProvider(Protocol):
    async def lookup(self, entity_type: EntityType, value: str) -> EnrichmentResult | None:
        ...


class CompositeEnrichmentProvider:
    def __init__(self, providers: list[EnrichmentProvider]) -> None:
        self._providers = providers

    async def lookup(self, entity_type: EntityType, value: str) -> EnrichmentResult | None:
        for provider in self._providers:
            result = await provider.lookup(entity_type, value)
            if result is not None:
                return result
        return None

    async def close(self) -> None:
        for provider in self._providers:
            close = getattr(provider, "close", None)
            if callable(close):
                await close()


class IpinfoLiteEnrichmentProvider:
    def __init__(
        self,
        *,
        token: str | None = None,
        base_url: str = "https://api.ipinfo.io/lite",
        timeout_seconds: float = 5.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._token = token
        self._base_url = base_url.rstrip("/")
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)

    async def lookup(self, entity_type: EntityType, value: str) -> EnrichmentResult | None:
        if entity_type != EntityType.IP:
            return None
        if not self._token:
            return None

        response = await self._client.get(f"{self._base_url}/{quote(value, safe='')}", params={"token": self._token})
        if response.status_code == 404:
            return None
        response.raise_for_status()

        payload = _normalize_payload(response)
        if payload is None:
            return None
        data = _compact_dict(
            {
                "ip": payload.get("ip"),
                "country": payload.get("country"),
                "country_code": payload.get("country_code"),
                "continent": payload.get("continent"),
                "continent_code": payload.get("continent_code"),
                "asn": payload.get("asn"),
                "as_name": payload.get("as_name"),
                "as_domain": payload.get("as_domain"),
                "provider": "ipinfo-lite",
            }
        )
        if not data:
            return None
        return EnrichmentResult(
            entity_type=entity_type.value,
            value=value,
            data=data,
            source="ipinfo-lite",
            cache_status="miss",
        )

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()


class MalwareBazaarEnrichmentProvider:
    def __init__(
        self,
        *,
        auth_key: str | None = None,
        base_url: str = "https://mb-api.abuse.ch/api/v1/",
        timeout_seconds: float = 5.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._auth_key = auth_key
        self._base_url = base_url
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)

    async def lookup(self, entity_type: EntityType, value: str) -> EnrichmentResult | None:
        if entity_type != EntityType.FILE_HASH:
            return None
        if not self._auth_key:
            return None

        response = await self._client.post(
            self._base_url,
            headers={"Auth-Key": self._auth_key},
            data={"query": "get_info", "hash": value},
        )
        response.raise_for_status()

        payload = _normalize_payload(response)
        if payload is None:
            return None
        status = str(payload.get("query_status") or "")
        if status in {"hash_not_found", "illegal_hash", "no_hash_provided", "no_results"}:
            return None

        record = _extract_malware_bazaar_record(payload)
        if record is None:
            return None

        signature = record.get("signature")
        data = _compact_dict(
            {
                "sha256_hash": record.get("sha256_hash"),
                "sha1_hash": record.get("sha1_hash"),
                "md5_hash": record.get("md5_hash"),
                "first_seen": record.get("first_seen"),
                "last_seen": record.get("last_seen"),
                "file_name": record.get("file_name"),
                "file_size": record.get("file_size"),
                "file_type": record.get("file_type"),
                "file_type_mime": record.get("file_type_mime"),
                "file_format": record.get("file_format"),
                "reporter": record.get("reporter"),
                "origin_country": record.get("origin_country"),
                "signature": signature,
                "malware_family": signature,
                "tags": record.get("tags"),
                "delivery_method": record.get("delivery_method"),
                "imphash": record.get("imphash"),
                "tlsh": record.get("tlsh"),
                "ssdeep": record.get("ssdeep"),
                "provider": "malwarebazaar",
            }
        )
        if not data:
            return None
        return EnrichmentResult(
            entity_type=entity_type.value,
            value=value,
            data=data,
            source="malwarebazaar",
            cache_status="miss",
        )

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()


def _normalize_payload(response: httpx.Response) -> dict[str, Any] | None:
    if not response.content:
        return None
    payload = response.json()
    if payload is None:
        return None
    if isinstance(payload, dict):
        return payload
    return {"result": payload}


def _compact_dict(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}


def _extract_malware_bazaar_record(payload: dict[str, Any]) -> dict[str, Any] | None:
    records = payload.get("data")
    if isinstance(records, list):
        for item in records:
            if isinstance(item, dict):
                return item
    if payload.get("query_status") == "ok":
        return payload
    return None
