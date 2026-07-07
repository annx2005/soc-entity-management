from __future__ import annotations

import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.parsers import router as parsers_router
from app.auth.dependencies import TenantContext, get_tenant_context


def test_list_parsers_requires_auth_context_and_returns_configs() -> None:
    client = parser_test_client(context=tenant_context(role="viewer"))

    response = client.get("/api/parsers")

    assert response.status_code == 200
    parser_ids = {item["id"] for item in response.json()}
    assert "sysmon" in parser_ids
    assert "wazuh-archive" in parser_ids
    assert "wazuh-alert" not in parser_ids


def test_preview_parser_allows_analyst() -> None:
    client = parser_test_client(context=tenant_context(role="analyst"))

    response = client.post(
        "/api/parsers/preview",
        json={
            "parser_id": "sysmon",
            "record": {
                "TimeCreated": "/Date(1783002881751)/",
                "Id": 1,
                "ProviderName": "Microsoft-Windows-Sysmon",
                "Message": "Process Create:\r\nUtcTime: 2026-07-02 14:34:41.749\r\nImage: C:\\Windows\\System32\\cmd.exe\r\nUser: NT AUTHORITY\\SYSTEM",
            },
        },
    )

    assert response.status_code == 200
    assert response.json()["parser_id"] == "sysmon"
    assert response.json()["ocsf_event"]["source_name"] == "sysmon"


def test_preview_parser_rejects_viewer() -> None:
    client = parser_test_client(context=tenant_context(role="viewer"))

    response = client.post("/api/parsers/preview", json={"record": {}})

    assert response.status_code == 403


def parser_test_client(context: TenantContext | None = None) -> TestClient:
    app = FastAPI()
    app.include_router(parsers_router)
    if context is not None:
        app.dependency_overrides[get_tenant_context] = lambda: context
    return TestClient(app)


def tenant_context(role: str) -> TenantContext:
    return TenantContext(
        account_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        tenant_slug="workspace",
        email="analyst@example.com",
        role=role,
        scope="tenant",
    )
