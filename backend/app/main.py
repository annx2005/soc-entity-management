from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session

from app.api.audit import router as audit_router
from app.api.auth import router as auth_router
from app.api.entities import router as entities_router
from app.api.events import router as events_router
from app.core.config import get_settings
from app.core.health import check_kafka, check_neo4j, check_postgres, check_redis
from app.database.session import get_db, init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title=get_settings().app_name, version="0.1.0", lifespan=lifespan)
app.include_router(auth_router)
app.include_router(events_router)
app.include_router(entities_router)
app.include_router(audit_router)


@app.get("/health")
def health(db: Session = Depends(get_db)) -> dict[str, Any]:
    services = {
        "postgresql": check_postgres(db),
        "redis": check_redis(),
        "neo4j": check_neo4j(),
        "kafka": check_kafka(),
    }
    overall = "ok" if all(service["status"] == "ok" for service in services.values()) else "degraded"
    return {"status": overall, "services": services}
