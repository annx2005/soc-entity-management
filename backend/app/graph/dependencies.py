from __future__ import annotations

from collections.abc import AsyncGenerator

from app.graph.repository import GraphRepository, create_graph_driver
from app.graph.service import GraphService


async def get_graph_service() -> AsyncGenerator[GraphService, None]:
    driver = create_graph_driver()
    try:
        yield GraphService(GraphRepository(driver))
    finally:
        await driver.close()
