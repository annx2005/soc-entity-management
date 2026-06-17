from __future__ import annotations

from app.graph.schemas import GraphIngestResult
from app.graph.service import GraphService
from app.ingestion.kafka_messages import OCSFEventMessage
from app.ocsf.schemas import OCSFEvent


async def process_ocsf_event_message(message: OCSFEventMessage, graph: GraphService) -> GraphIngestResult:
    event = OCSFEvent.model_validate(message.ocsf_event)
    return await graph.process_event(event)
