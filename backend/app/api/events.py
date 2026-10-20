"""AEGIS API Router -- Server-Sent Events (SSE) Stream

Provides live SSE endpoint at GET /api/events/{scan_id} that replays
historical events and streams real-time scan progress to frontend clients.
"""
import logging
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from app.recon.event_bus import event_bus

logger = logging.getLogger("aegis.api.events")

router = APIRouter(prefix="/api/events", tags=["Events"])


@router.get(
    "/{scan_id}",
    summary="Subscribe to real-time scan events via SSE",
    response_class=StreamingResponse,
)
async def stream_scan_events(scan_id: str):
    """Server-Sent Events endpoint.

    Clients connect via EventSource and receive JSON-encoded events:
    - scan_progress: phase updates with percent completion
    - asset_discovered: new subdomain/IP found
    - port_discovered: open ports on an asset
    - vulnerability_discovered: new CVE or finding
    - risk_scored: ML risk score + SHAP summary
    - scan_completed / scan_failed: terminal events

    History events are replayed first for late-joining clients.
    """
    logger.info(f"SSE client connected for scan {scan_id}")

    return StreamingResponse(
        event_bus.subscribe(scan_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable Nginx buffering
        },
    )
