"""AEGIS API Router -- Scan Management

Endpoints for creating, listing, retrieving, deleting, and cancelling scans.
POST /scans launches the 7-stage DAG orchestrator as a background asyncio task.
"""
import asyncio
import logging
from typing import Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models import Scan, Asset
from app.schemas import (
    ScanCreate, ScanResponse, ScanListResponse,
    SuccessEnvelope, ErrorResponse
)
from app.recon.orchestrator import launch_scan_background
from app.recon.event_bus import event_bus
from app.config import settings

logger = logging.getLogger("aegis.api.scans")

router = APIRouter(prefix="/api/scans", tags=["Scans"])

# In-memory scan task registry (scan_id -> asyncio.Task)
_scan_tasks: Dict[str, asyncio.Task] = {}


# ---- Helper ----
def _classify_risk(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


# ---- Create Scan ----
@router.post(
    "",
    response_model=SuccessEnvelope[ScanResponse],
    status_code=201,
    summary="Launch a new attack surface scan",
    responses={409: {"model": ErrorResponse}},
)
async def create_scan(payload: ScanCreate, db: Session = Depends(get_db)):
    """Validates target domain, creates DB record, and launches the scan orchestrator
    as a detached asyncio background task."""

    # Throttle: enforce maximum concurrent scans
    running_count = db.query(func.count(Scan.id)).filter(
        Scan.status.in_(["pending", "running"])
    ).scalar()
    if running_count >= settings.MAX_CONCURRENT_SCANS:
        raise HTTPException(
            status_code=409,
            detail=f"Maximum of {settings.MAX_CONCURRENT_SCANS} concurrent scans allowed. "
                   f"Wait for an existing scan to complete.",
        )

    # Sanitize target domain and extract optional custom port
    raw_target = payload.target_domain.strip().lower()
    custom_port = None
    if "://" in raw_target:
        from urllib.parse import urlparse
        parsed = urlparse(raw_target)
        clean_domain = parsed.hostname or raw_target
        custom_port = parsed.port
    elif ":" in raw_target:
        parts = raw_target.split(":")
        clean_domain = parts[0].strip()
        try:
            custom_port = int(parts[1].split("/")[0].strip())
        except ValueError:
            clean_domain = raw_target.split("/")[0].strip()
    else:
        clean_domain = raw_target.split("/")[0].strip()

    # Create the scan record with cleaned domain
    scan = Scan(
        target_domain=clean_domain,
        scan_profile=payload.scan_profile,
        status="pending",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    logger.info(f"Created scan {scan.id} for '{scan.target_domain}' (port={custom_port}, profile={scan.scan_profile})")

    # Launch the orchestrator as a background task
    task = launch_scan_background(
        scan_id=scan.id,
        target_domain=scan.target_domain,
        scan_profile=scan.scan_profile,
        custom_port=custom_port,
    )
    _scan_tasks[scan.id] = task

    # Cleanup reference when task finishes
    def _on_done(t: asyncio.Task):
        _scan_tasks.pop(scan.id, None)
    task.add_done_callback(_on_done)

    return SuccessEnvelope(
        data=ScanResponse.model_validate(scan),
        message=f"Scan initiated for '{scan.target_domain}'",
    )


# ---- List Scans ----
@router.get(
    "",
    response_model=SuccessEnvelope[ScanListResponse],
    summary="List scans with pagination and optional status filter",
)
def list_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None, pattern="^(pending|running|completed|failed)$"),
    db: Session = Depends(get_db),
):
    query = db.query(Scan)
    if status:
        query = query.filter(Scan.status == status)

    total = query.count()
    pages = max(1, (total + per_page - 1) // per_page)
    offset = (page - 1) * per_page

    items = query.order_by(Scan.created_at.desc()).offset(offset).limit(per_page).all()

    return SuccessEnvelope(
        data=ScanListResponse(
            items=[ScanResponse.model_validate(s) for s in items],
            total=total,
            page=page,
            pages=pages,
        ),
        message=f"Retrieved {len(items)} scans (page {page}/{pages})",
    )


# ---- Get Scan Detail ----
@router.get(
    "/{scan_id}",
    response_model=SuccessEnvelope[ScanResponse],
    summary="Get scan details by ID",
    responses={404: {"model": ErrorResponse}},
)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    return SuccessEnvelope(data=ScanResponse.model_validate(scan))


# ---- Delete Scan ----
@router.delete(
    "/{scan_id}",
    response_model=SuccessEnvelope[dict],
    summary="Delete a scan and all associated data",
    responses={404: {"model": ErrorResponse}},
)
async def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")

    # Cancel running task if exists
    task = _scan_tasks.pop(scan_id, None)
    if task and not task.done():
        task.cancel()

    # Cascade delete handled by SQLAlchemy relationships
    db.delete(scan)
    db.commit()

    # Purge event bus history
    event_bus.clear_scan(scan_id)

    logger.info(f"Deleted scan {scan_id} for domain '{scan.target_domain}'")

    return SuccessEnvelope(
        data={"id": scan_id, "deleted": True},
        message=f"Scan '{scan_id}' and all associated data deleted",
    )


# ---- Cancel Scan ----
@router.post(
    "/{scan_id}/cancel",
    response_model=SuccessEnvelope[ScanResponse],
    summary="Cancel a running scan",
    responses={404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)
async def cancel_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")

    if scan.status not in ("pending", "running"):
        raise HTTPException(
            status_code=409,
            detail=f"Scan is already '{scan.status}', cannot cancel",
        )

    # Cancel background task
    task = _scan_tasks.pop(scan_id, None)
    if task and not task.done():
        task.cancel()

    scan.status = "failed"
    scan.error_message = "Scan cancelled by user"
    db.commit()
    db.refresh(scan)

    await event_bus.publish(scan_id, "scan_failed", {
        "scan_id": scan_id,
        "error": "Scan cancelled by user",
    })

    return SuccessEnvelope(
        data=ScanResponse.model_validate(scan),
        message="Scan cancelled",
    )


# ---- Get Scan Log ----
@router.get(
    "/{scan_id}/log",
    response_model=SuccessEnvelope[dict],
    summary="Retrieve the text log for a scan",
    responses={404: {"model": ErrorResponse}},
)
def get_scan_log(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")

    return SuccessEnvelope(
        data={"scan_id": scan_id, "log": scan.scan_log or ""},
        message="Scan log retrieved",
    )
