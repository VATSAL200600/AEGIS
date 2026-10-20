"""AEGIS API Router -- Asset Browsing & Detail

Endpoints for listing and querying assets and all associated reconnaissance
sub-resources (ports, technologies, vulns, SSL, headers, DNS, threat intel).
"""
import json
import logging
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.models import (
    Asset, Scan, Port, Technology, Vulnerability,
    SSLCertificate, SecurityHeader, DNSRecord, ThreatIntel
)
from app.schemas import (
    AssetSummary, AssetDetail, PortResponse, TechnologyResponse,
    VulnerabilityResponse, SSLCertResponse, SecurityHeaderResponse,
    DNSRecordResponse, ThreatIntelResponse,
    SuccessEnvelope, ErrorResponse
)

logger = logging.getLogger("aegis.api.assets")

router = APIRouter(prefix="/api/assets", tags=["Assets"])


# ---- Helper: build AssetSummary from ORM ----
def _build_summary(asset: Asset, db: Session) -> AssetSummary:
    ports = db.query(Port).filter_by(asset_id=asset.id).all()
    techs = db.query(Technology).filter_by(asset_id=asset.id).all()
    vulns_count = db.query(Vulnerability).filter_by(asset_id=asset.id).count()
    ssl = db.query(SSLCertificate).filter_by(asset_id=asset.id).first()
    hdr = db.query(SecurityHeader).filter_by(asset_id=asset.id).first()

    ssl_status = None
    if ssl:
        if ssl.is_expired:
            ssl_status = "expired"
        elif ssl.is_self_signed:
            ssl_status = "self-signed"
        elif ssl.has_weak_cipher or ssl.has_weak_protocol:
            ssl_status = "weak"
        else:
            ssl_status = "valid"

    return AssetSummary(
        id=asset.id,
        scan_id=asset.scan_id,
        hostname=asset.hostname,
        ip_address=asset.ip_address,
        is_apex=asset.is_apex,
        is_live=asset.is_live,
        risk_score=asset.risk_score or 0.0,
        risk_level=asset.risk_level or "info",
        open_ports=[p.port_number for p in ports],
        technologies=[t.name for t in techs],
        vulnerabilities_count=vulns_count,
        ssl_status=ssl_status,
        header_grade=hdr.grade if hdr else None,
        created_at=asset.created_at,
    )


# ---- Helper: build AssetDetail from ORM ----
def _build_detail(asset: Asset, db: Session) -> AssetDetail:
    ports = db.query(Port).filter_by(asset_id=asset.id).all()
    techs = db.query(Technology).filter_by(asset_id=asset.id).all()
    vulns = db.query(Vulnerability).filter_by(asset_id=asset.id).all()
    ssl = db.query(SSLCertificate).filter_by(asset_id=asset.id).first()
    hdr = db.query(SecurityHeader).filter_by(asset_id=asset.id).first()
    dns = db.query(DNSRecord).filter_by(asset_id=asset.id).all()
    intel = db.query(ThreatIntel).filter_by(asset_id=asset.id).all()

    # Parse shap_explanation from JSON string if needed
    shap = asset.shap_explanation
    if isinstance(shap, str):
        try:
            shap = json.loads(shap)
        except (json.JSONDecodeError, TypeError):
            shap = {}
    if not shap:
        shap = {}

    return AssetDetail(
        id=asset.id,
        scan_id=asset.scan_id,
        hostname=asset.hostname,
        ip_address=asset.ip_address,
        is_apex=asset.is_apex,
        is_live=asset.is_live,
        risk_score=asset.risk_score or 0.0,
        risk_level=asset.risk_level or "info",
        shap_explanation=shap,
        http_status=asset.http_status,
        http_title=asset.http_title,
        country=asset.country,
        asn=asset.asn,
        screenshot_path=asset.screenshot_path,
        created_at=asset.created_at,
        ports=[PortResponse.model_validate(p) for p in ports],
        technologies=[TechnologyResponse.model_validate(t) for t in techs],
        vulnerabilities=[VulnerabilityResponse.model_validate(v) for v in vulns],
        ssl_cert=SSLCertResponse.model_validate(ssl) if ssl else None,
        security_headers=SecurityHeaderResponse.model_validate(hdr) if hdr else None,
        dns_records=[DNSRecordResponse.model_validate(d) for d in dns],
        threat_intel=[ThreatIntelResponse.model_validate(i) for i in intel],
    )


# ---- List Assets for a Scan or System-wide ----
@router.get(
    "",
    response_model=SuccessEnvelope[List[AssetSummary]],
    summary="List assets for a scan or system-wide, optionally filtered/sorted",
)
def list_assets(
    scan_id: Optional[str] = Query(None, description="Optional parent scan ID"),
    sort_by: str = Query("risk_score", pattern="^(risk_score|hostname|created_at)$"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    risk_level: Optional[str] = Query(None, pattern="^(critical|high|medium|low|info)$"),
    search: Optional[str] = Query(None, description="Filter by hostname or IP"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    query = db.query(Asset)

    if scan_id and isinstance(scan_id, str) and scan_id.strip():
        scan = db.query(Scan).filter_by(id=scan_id.strip()).first()
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
        query = query.filter_by(scan_id=scan_id.strip())

    if risk_level:
        query = query.filter(Asset.risk_level == risk_level)

    if search:
        s = f"%{search.strip()}%"
        query = query.filter((Asset.hostname.ilike(s)) | (Asset.ip_address.ilike(s)))

    # Dynamic sort
    sort_col = getattr(Asset, sort_by, Asset.risk_score)
    if sort_order == "desc":
        query = query.order_by(sort_col.desc())
    else:
        query = query.order_by(sort_col.asc())

    assets = query.offset(offset).limit(limit).all()
    summaries = [_build_summary(a, db) for a in assets]

    msg = f"Retrieved {len(summaries)} assets" + (f" for scan '{scan_id}'" if scan_id else "")
    return SuccessEnvelope(
        data=summaries,
        message=msg,
    )



# ---- Get Asset Detail ----
@router.get(
    "/{asset_id}",
    response_model=SuccessEnvelope[AssetDetail],
    summary="Get full asset detail including all recon sub-resources",
    responses={404: {"model": ErrorResponse}},
)
def get_asset_detail(asset_id: str, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter_by(id=asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")

    detail = _build_detail(asset, db)
    return SuccessEnvelope(data=detail, message=f"Asset detail for '{asset.hostname}'")


# ---- Get SHAP Explanation for Asset ----
@router.get(
    "/{asset_id}/shap",
    response_model=SuccessEnvelope[dict],
    summary="Get the TreeSHAP risk explanation for a single asset",
    responses={404: {"model": ErrorResponse}},
)
def get_asset_shap(asset_id: str, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter_by(id=asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")

    shap = asset.shap_explanation
    if isinstance(shap, str):
        try:
            shap = json.loads(shap)
        except (json.JSONDecodeError, TypeError):
            shap = {}
    if not shap:
        shap = {}

    return SuccessEnvelope(
        data={"asset_id": asset_id, "hostname": asset.hostname, "explanation": shap},
        message=f"SHAP explanation for '{asset.hostname}'",
    )


# ---- List Vulnerabilities for Scan (cross-asset) ----
@router.get(
    "/vulnerabilities/all",
    response_model=SuccessEnvelope[List[dict]],
    summary="List all vulnerabilities across all assets in a scan",
)
def list_scan_vulnerabilities(
    scan_id: str = Query(..., description="Parent scan ID"),
    severity: Optional[str] = Query(None, pattern="^(critical|high|medium|low)$"),
    db: Session = Depends(get_db),
):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")

    asset_ids = [a.id for a in db.query(Asset.id).filter_by(scan_id=scan_id).all()]
    if not asset_ids:
        return SuccessEnvelope(data=[], message="No assets found for this scan")

    query = db.query(Vulnerability).filter(Vulnerability.asset_id.in_(asset_ids))
    if severity:
        query = query.filter(Vulnerability.severity == severity)

    vulns = query.order_by(Vulnerability.cvss_score.desc().nullslast()).all()

    result = []
    for v in vulns:
        asset = db.query(Asset).filter_by(id=v.asset_id).first()
        entry = VulnerabilityResponse.model_validate(v).model_dump()
        entry["hostname"] = asset.hostname if asset else "unknown"
        result.append(entry)

    return SuccessEnvelope(
        data=result,
        message=f"Found {len(result)} vulnerabilities in scan '{scan_id}'",
    )
