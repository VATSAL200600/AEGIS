"""AEGIS API Router -- Dashboard Analytics

Aggregated statistics endpoint for the frontend dashboard:
overall posture, severity distribution, top risky assets,
exposed critical ports, and common technology stack.
"""
import logging
from typing import Dict, Any, List
from collections import Counter
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models import (
    Scan, Asset, Port, Technology, Vulnerability, SecurityHeader
)
from app.schemas import DashboardStats, SuccessEnvelope

logger = logging.getLogger("aegis.api.dashboard")

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

# Well-known high-risk ports
CRITICAL_PORT_LABELS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}


@router.get(
    "",
    response_model=SuccessEnvelope[DashboardStats],
    summary="Get aggregated dashboard analytics",
)
def get_dashboard_stats(
    scan_id: str = Query(None, description="Optional: scope to a single scan"),
    db: Session = Depends(get_db),
):
    """Computes real-time dashboard analytics from scan results."""

    # Scope queries
    if scan_id:
        scans = db.query(Scan).filter_by(id=scan_id).all()
        asset_q = db.query(Asset).filter_by(scan_id=scan_id)
    else:
        scans = db.query(Scan).filter(Scan.status == "completed").all()
        completed_ids = [s.id for s in scans]
        if completed_ids:
            asset_q = db.query(Asset).filter(Asset.scan_id.in_(completed_ids))
        else:
            asset_q = db.query(Asset).filter(False)  # empty

    total_scans = len(scans)
    all_assets = asset_q.all()
    total_assets = len(all_assets)

    # ---- Overall Security Posture Score (0-100, higher = safer) ----
    # Inverse of average risk: posture = 100 - avg_risk
    if total_assets:
        avg_risk = sum((a.risk_score or 0.0) for a in all_assets) / total_assets
        posture = round(max(0.0, 100.0 - avg_risk), 1)
    else:
        avg_risk = 0.0
        posture = 100.0

    # ---- Severity Distribution ----
    severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for a in all_assets:
        level = (a.risk_level or "info").lower()
        if level in severity_dist:
            severity_dist[level] += 1

    # ---- Top Vulnerable Assets (top 10 by risk_score descending) ----
    sorted_assets = sorted(all_assets, key=lambda a: (a.risk_score or 0.0), reverse=True)
    top_vuln = []
    for a in sorted_assets[:10]:
        vuln_count = db.query(func.count(Vulnerability.id)).filter_by(asset_id=a.id).scalar() or 0
        hdr = db.query(SecurityHeader).filter_by(asset_id=a.id).first()
        top_vuln.append({
            "asset_id": a.id,
            "hostname": a.hostname,
            "ip_address": a.ip_address,
            "risk_score": round(a.risk_score or 0.0, 1),
            "risk_level": a.risk_level or "info",
            "vulnerabilities_count": vuln_count,
            "header_grade": hdr.grade if hdr else None,
        })

    # ---- Exposed Critical Ports (aggregate counts) ----
    asset_ids = [a.id for a in all_assets]
    exposed_ports: Dict[str, int] = {}
    if asset_ids:
        port_rows = (
            db.query(Port.port_number, func.count(Port.id))
            .filter(Port.asset_id.in_(asset_ids), Port.is_critical == True)
            .group_by(Port.port_number)
            .all()
        )
        for port_num, count in port_rows:
            label = CRITICAL_PORT_LABELS.get(port_num, f"Port {port_num}")
            exposed_ports[label] = count

    # ---- Common Technologies (top 15) ----
    tech_counter: Counter = Counter()
    if asset_ids:
        techs = (
            db.query(Technology.name, func.count(Technology.id))
            .filter(Technology.asset_id.in_(asset_ids))
            .group_by(Technology.name)
            .order_by(func.count(Technology.id).desc())
            .limit(15)
            .all()
        )
        for name, count in techs:
            tech_counter[name] = count

    common_techs: List[Dict[str, Any]] = [
        {"name": name, "count": count} for name, count in tech_counter.most_common(15)
    ]

    stats = DashboardStats(
        total_scans=total_scans,
        total_assets_monitored=total_assets,
        overall_security_posture_score=posture,
        severity_distribution=severity_dist,
        top_vulnerable_assets=top_vuln,
        exposed_critical_ports=exposed_ports,
        common_technologies=common_techs,
    )

    return SuccessEnvelope(
        data=stats,
        message=f"Dashboard stats computed across {total_scans} scan(s) and {total_assets} asset(s)",
    )
