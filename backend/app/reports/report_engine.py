"""AEGIS Report Generator -- Report Engine Coordinator

Orchestrates end-to-end report generation:
1. Gathers all scan data (assets, vulns, SHAP explanations) from DB
2. Selects provider (Gemini AI or Template fallback)
3. Generates report content
4. Persists the Report record to the database
"""
import json
import logging
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models import (
    Scan, Asset, Port, Technology, Vulnerability,
    SSLCertificate, SecurityHeader, DNSRecord, ThreatIntel, Report
)
from app.reports.template_provider import TemplateReportProvider
from app.reports.gemini_provider import GeminiReportProvider

logger = logging.getLogger("aegis.reports.engine")


class ReportEngine:
    """Coordinates report generation across providers."""

    def __init__(self):
        self.template_provider = TemplateReportProvider()
        self.gemini_provider = GeminiReportProvider()

    def gather_scan_data(self, scan_id: str, db: Session) -> Optional[Dict[str, Any]]:
        """Gather all scan results into a structured dict for report generation.

        Returns None if the scan doesn't exist or hasn't completed.
        """
        scan = db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return None

        if scan.status not in ("completed", "failed"):
            logger.warning(f"Scan {scan_id} status is '{scan.status}', report may be incomplete")

        assets_orm = db.query(Asset).filter_by(scan_id=scan_id).order_by(Asset.risk_score.desc()).all()

        assets_data = []
        all_vulns = []

        for asset in assets_orm:
            ports = db.query(Port).filter_by(asset_id=asset.id).all()
            techs = db.query(Technology).filter_by(asset_id=asset.id).all()
            vulns = db.query(Vulnerability).filter_by(asset_id=asset.id).all()
            ssl = db.query(SSLCertificate).filter_by(asset_id=asset.id).first()
            hdr = db.query(SecurityHeader).filter_by(asset_id=asset.id).first()
            dns = db.query(DNSRecord).filter_by(asset_id=asset.id).all()

            # Parse SHAP explanation
            shap = asset.shap_explanation
            if isinstance(shap, str):
                try:
                    shap = json.loads(shap)
                except (json.JSONDecodeError, TypeError):
                    shap = {}
            if not shap:
                shap = {}

            asset_dict = {
                "id": asset.id,
                "hostname": asset.hostname,
                "ip_address": asset.ip_address,
                "is_apex": asset.is_apex,
                "is_live": asset.is_live,
                "risk_score": asset.risk_score or 0.0,
                "risk_level": asset.risk_level or "info",
                "shap_explanation": shap,
                "http_status": asset.http_status,
                "http_title": asset.http_title,
                "ports": [
                    {
                        "port_number": p.port_number,
                        "protocol": p.protocol,
                        "state": p.state,
                        "service_name": p.service_name,
                        "service_version": p.service_version,
                        "banner": p.banner,
                        "is_critical": p.is_critical,
                    }
                    for p in ports
                ],
                "technologies": [
                    {
                        "name": t.name,
                        "version": t.version,
                        "category": t.category,
                        "is_outdated": t.is_outdated,
                    }
                    for t in techs
                ],
                "security_headers": {
                    "grade": hdr.grade,
                    "score": hdr.score,
                    "hsts": hdr.hsts,
                    "csp": hdr.csp,
                } if hdr else None,
                "ssl_cert": {
                    "issuer": ssl.issuer,
                    "is_expired": ssl.is_expired,
                    "is_self_signed": ssl.is_self_signed,
                    "has_weak_cipher": ssl.has_weak_cipher,
                    "expires_in_days": ssl.expires_in_days,
                    "tls_version": ssl.tls_version,
                } if ssl else None,
                "dns_records": [
                    {
                        "record_type": d.record_type,
                        "record_value": d.record_value,
                        "is_dangling": d.is_dangling,
                        "finding": d.finding,
                    }
                    for d in dns
                ],
            }
            assets_data.append(asset_dict)

            # Collect vulns with hostname enrichment
            for v in vulns:
                vuln_dict = {
                    "id": v.id,
                    "asset_id": v.asset_id,
                    "hostname": asset.hostname,
                    "cve_id": v.cve_id,
                    "title": v.title,
                    "description": v.description,
                    "severity": v.severity,
                    "cvss_score": v.cvss_score,
                    "epss_score": v.epss_score,
                    "epss_percentile": v.epss_percentile,
                    "is_cisa_kev": v.is_cisa_kev,
                    "remediation": v.remediation,
                }
                all_vulns.append(vuln_dict)

        return {
            "scan": {
                "id": scan.id,
                "target_domain": scan.target_domain,
                "scan_profile": scan.scan_profile,
                "status": scan.status,
                "total_assets": scan.total_assets,
                "started_at": str(scan.started_at) if scan.started_at else None,
                "completed_at": str(scan.completed_at) if scan.completed_at else None,
            },
            "assets": assets_data,
            "vulnerabilities": all_vulns,
            "stats": {
                "avg_risk_score": scan.avg_risk_score or 0.0,
                "max_risk_score": scan.max_risk_score or 0.0,
                "critical_count": scan.critical_count or 0,
                "high_count": scan.high_count or 0,
                "medium_count": scan.medium_count or 0,
                "low_count": scan.low_count or 0,
                "info_count": scan.info_count or 0,
            },
        }

    async def generate_report(
        self,
        scan_id: str,
        report_type: str,
        provider: str,
        db: Session,
    ) -> Optional[Report]:
        """Generate and persist a report.

        Args:
            scan_id: The scan to report on.
            report_type: 'executive', 'technical', or 'compliance'.
            provider: 'gemini' or 'template'.
            db: SQLAlchemy session.

        Returns:
            The persisted Report ORM object, or None on failure.
        """
        # 1. Gather data
        scan_data = self.gather_scan_data(scan_id, db)
        if not scan_data:
            return None

        # 2. Generate with selected provider
        report_content = None

        if provider == "gemini" and self.gemini_provider.is_available:
            logger.info(f"Generating {report_type} report via Gemini AI for scan {scan_id}")
            report_content = await self.gemini_provider.generate(scan_data, report_type)

            if not report_content:
                logger.warning("Gemini generation failed, falling back to template provider")

        # Fallback or explicit template selection
        if not report_content:
            logger.info(f"Generating {report_type} report via template provider for scan {scan_id}")
            report_content = self.template_provider.generate(scan_data, report_type)

        if not report_content:
            logger.error("Both providers failed to generate report")
            return None

        # 3. If Gemini produced no HTML, render with template provider
        if not report_content.get("html_content"):
            # Use template provider's HTML renderer with Gemini's markdown content
            html = self.template_provider._render_html(
                title=report_content["title"],
                exec_summary=report_content["executive_summary"],
                attack_surface=report_content["attack_surface_analysis"],
                remediation_plan=report_content.get("remediation_plan", []),
                domain=scan_data["scan"]["target_domain"],
                timestamp=scan_data["scan"].get("completed_at", "N/A"),
                posture=0,
            )
            report_content["html_content"] = html

        # 4. Persist to database
        report = Report(
            scan_id=scan_id,
            report_type=report_type,
            title=report_content["title"],
            executive_summary=report_content.get("executive_summary"),
            attack_surface_analysis=report_content.get("attack_surface_analysis"),
            remediation_plan=report_content.get("remediation_plan", []),
            html_content=report_content.get("html_content"),
        )
        db.add(report)
        db.commit()
        db.refresh(report)

        logger.info(f"Report {report.id} generated successfully ({report_type} via {provider})")
        return report


# Module-level singleton
report_engine = ReportEngine()
