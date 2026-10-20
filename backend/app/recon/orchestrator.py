"""AEGIS Reconnaissance Engine — Scan Orchestrator

Coordinates the asynchronous execution Directed Acyclic Graph (DAG) for asset discovery,
port mapping, web inspection, DNS auditing, threat intel enrichment, and AI risk scoring.
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import (
    Scan, Asset, Port, Technology, Vulnerability,
    SSLCertificate, SecurityHeader, DNSRecord, ThreatIntel, utcnow
)
from app.recon.event_bus import event_bus
from app.recon.subdomain_scanner import SubdomainScanner
from app.recon.port_scanner import PortScanner, TOP_20_PORTS, TOP_100_PORTS
from app.recon.tech_detector import TechnologyDetector
from app.recon.ssl_analyzer import SSLAnalyzer
from app.recon.header_auditor import SecurityHeaderAuditor
from app.recon.dns_analyzer import DNSAnalyzer
from app.recon.takeover_auditor import SubdomainTakeoverAuditor
from app.intel.shodan_client import ShodanClient
from app.intel.cve_enricher import CVEEnricher
from app.ai.risk_engine import RiskEngine

logger = logging.getLogger("aegis.recon.orchestrator")


class ScanOrchestrator:
    """Manages full external attack surface reconnaissance workflow for a scan session."""

    def __init__(self, scan_id: str, target_domain: str, scan_profile: str = "standard", custom_port: Optional[int] = None):
        self.scan_id = scan_id
        # Clean domain and extract port if present
        raw = target_domain.strip().lower()
        if "://" in raw:
            from urllib.parse import urlparse
            p = urlparse(raw)
            clean = p.hostname or raw
            if not custom_port:
                custom_port = p.port
        elif ":" in raw:
            parts = raw.split(":")
            clean = parts[0].strip()
            if not custom_port:
                try:
                    custom_port = int(parts[1].split("/")[0].strip())
                except ValueError:
                    pass
        else:
            clean = raw.split("/")[0].strip()
        self.target_domain = clean
        self.custom_port = custom_port
        self.scan_profile = scan_profile  # quick, standard, deep

        # Submodules
        self.subdomain_scanner = SubdomainScanner()
        self.port_scanner = PortScanner()
        self.tech_detector = TechnologyDetector()
        self.ssl_analyzer = SSLAnalyzer()
        self.header_auditor = SecurityHeaderAuditor()
        self.dns_analyzer = DNSAnalyzer()
        self.takeover_auditor = SubdomainTakeoverAuditor()
        self.shodan_client = ShodanClient()
        self.cve_enricher = CVEEnricher()
        self.risk_engine = RiskEngine(auto_init=True)

    async def _emit_progress(self, phase: str, percent: int, message: str, db: Session, extra: Optional[Dict[str, Any]] = None):
        """Update scan phase in DB and publish real-time SSE event."""
        payload = {
            "scan_id": self.scan_id,
            "phase": phase,
            "progress_percent": percent,
            "percent": percent,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        if extra:
            payload.update(extra)

        # Update DB scan record
        scan = db.query(Scan).filter_by(id=self.scan_id).first()
        if scan:
            scan.current_phase = phase
            scan.progress_percent = percent
            scan.scan_log = (scan.scan_log or "") + f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {message}\n"
            db.commit()

        await event_bus.publish(self.scan_id, "scan_progress", payload)

    async def execute(self):
        """Executes the full end-to-end reconnaissance DAG."""
        db: Session = SessionLocal()
        logger.info(f"Initiating scan {self.scan_id} for target domain '{self.target_domain}' (profile={self.scan_profile})")

        try:
            # Update scan status to running
            scan = db.query(Scan).filter_by(id=self.scan_id).first()
            if not scan:
                logger.error(f"Scan {self.scan_id} not found in database")
                return

            scan.status = "running"
            scan.started_at = utcnow()
            db.commit()

            # =========================================================================
            # STAGE 1: Subdomain Discovery (0% - 25%)
            # =========================================================================
            await self._emit_progress(
                phase="discovering_subdomains",
                percent=5,
                message=f"Starting asset discovery for '{self.target_domain}' via CT logs and DNS enumeration...",
                db=db
            )

            include_bf = (self.scan_profile != "quick")
            discovered_raw = await self.subdomain_scanner.enumerate(
                domain=self.target_domain,
                include_bruteforce=include_bf
            )

            assets_map: Dict[str, Asset] = {}

            for item in discovered_raw:
                hostname = item["hostname"]
                ip_addr = item.get("ip_address")
                is_apex = item.get("is_apex", False)

                asset = Asset(
                    scan_id=self.scan_id,
                    hostname=hostname,
                    ip_address=ip_addr,
                    is_apex=is_apex,
                    is_live=bool(ip_addr)
                )
                db.add(asset)
                db.commit()
                db.refresh(asset)

                assets_map[hostname] = asset

                await event_bus.publish(self.scan_id, "asset_discovered", {
                    "asset_id": asset.id,
                    "hostname": hostname,
                    "ip_address": ip_addr,
                    "is_apex": is_apex
                })

            if self.target_domain not in assets_map:
                resolver = self.subdomain_scanner._get_async_resolver()
                ips = await self.subdomain_scanner.resolve_host(self.target_domain, resolver)
                asset = Asset(
                    scan_id=self.scan_id,
                    hostname=self.target_domain,
                    ip_address=ips[0] if ips else None,
                    is_apex=True,
                    is_live=bool(ips)
                )
                db.add(asset)
                db.commit()
                db.refresh(asset)
                assets_map[self.target_domain] = asset

            await self._emit_progress(
                phase="discovering_subdomains",
                percent=25,
                message=f"Discovered {len(assets_map)} assets for '{self.target_domain}'.",
                db=db,
                extra={"total_assets": len(assets_map)}
            )

            # =========================================================================
            # STAGE 2: Port Scanning (25% - 45%)
            # =========================================================================
            await self._emit_progress(
                phase="port_scanning",
                percent=30,
                message="Probing TCP ports and grabbing service banners...",
                db=db
            )

            live_assets = [a for a in assets_map.values() if a.ip_address]
            total_live = len(live_assets)

            for idx, asset in enumerate(live_assets):
                try:
                    ports_to_probe = None
                    if self.custom_port:
                        base = list(TOP_20_PORTS if self.scan_profile == "quick" else TOP_100_PORTS)
                        if self.custom_port not in base:
                            base.append(self.custom_port)
                        ports_to_probe = base

                    ports_found = await self.port_scanner.scan_host(
                        host=asset.ip_address,
                        ports=ports_to_probe,
                        profile=self.scan_profile
                    )

                    for p_data in ports_found:
                        port_obj = Port(
                            asset_id=asset.id,
                            port_number=p_data["port_number"],
                            protocol=p_data["protocol"],
                            state=p_data["state"],
                            service_name=p_data["service_name"],
                            service_version=p_data.get("service_version"),
                            banner=p_data.get("banner"),
                            is_critical=p_data.get("is_critical", False)
                        )
                        db.add(port_obj)

                    db.commit()

                    if ports_found:
                        await event_bus.publish(self.scan_id, "port_discovered", {
                            "hostname": asset.hostname,
                            "ip": asset.ip_address,
                            "open_ports": [p["port_number"] for p in ports_found]
                        })

                except Exception as e:
                    logger.warning(f"Error scanning ports for {asset.hostname}: {e}")

                step_pct = 25 + int(((idx + 1) / max(total_live, 1)) * 20)
                await self._emit_progress(
                    phase="port_scanning",
                    percent=step_pct,
                    message=f"Scanned ports for {idx + 1}/{total_live} assets...",
                    db=db
                )

            # =========================================================================
            # STAGE 3: Web Inspection (Headers, Technologies, SSL) (45% - 65%)
            # =========================================================================
            await self._emit_progress(
                phase="inspecting_assets",
                percent=48,
                message="Auditing web technologies, SSL certificates, and security headers...",
                db=db
            )

            for idx, asset in enumerate(live_assets):
                # Check if asset has HTTP/HTTPS ports open
                asset_ports = db.query(Port).filter_by(asset_id=asset.id).all()
                port_numbers = {p.port_number for p in asset_ports}

                web_port = 80
                web_ssl = False

                if self.custom_port and (self.custom_port in port_numbers or asset.is_apex or asset.hostname == self.target_domain):
                    web_port = self.custom_port
                    web_ssl = (self.custom_port in [443, 8443])
                elif 443 in port_numbers or 8443 in port_numbers:
                    web_port = 443 if 443 in port_numbers else 8443
                    web_ssl = True
                elif 80 in port_numbers:
                    web_port = 80
                    web_ssl = False
                elif 8080 in port_numbers:
                    web_port = 8080
                    web_ssl = False
                elif any(p in port_numbers for p in [8000, 8081, 8888, 3000, 5000, 4280]):
                    web_port = next(p for p in [8000, 8081, 8888, 3000, 5000, 4280] if p in port_numbers)
                    web_ssl = False

                has_web = (
                    web_ssl or
                    bool({80, 8080, 8000, 8081, 8888, 3000, 5000, 4280}.intersection(port_numbers)) or
                    (self.custom_port is not None and self.custom_port in port_numbers) or
                    asset.is_apex
                )

                if has_web or asset.is_apex:
                    # 1. Technologies
                    try:
                        techs = await self.tech_detector.detect(
                            host=asset.hostname,
                            port=web_port,
                            use_ssl=web_ssl
                        )
                        for t in techs:
                            tech_obj = Technology(
                                asset_id=asset.id,
                                name=t["name"],
                                category=t.get("category"),
                                version=t.get("version"),
                                confidence=t.get("confidence", 100),
                                is_outdated=t.get("is_outdated", False),
                                detection_method=t.get("detection_method")
                            )
                            db.add(tech_obj)
                    except Exception as e:
                        logger.debug(f"Tech detection error on {asset.hostname}: {e}")

                    # 2. Security Headers
                    try:
                        hdr_res = await self.header_auditor.audit(
                            host=asset.hostname,
                            port=web_port,
                            use_ssl=web_ssl
                        )
                        hdr_obj = SecurityHeader(
                            asset_id=asset.id,
                            grade=hdr_res["grade"],
                            score=hdr_res["score"],
                            hsts=hdr_res["hsts"],
                            csp=hdr_res["csp"],
                            x_frame_options=hdr_res["x_frame_options"],
                            x_content_type=hdr_res["x_content_type"],
                            referrer_policy=hdr_res["referrer_policy"],
                            permissions_policy=hdr_res["permissions_policy"],
                            cors_misconfigured=hdr_res["cors_misconfigured"],
                            raw_headers=hdr_res["raw_headers"]
                        )
                        db.add(hdr_obj)
                    except Exception as e:
                        logger.debug(f"Header audit error on {asset.hostname}: {e}")

                    # 3. SSL Certificate
                    if web_ssl or (443 in port_numbers):
                        try:
                            ssl_res = self.ssl_analyzer.inspect(asset.hostname, port=443 if 443 in port_numbers else web_port)
                            ssl_obj = SSLCertificate(
                                asset_id=asset.id,
                                issuer=ssl_res.get("issuer"),
                                subject=ssl_res.get("subject"),
                                valid_from=datetime.fromisoformat(ssl_res["valid_from"]) if ssl_res.get("valid_from") else None,
                                valid_to=datetime.fromisoformat(ssl_res["valid_to"]) if ssl_res.get("valid_to") else None,
                                expires_in_days=ssl_res.get("expires_in_days", 0),
                                is_expired=ssl_res.get("is_expired", False),
                                is_self_signed=ssl_res.get("is_self_signed", False),
                                has_weak_cipher=ssl_res.get("has_weak_cipher", False),
                                has_weak_protocol=ssl_res.get("has_weak_protocol", False),
                                tls_version=ssl_res.get("tls_version"),
                                cipher_suite=ssl_res.get("cipher_suite"),
                                san_entries=ssl_res.get("san_entries", [])
                            )
                            db.add(ssl_obj)
                        except Exception as e:
                            logger.debug(f"SSL analysis error on {asset.hostname}: {e}")

                    db.commit()

                step_pct = 48 + int(((idx + 1) / max(total_live, 1)) * 17)
                await self._emit_progress(
                    phase="inspecting_assets",
                    percent=step_pct,
                    message=f"Inspected web posture for {idx + 1}/{total_live} assets...",
                    db=db
                )

            # =========================================================================
            # STAGE 4: DNS Posture & Subdomain Takeovers (65% - 75%)
            # =========================================================================
            await self._emit_progress(
                phase="dns_and_takeovers",
                percent=68,
                message="Evaluating DNS security records and probing for dangling CNAME takeovers...",
                db=db
            )

            # Audit Apex DNS
            try:
                dns_res = self.dns_analyzer.analyze(self.target_domain)
                apex_asset = next((a for a in assets_map.values() if a.is_apex), None)
                target_asset_id = apex_asset.id if apex_asset else list(assets_map.values())[0].id

                for rtype, vals in dns_res.get("records", {}).items():
                    for val in vals:
                        dns_obj = DNSRecord(
                            asset_id=target_asset_id,
                            record_type=rtype,
                            record_value=val,
                            is_misconfigured=False
                        )
                        db.add(dns_obj)

                for finding in dns_res.get("findings", []):
                    dns_obj = DNSRecord(
                        asset_id=target_asset_id,
                        record_type="AUDIT",
                        record_value=finding["category"],
                        is_misconfigured=(finding["severity"] in ["high", "critical"]),
                        finding=finding["message"]
                    )
                    db.add(dns_obj)

                db.commit()
            except Exception as e:
                logger.warning(f"Error auditing DNS for {self.target_domain}: {e}")

            # Subdomain Takeovers
            for asset in assets_map.values():
                if not asset.is_apex:
                    try:
                        tk_res = await self.takeover_auditor.audit_subdomain(asset.hostname)
                        if tk_res.get("is_vulnerable"):
                            db.add(DNSRecord(
                                asset_id=asset.id,
                                record_type="CNAME",
                                record_value=tk_res.get("cname", ""),
                                is_dangling=True,
                                is_misconfigured=True,
                                finding=tk_res.get("finding")
                            ))
                            # Add vulnerability entry
                            db.add(Vulnerability(
                                asset_id=asset.id,
                                title=f"Subdomain Takeover on {asset.hostname}",
                                description=tk_res.get("finding"),
                                severity="critical",
                                cvss_score=9.8,
                                remediation=tk_res.get("remediation")
                            ))
                            db.commit()

                            await event_bus.publish(self.scan_id, "vulnerability_discovered", {
                                "hostname": asset.hostname,
                                "title": f"Subdomain Takeover ({tk_res.get('service')})",
                                "severity": "critical"
                            })
                    except Exception as e:
                        logger.debug(f"Takeover check failed for {asset.hostname}: {e}")

            # =========================================================================
            # STAGE 5: Threat Intelligence Enrichment (75% - 85%)
            # =========================================================================
            await self._emit_progress(
                phase="enriching_intel",
                percent=78,
                message="Enriching IP reputation and vulnerability intelligence (EPSS & CISA KEV)...",
                db=db
            )

            # Query Shodan InternetDB on unique IPs
            unique_ips = {a.ip_address for a in live_assets if a.ip_address}
            ip_intel_map: Dict[str, Dict[str, Any]] = {}

            for ip in unique_ips:
                try:
                    intel_res = await self.shodan_client.enrich_ip(ip)
                    if intel_res:
                        ip_intel_map[ip] = intel_res
                except Exception as e:
                    logger.debug(f"Shodan enrichment failed for {ip}: {e}")

            # Persist Shodan intelligence and CVEs
            for asset in live_assets:
                if asset.ip_address and asset.ip_address in ip_intel_map:
                    intel = ip_intel_map[asset.ip_address]
                    db.add(ThreatIntel(
                        asset_id=asset.id,
                        source=intel.get("source", "shodan"),
                        data=intel
                    ))

                    # Enrich any CVEs reported by Shodan
                    for cve_id in intel.get("vulns", []):
                        try:
                            enriched_vuln = await self.cve_enricher.enrich_cve(cve_id)
                            vuln_obj = Vulnerability(
                                asset_id=asset.id,
                                cve_id=enriched_vuln["cve_id"],
                                title=enriched_vuln["title"],
                                description=enriched_vuln.get("description"),
                                severity=enriched_vuln["severity"],
                                cvss_score=enriched_vuln.get("cvss_score"),
                                epss_score=enriched_vuln.get("epss_score"),
                                epss_percentile=enriched_vuln.get("epss_percentile"),
                                is_cisa_kev=enriched_vuln.get("is_cisa_kev", False),
                                remediation=enriched_vuln.get("remediation"),
                                references=enriched_vuln.get("references", [])
                            )
                            db.add(vuln_obj)
                        except Exception as e:
                            logger.debug(f"CVE enrichment failed for {cve_id}: {e}")

                    db.commit()

            # =========================================================================
            # STAGE 6: AI/ML Risk Scoring & SHAP Explanations (85% - 95%)
            # =========================================================================
            await self._emit_progress(
                phase="scoring_risk",
                percent=88,
                message="Executing XGBoost ML risk model and computing TreeSHAP factor attributions...",
                db=db
            )

            scores: List[float] = []

            for asset in assets_map.values():
                # Explicitly query child entities to ensure all findings are fresh
                asset_ports = db.query(Port).filter_by(asset_id=asset.id).all()
                asset_ssl = db.query(SSLCertificate).filter_by(asset_id=asset.id).first()
                asset_hdr = db.query(SecurityHeader).filter_by(asset_id=asset.id).first()
                asset_dns = db.query(DNSRecord).filter_by(asset_id=asset.id).all()
                asset_vulns = db.query(Vulnerability).filter_by(asset_id=asset.id).all()
                asset_techs = db.query(Technology).filter_by(asset_id=asset.id).all()

                asset_data = {
                    "is_apex": asset.is_apex,
                    "ports": asset_ports,
                    "ssl_cert": asset_ssl,
                    "security_headers": asset_hdr,
                    "dns_records": asset_dns,
                    "vulnerabilities": asset_vulns,
                    "technologies": asset_techs
                }

                scored = self.risk_engine.score_asset(asset_data)
                asset.risk_score = scored["risk_score"]
                asset.risk_level = scored["risk_level"]
                asset.shap_explanation = scored["shap_explanation"]
                db.commit()

                scores.append(scored["risk_score"])

                await event_bus.publish(self.scan_id, "risk_scored", {
                    "hostname": asset.hostname,
                    "risk_score": scored["risk_score"],
                    "risk_level": scored["risk_level"],
                    "summary": scored["shap_explanation"].get("summary")
                })

            # =========================================================================
            # STAGE 7: Finalize & Summary Aggregation (100%)
            # =========================================================================
            total_assets = len(scores)
            avg_score = float(sum(scores) / max(total_assets, 1))
            max_score = float(max(scores)) if scores else 0.0

            scan = db.query(Scan).filter_by(id=self.scan_id).first()
            if scan:
                scan.status = "completed"
                scan.progress_percent = 100
                scan.current_phase = "completed"
                scan.total_assets = total_assets
                scan.avg_risk_score = round(avg_score, 1)
                scan.max_risk_score = round(max_score, 1)
                scan.critical_count = sum(1 for s in scores if s >= 80.0)
                scan.high_count = sum(1 for s in scores if 60.0 <= s < 80.0)
                scan.medium_count = sum(1 for s in scores if 40.0 <= s < 60.0)
                scan.low_count = sum(1 for s in scores if 20.0 <= s < 40.0)
                scan.info_count = sum(1 for s in scores if s < 20.0)
                scan.completed_at = utcnow()
                db.commit()

            final_summary = {
                "scan_id": self.scan_id,
                "status": "completed",
                "total_assets": total_assets,
                "avg_risk_score": round(avg_score, 1),
                "max_risk_score": round(max_score, 1),
                "critical_count": scan.critical_count if scan else 0,
                "high_count": scan.high_count if scan else 0,
                "completed_at": datetime.now(timezone.utc).isoformat()
            }

            await self._emit_progress(
                phase="completed",
                percent=100,
                message=f"Scan completed successfully. Monitored {total_assets} assets with average risk score {avg_score:.1f}/100.",
                db=db,
                extra=final_summary
            )

            await event_bus.publish(self.scan_id, "scan_completed", final_summary)
            logger.info(f"Scan {self.scan_id} successfully completed for '{self.target_domain}'")

        except Exception as e:
            logger.exception(f"Fatal error during scan execution {self.scan_id}: {e}")
            scan = db.query(Scan).filter_by(id=self.scan_id).first()
            if scan:
                scan.status = "failed"
                scan.error_message = str(e)
                scan.completed_at = utcnow()
                db.commit()

            await event_bus.publish(self.scan_id, "scan_failed", {
                "scan_id": self.scan_id,
                "error": str(e)
            })
        finally:
            db.close()


def launch_scan_background(scan_id: str, target_domain: str, scan_profile: str = "standard", custom_port: Optional[int] = None) -> asyncio.Task:
    """Helper to launch a scan orchestrator as a detached background task."""
    orchestrator = ScanOrchestrator(scan_id=scan_id, target_domain=target_domain, scan_profile=scan_profile, custom_port=custom_port)
    return asyncio.create_task(orchestrator.execute())

