"""AEGIS Threat Intelligence — CVE Enrichment Coordinator

Unifies CVSS severity scoring, FIRST.org EPSS exploit probability,
and CISA Known Exploited Vulnerabilities (KEV) status into a consolidated vulnerability dossier.
"""
import logging
from typing import Dict, Any, List, Optional
from app.intel.epss_client import EPSSClient
from app.intel.cisa_kev import cisa_kev

logger = logging.getLogger("aegis.intel.enricher")


class CVEEnricher:
    """Coordinates enrichment of detected CVE identifiers with EPSS and CISA KEV."""

    def __init__(self, epss_client: Optional[EPSSClient] = None):
        self.epss_client = epss_client or EPSSClient()
        self.kev_manager = cisa_kev

    def infer_severity(self, cvss: Optional[float], is_kev: bool, epss: float) -> str:
        """Determines unified severity based on CVSS score, active exploitation, and EPSS."""
        if is_kev or epss >= 0.70 or (cvss is not None and cvss >= 9.0):
            return "critical"
        if (cvss is not None and cvss >= 7.0) or epss >= 0.35:
            return "high"
        if (cvss is not None and cvss >= 4.0) or epss >= 0.10:
            return "medium"
        return "low"

    async def enrich_cve(
        self,
        cve_id: str,
        cvss_score: Optional[float] = None,
        title: Optional[str] = None,
        description: Optional[str] = None,
        affected_component: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Enriches a single CVE ID with EPSS exploit probability and CISA KEV status.
        """
        cve_upper = cve_id.strip().upper()

        # 1. Query EPSS
        epss_data = await self.epss_client.get_epss(cve_upper)
        epss_score = epss_data.get("epss", 0.0)
        epss_percentile = epss_data.get("percentile", 0.0)

        # 2. Check CISA KEV
        is_kev = self.kev_manager.is_in_kev(cve_upper)
        kev_details = self.kev_manager.get_details(cve_upper) if is_kev else None

        # 3. Determine severity and title
        severity = self.infer_severity(cvss_score, is_kev, epss_score)

        if not title:
            if kev_details and kev_details.get("vulnerabilityName"):
                title = kev_details["vulnerabilityName"]
            else:
                title = f"Vulnerability {cve_upper}"

        if not description and kev_details:
            description = (
                f"{kev_details.get('vulnerabilityName')}. "
                f"Action required: {kev_details.get('requiredAction', 'Patch immediately')}."
            )

        remediation = "Apply the latest security patches provided by the software vendor immediately."
        if kev_details:
            remediation = f"CISA KEV Mandatory Remediation: {kev_details.get('requiredAction')}"

        references = [f"https://nvd.nist.gov/vuln/detail/{cve_upper}"]
        if is_kev:
            references.append("https://www.cisa.gov/known-exploited-vulnerabilities-catalog")

        return {
            "cve_id": cve_upper,
            "title": title,
            "description": description,
            "severity": severity,
            "cvss_score": cvss_score or (9.8 if is_kev else None),
            "epss_score": epss_score,
            "epss_percentile": epss_percentile,
            "is_cisa_kev": is_kev,
            "affected_component": affected_component,
            "remediation": remediation,
            "references": references,
            "ransomware_use": kev_details.get("knownRansomwareCampaignUse") if kev_details else "Unknown"
        }

    async def enrich_batch(self, cve_ids: List[str]) -> List[Dict[str, Any]]:
        """Batch enriches multiple CVEs efficiently."""
        if not cve_ids:
            return []

        # Pre-fetch all EPSS scores in batch
        await self.epss_client.get_epss_batch(cve_ids)

        tasks = [self.enrich_cve(cve) for cve in set(cve_ids)]
        return await asyncio.gather(*tasks)
