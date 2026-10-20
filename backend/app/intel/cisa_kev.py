"""AEGIS Threat Intelligence — CISA Known Exploited Vulnerabilities (KEV) Catalog

Maintains an indexed catalog of vulnerabilities actively exploited by threat actors
in the wild, backed by disk cache and offline fallback seeds.
"""
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Set
import httpx

logger = logging.getLogger("aegis.intel.cisa_kev")

CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DATA_DIR = Path(__file__).resolve().parent / "data"
CACHE_FILE = DATA_DIR / "cisa_kev.json"

# High-profile seed CVEs for offline/air-gapped operation
FALLBACK_KEV_SEEDS = {
    "CVE-2021-44228": {
        "cveID": "CVE-2021-44228",
        "vendorProject": "Apache",
        "product": "Log4j",
        "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
        "dateAdded": "2021-12-10",
        "requiredAction": "Apply updates per vendor instructions.",
        "knownRansomwareCampaignUse": "Known"
    },
    "CVE-2017-0144": {
        "cveID": "CVE-2017-0144",
        "vendorProject": "Microsoft",
        "product": "SMBv1",
        "vulnerabilityName": "Microsoft SMBv1 Remote Code Execution (EternalBlue)",
        "dateAdded": "2022-02-10",
        "requiredAction": "Apply updates per vendor instructions.",
        "knownRansomwareCampaignUse": "Known"
    },
    "CVE-2019-19781": {
        "cveID": "CVE-2019-19781",
        "vendorProject": "Citrix",
        "product": "ADC and Gateway",
        "vulnerabilityName": "Citrix ADC and Gateway Directory Traversal",
        "dateAdded": "2021-11-03",
        "requiredAction": "Apply updates per vendor instructions.",
        "knownRansomwareCampaignUse": "Known"
    },
    "CVE-2023-34362": {
        "cveID": "CVE-2023-34362",
        "vendorProject": "Progress",
        "product": "MOVEit Transfer",
        "vulnerabilityName": "Progress MOVEit Transfer SQL Injection Vulnerability",
        "dateAdded": "2023-06-02",
        "requiredAction": "Apply updates per vendor instructions.",
        "knownRansomwareCampaignUse": "Known"
    },
    "CVE-2023-4966": {
        "cveID": "CVE-2023-4966",
        "vendorProject": "Citrix",
        "product": "NetScaler ADC and NetScaler Gateway",
        "vulnerabilityName": "Citrix NetScaler ADC and Gateway Sensitive Information Disclosure (CitrixBleed)",
        "dateAdded": "2023-10-18",
        "requiredAction": "Apply updates per vendor instructions.",
        "knownRansomwareCampaignUse": "Known"
    },
    "CVE-2024-1709": {
        "cveID": "CVE-2024-1709",
        "vendorProject": "ConnectWise",
        "product": "ScreenConnect",
        "vulnerabilityName": "ConnectWise ScreenConnect Authentication Bypass Vulnerability",
        "dateAdded": "2024-02-21",
        "requiredAction": "Apply updates per vendor instructions.",
        "knownRansomwareCampaignUse": "Known"
    }
}


class CISAKEVManager:
    """Manages the CISA KEV catalog with in-memory O(1) lookups and local file caching."""

    def __init__(self):
        self._kev_catalog: Dict[str, Dict[str, Any]] = {}
        self._kev_cve_set: Set[str] = set()
        self.load_catalog()

    def load_catalog(self) -> int:
        """Loads catalog from local disk cache or fallback seeds."""
        DATA_DIR.mkdir(parents=True, exist_ok=True)

        if CACHE_FILE.exists():
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    vulns = data.get("vulnerabilities", [])
                    for v in vulns:
                        cve = v.get("cveID", "").upper()
                        if cve:
                            self._kev_catalog[cve] = v
                            self._kev_cve_set.add(cve)
                    logger.info(f"Loaded {len(self._kev_cve_set)} CISA KEV entries from local disk cache")
                    return len(self._kev_cve_set)
            except Exception as e:
                logger.warning(f"Failed to read KEV disk cache: {e}")

        # Fallback to embedded seed catalog
        for cve, info in FALLBACK_KEV_SEEDS.items():
            self._kev_catalog[cve] = info
            self._kev_cve_set.add(cve)

        logger.info(f"Initialized KEV with {len(self._kev_cve_set)} fallback seed entries")
        return len(self._kev_cve_set)

    async def update_from_cisa(self, timeout: float = 10.0) -> bool:
        """
        Downloads the latest KEV catalog from CISA and updates disk cache.
        """
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(CISA_KEV_FEED_URL, headers={"User-Agent": "AEGIS-ASM/1.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    vulns = data.get("vulnerabilities", [])
                    if vulns:
                        # Write to local cache
                        DATA_DIR.mkdir(parents=True, exist_ok=True)
                        with open(CACHE_FILE, "w", encoding="utf-8") as f:
                            json.dump(data, f, indent=2)

                        # Update in-memory index
                        new_catalog: Dict[str, Dict[str, Any]] = {}
                        new_set: Set[str] = set()
                        for v in vulns:
                            cve = v.get("cveID", "").upper()
                            if cve:
                                new_catalog[cve] = v
                                new_set.add(cve)

                        self._kev_catalog = new_catalog
                        self._kev_cve_set = new_set
                        logger.info(f"Successfully updated KEV catalog from CISA ({len(new_set)} entries)")
                        return True
        except Exception as e:
            logger.warning(f"Could not update KEV from CISA feed: {e}")

        return False

    def is_in_kev(self, cve_id: str) -> bool:
        """O(1) membership check for whether a CVE is in the CISA KEV catalog."""
        return cve_id.strip().upper() in self._kev_cve_set

    def get_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Returns KEV details for a CVE, or None if not listed."""
        return self._kev_catalog.get(cve_id.strip().upper())


# Global singleton instance
cisa_kev = CISAKEVManager()
