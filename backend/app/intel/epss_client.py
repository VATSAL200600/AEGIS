"""AEGIS Threat Intelligence — FIRST.org EPSS (Exploit Prediction Scoring System) Client

Queries the FIRST.org EPSS API to assess the probability that a specific CVE
will be actively exploited in the wild within 30 days. Includes in-memory caching.
"""
import asyncio
import logging
import time
from typing import Dict, List, Optional, Any
import httpx

logger = logging.getLogger("aegis.intel.epss")

EPSS_API_URL = "https://api.first.org/data/v1/epss"


class EPSSClient:
    """Client for the FIRST.org EPSS REST API with caching and batch query support."""

    def __init__(self, timeout: float = 6.0, cache_ttl_seconds: int = 86400):
        self.timeout = timeout
        self.cache_ttl = cache_ttl_seconds
        # In-memory cache: cve_id -> {"epss": float, "percentile": float, "cached_at": timestamp}
        self._cache: Dict[str, Dict[str, Any]] = {}

    def _get_cached(self, cve_id: str) -> Optional[Dict[str, float]]:
        """Retrieve from cache if entry is not expired."""
        cve_upper = cve_id.strip().upper()
        if cve_upper in self._cache:
            entry = self._cache[cve_upper]
            if time.time() - entry["cached_at"] < self.cache_ttl:
                return {"epss": entry["epss"], "percentile": entry["percentile"]}
        return None

    def _set_cached(self, cve_id: str, epss: float, percentile: float):
        """Store in cache with current timestamp."""
        cve_upper = cve_id.strip().upper()
        self._cache[cve_upper] = {
            "epss": epss,
            "percentile": percentile,
            "cached_at": time.time(),
        }

    async def get_epss(self, cve_id: str) -> Dict[str, float]:
        """
        Fetch EPSS score for a single CVE ID (e.g. 'CVE-2021-44228').
        Returns dict with 'epss' (0.0 to 1.0) and 'percentile' (0.0 to 1.0).
        """
        cve_upper = cve_id.strip().upper()
        cached = self._get_cached(cve_upper)
        if cached:
            return cached

        results = await self.get_epss_batch([cve_upper])
        return results.get(cve_upper, {"epss": 0.0, "percentile": 0.0})

    async def get_epss_batch(self, cve_ids: List[str]) -> Dict[str, Dict[str, float]]:
        """
        Fetch EPSS scores for multiple CVE IDs in chunks of up to 50.
        """
        results: Dict[str, Dict[str, float]] = {}
        missing_cves: List[str] = []

        for cve in cve_ids:
            cve_upper = cve.strip().upper()
            cached = self._get_cached(cve_upper)
            if cached:
                results[cve_upper] = cached
            else:
                missing_cves.append(cve_upper)

        if not missing_cves:
            return results

        # Process missing CVEs in chunks of 50
        chunk_size = 50
        for i in range(0, len(missing_cves), chunk_size):
            chunk = missing_cves[i : i + chunk_size]
            cve_param = ",".join(chunk)
            url = f"{EPSS_API_URL}?cve={cve_param}"

            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.get(url, headers={"User-Agent": "AEGIS-ASM/1.0"})
                    if resp.status_code == 200:
                        data = resp.json()
                        for item in data.get("data", []):
                            cve_name = item.get("cve", "").upper()
                            try:
                                epss_val = float(item.get("epss", 0.0))
                                perc_val = float(item.get("percentile", 0.0))
                            except (ValueError, TypeError):
                                epss_val, perc_val = 0.0, 0.0

                            entry = {"epss": round(epss_val, 5), "percentile": round(perc_val, 5)}
                            results[cve_name] = entry
                            self._set_cached(cve_name, entry["epss"], entry["percentile"])
            except Exception as e:
                logger.warning(f"Failed to query EPSS API for chunk: {e}")

        # Fill any remaining unqueried with zeros
        for cve in missing_cves:
            if cve not in results:
                results[cve] = {"epss": 0.0, "percentile": 0.0}

        return results
