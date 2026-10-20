"""AEGIS Threat Intelligence — Shodan InternetDB & Shodan REST Client

Queries the free, zero-key Shodan InternetDB API (or full Shodan API when key is provided)
to discover known open ports, vulnerabilities (CVEs), CPEs, and hostnames for public IPs.
"""
import ipaddress
import logging
from typing import Dict, Any, List, Optional
import httpx
from app.config import settings

logger = logging.getLogger("aegis.intel.shodan")

INTERNETDB_URL = "https://internetdb.shodan.io"
SHODAN_HOST_URL = "https://api.shodan.io/shodan/host"


class ShodanClient:
    """Enriches IP addresses with intelligence via Shodan InternetDB and REST API."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.api_key = settings.SHODAN_API_KEY

    def is_public_ip(self, ip_str: str) -> bool:
        """Verify whether an IP is a valid, globally-routable public IPv4/IPv6 address."""
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            return ip_obj.is_global
        except ValueError:
            return False

    async def lookup_internetdb(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Queries free Shodan InternetDB (zero API key needed).
        Returns ports, vulns, cpes, and hostnames.
        """
        if not self.is_public_ip(ip):
            logger.debug(f"Skipping InternetDB query for non-public IP: {ip}")
            return None

        url = f"{INTERNETDB_URL}/{ip.strip()}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers={"User-Agent": "AEGIS-ASM/1.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "ip": data.get("ip", ip),
                        "ports": sorted(data.get("ports", [])),
                        "vulns": sorted(data.get("vulns", [])),
                        "cpes": data.get("cpes", []),
                        "hostnames": data.get("hostnames", []),
                        "tags": data.get("tags", []),
                        "source": "shodan_internetdb"
                    }
                elif resp.status_code == 404:
                    # IP not indexed in InternetDB
                    return {
                        "ip": ip,
                        "ports": [],
                        "vulns": [],
                        "cpes": [],
                        "hostnames": [],
                        "tags": [],
                        "source": "shodan_internetdb"
                    }
        except Exception as e:
            logger.warning(f"InternetDB lookup failed for {ip}: {e}")

        return None

    async def lookup_shodan_api(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Queries official Shodan API if user configured SHODAN_API_KEY.
        """
        if not self.api_key or not self.is_public_ip(ip):
            return None

        url = f"{SHODAN_HOST_URL}/{ip.strip()}?key={self.api_key}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers={"User-Agent": "AEGIS-ASM/1.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "ip": ip,
                        "ports": sorted(data.get("ports", [])),
                        "vulns": sorted(list(data.get("vulns", []))),
                        "org": data.get("org"),
                        "isp": data.get("isp"),
                        "country_name": data.get("country_name"),
                        "city": data.get("city"),
                        "hostnames": data.get("hostnames", []),
                        "source": "shodan_api"
                    }
        except Exception as e:
            logger.warning(f"Shodan API lookup failed for {ip}: {e}")

        return None

    async def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """
        Full IP enrichment fallback pipeline:
        1. Query full Shodan API if key is present.
        2. Fall back to free Shodan InternetDB.
        """
        # Try full API first if key configured
        if self.api_key:
            res = await self.lookup_shodan_api(ip)
            if res:
                return res

        # Free InternetDB lookup
        res = await self.lookup_internetdb(ip)
        if res:
            return res

        return {
            "ip": ip,
            "ports": [],
            "vulns": [],
            "cpes": [],
            "hostnames": [],
            "tags": [],
            "source": "none"
        }
