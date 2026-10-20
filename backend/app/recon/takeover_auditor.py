"""AEGIS Reconnaissance Engine — Subdomain Takeover Auditor

Audits discovered assets for dangling CNAME records pointing to unclaimed third-party
cloud infrastructure (AWS S3, GitHub Pages, Heroku, Azure, Shopify, etc.).
"""
import logging
import re
from typing import Dict, Any, List, Optional
import httpx
import dns.resolver

logger = logging.getLogger("aegis.recon.takeover")

# Comprehensive Cloud Provider Takeover Fingerprints Database
TAKEOVER_SIGNATURES: List[Dict[str, Any]] = [
    {
        "service": "GitHub Pages",
        "cname_suffix": [".github.io"],
        "response_regex": r"There isn't a GitHub Pages site here\.",
        "status_code": [404]
    },
    {
        "service": "Amazon S3",
        "cname_suffix": [".s3.amazonaws.com", ".s3-website", ".s3.dualstack"],
        "response_regex": r"<Code>NoSuchBucket</Code>",
        "status_code": [404]
    },
    {
        "service": "Heroku",
        "cname_suffix": [".herokuapp.com", ".herokudns.com"],
        "response_regex": r"(?:No such app|herokucdn\.com/error-pages/no-such-app\.html)",
        "status_code": [503, 404]
    },
    {
        "service": "Azure App Service",
        "cname_suffix": [".azurewebsites.net", ".azurewebsites.windows.net"],
        "response_regex": r"404 Web Site not found",
        "status_code": [404]
    },
    {
        "service": "Shopify",
        "cname_suffix": [".myshopify.com"],
        "response_regex": r"Sorry, this shop is currently unavailable",
        "status_code": [404]
    },
    {
        "service": "Surge.sh",
        "cname_suffix": [".surge.sh"],
        "response_regex": r"project not found",
        "status_code": [404]
    },
    {
        "service": "Ghost",
        "cname_suffix": [".ghost.io"],
        "response_regex": r"The thing you were looking for is no longer here",
        "status_code": [404]
    },
    {
        "service": "Pantheon",
        "cname_suffix": [".pantheonsite.io"],
        "response_regex": r"404 error unknown site!",
        "status_code": [404]
    },
    {
        "service": "Fastly",
        "cname_suffix": [".fastly.net", ".fastlylb.net"],
        "response_regex": r"Fastly error: unknown domain",
        "status_code": [500, 404]
    },
    {
        "service": "Bitbucket",
        "cname_suffix": [".bitbucket.io"],
        "response_regex": r"Repository not found",
        "status_code": [404]
    },
    {
        "service": "Readme.io",
        "cname_suffix": [".readme.io"],
        "response_regex": r"Project doesnt exist",
        "status_code": [404]
    },
    {
        "service": "Zendesk",
        "cname_suffix": [".zendesk.com"],
        "response_regex": r"Help Center Closed",
        "status_code": [404]
    },
    {
        "service": "WordPress.com",
        "cname_suffix": [".wordpress.com"],
        "response_regex": r"Do you want to register",
        "status_code": [301, 302, 404]
    },
    {
        "service": "Helpjuice",
        "cname_suffix": [".helpjuice.com"],
        "response_regex": r"We could not find what you're looking for",
        "status_code": [404]
    },
    {
        "service": "Webflow",
        "cname_suffix": [".proxy.webflow.com", ".proxy.webflow.io"],
        "response_regex": r"The page you are looking for doesn't exist or has been moved",
        "status_code": [404]
    },
    {
        "service": "Cargo Collective",
        "cname_suffix": [".cargocollective.com"],
        "response_regex": r"404 Not Found",
        "status_code": [404]
    },
    {
        "service": "Unbounce",
        "cname_suffix": [".unbouncepages.com"],
        "response_regex": r"The requested URL was not found on this server",
        "status_code": [404]
    }
]


class SubdomainTakeoverAuditor:
    """Detects dangling CNAME records vulnerable to external account hijacking."""

    def __init__(self, timeout: float = 4.0, resolver: Optional[dns.resolver.Resolver] = None):
        self.timeout = timeout
        self.resolver = resolver or dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def resolve_cname(self, hostname: str) -> Optional[str]:
        """Resolve CNAME record for a hostname."""
        try:
            answers = self.resolver.resolve(hostname, "CNAME")
            for a in answers:
                return a.target.to_text().rstrip(".").lower()
        except Exception:
            pass
        return None

    async def audit_subdomain(self, hostname: str) -> Dict[str, Any]:
        """
        Tests whether hostname has a dangling CNAME vulnerable to subdomain takeover.
        """
        hostname = hostname.strip().lower()
        cname = self.resolve_cname(hostname)

        if not cname:
            return {
                "hostname": hostname,
                "cname": None,
                "is_vulnerable": False,
                "service": None,
                "finding": None
            }

        # Check if CNAME matches any cloud provider
        matching_sig = None
        for sig in TAKEOVER_SIGNATURES:
            for suffix in sig["cname_suffix"]:
                if cname.endswith(suffix):
                    matching_sig = sig
                    break
            if matching_sig:
                break

        if not matching_sig:
            return {
                "hostname": hostname,
                "cname": cname,
                "is_vulnerable": False,
                "service": None,
                "finding": f"CNAME points to '{cname}' (no known takeover signature)."
            }

        service_name = matching_sig["service"]

        # Probe HTTP and HTTPS endpoints for error fingerprint
        for protocol in ["https", "http"]:
            url = f"{protocol}://{hostname}"
            try:
                async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=True) as client:
                    resp = await client.get(url, headers={"User-Agent": "AEGIS-TakeoverAuditor/1.0"})
                    status = resp.status_code
                    body = resp.text

                    if status in matching_sig["status_code"] or not matching_sig["status_code"]:
                        if re.search(matching_sig["response_regex"], body, re.IGNORECASE):
                            return {
                                "hostname": hostname,
                                "cname": cname,
                                "is_vulnerable": True,
                                "service": service_name,
                                "confidence": "HIGH",
                                "finding": (
                                    f"CRITICAL: Subdomain '{hostname}' points to an unclaimed {service_name} resource "
                                    f"via CNAME '{cname}'. An attacker can claim this resource to hijack the domain."
                                ),
                                "remediation": f"Immediately claim the {service_name} resource or remove the '{cname}' CNAME DNS record."
                            }
            except Exception:
                continue

        return {
            "hostname": hostname,
            "cname": cname,
            "is_vulnerable": False,
            "service": service_name,
            "finding": f"CNAME points to {service_name} ({cname}), but the service is currently claimed/active."
        }
