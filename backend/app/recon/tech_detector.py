"""AEGIS Reconnaissance Engine — Technology Fingerprinting Module

Identifies web frameworks, CMSs, web servers, CDNs, and libraries via HTTP headers,
HTML DOM/regex inspection, and Shodan-compatible MurmurHash3 favicon hashing.
"""
import base64
import logging
import re
from typing import List, Dict, Any, Optional
import httpx
import mmh3

logger = logging.getLogger("aegis.recon.tech")

# MurmurHash3 Favicon Signatures Database
FAVICON_HASHES: Dict[int, Dict[str, str]] = {
    81586312: {"name": "Jenkins", "category": "CI/CD"},
    -1854810269: {"name": "Grafana", "category": "Monitoring"},
    116323821: {"name": "Spring Boot", "category": "Backend Framework"},
    -1293291880: {"name": "Apache Tomcat", "category": "Web Server"},
    -1184861099: {"name": "Kibana", "category": "Monitoring"},
    442749392: {"name": "Jira", "category": "Project Management"},
    -1349514781: {"name": "GitLab", "category": "Version Control"},
    -1250275822: {"name": "WordPress", "category": "CMS"},
    -1875151523: {"name": "phpMyAdmin", "category": "Database Admin"},
    -1257493294: {"name": "Drupal", "category": "CMS"},
    -1559445102: {"name": "Django", "category": "Backend Framework"},
    -956894089: {"name": "Swagger UI", "category": "API Documentation"},
    1096738722: {"name": "Plesk", "category": "Hosting Panel"},
    -1277154546: {"name": "cPanel", "category": "Hosting Panel"},
    -1011681729: {"name": "RabbitMQ", "category": "Message Broker"},
    -669116886: {"name": "Kubernetes Dashboard", "category": "Container Management"},
}

# Rule-based Technology Detection Signatures
TECH_SIGNATURES = [
    {
        "name": "WordPress",
        "category": "CMS",
        "headers": {},
        "html_regex": [r"/wp-content/", r"/wp-includes/", r"wp-json"],
        "meta": {"generator": r"WordPress"},
        "cookies": [r"wordpress_", r"wp-settings-"]
    },
    {
        "name": "Next.js",
        "category": "Frontend Framework",
        "headers": {"x-powered-by": r"Next\.js"},
        "html_regex": [r"/_next/static/", r"<div id=\"__next\">", r"__NEXT_DATA__"],
        "meta": {},
        "cookies": []
    },
    {
        "name": "React",
        "category": "Frontend Library",
        "headers": {},
        "html_regex": [r"react-dom", r"__reactFiber", r"react\.production\.min\.js"],
        "meta": {},
        "cookies": []
    },
    {
        "name": "Vue.js",
        "category": "Frontend Library",
        "headers": {},
        "html_regex": [r"vue\.min\.js", r"vue\.runtime", r"data-v-[a-f0-9]+"],
        "meta": {},
        "cookies": []
    },
    {
        "name": "Angular",
        "category": "Frontend Framework",
        "headers": {},
        "html_regex": [r"<app-root", r"ng-version", r"zone\.js"],
        "meta": {},
        "cookies": []
    },
    {
        "name": "Laravel",
        "category": "Backend Framework",
        "headers": {},
        "html_regex": [r"window\.Laravel"],
        "meta": {},
        "cookies": [r"laravel_session", r"XSRF-TOKEN"]
    },
    {
        "name": "Django",
        "category": "Backend Framework",
        "headers": {},
        "html_regex": [r"csrfmiddlewaretoken"],
        "meta": {},
        "cookies": [r"csrftoken"]
    },
    {
        "name": "Express",
        "category": "Backend Framework",
        "headers": {"x-powered-by": r"Express"},
        "html_regex": [],
        "meta": {},
        "cookies": []
    },
    {
        "name": "Nginx",
        "category": "Web Server",
        "headers": {"server": r"nginx(?:/([0-9.]+))?"},
        "html_regex": [],
        "meta": {},
        "cookies": []
    },
    {
        "name": "Apache",
        "category": "Web Server",
        "headers": {"server": r"Apache(?:/([0-9.]+))?"},
        "html_regex": [],
        "meta": {},
        "cookies": []
    },
    {
        "name": "Cloudflare",
        "category": "CDN / WAF",
        "headers": {"server": r"cloudflare", "cf-ray": r".+"},
        "html_regex": [],
        "meta": {},
        "cookies": [r"__cf_bm"]
    },
    {
        "name": "Swagger UI",
        "category": "API Documentation",
        "headers": {},
        "html_regex": [r"swagger-ui\.css", r"SwaggerUIBundle", r"id=\"swagger-ui\""],
        "meta": {},
        "cookies": []
    },
    {
        "name": "Shopify",
        "category": "E-Commerce",
        "headers": {"x-shopid": r".+"},
        "html_regex": [r"cdn\.shopify\.com", r"Shopify\.theme"],
        "meta": {},
        "cookies": []
    }
]


class TechnologyDetector:
    """Performs deep web technology fingerprinting."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    async def compute_favicon_hash(self, base_url: str) -> Optional[int]:
        """
        Calculates Shodan-compatible MurmurHash3 from target's /favicon.ico.
        Uses RFC 2048 76-character line wrapping before hashing.
        """
        fav_url = f"{base_url.rstrip('/')}/favicon.ico"
        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(fav_url)
                if resp.status_code == 200 and len(resp.content) > 0:
                    b64_content = base64.encodebytes(resp.content)
                    return mmh3.hash(b64_content)
        except Exception:
            pass
        return None

    def _check_outdated(self, name: str, version: Optional[str]) -> bool:
        """Determines if a given software version is known to be severely outdated or EOL."""
        if not version:
            return False
        try:
            parts = [int(p) for p in re.findall(r"\d+", version)[:2]]
            if len(parts) >= 1:
                major = parts[0]
                minor = parts[1] if len(parts) > 1 else 0

                if name == "Apache" and (major < 2 or (major == 2 and minor < 4)):
                    return True
                if name == "Nginx" and (major < 1 or (major == 1 and minor < 18)):
                    return True
                if name == "PHP" and major < 8:
                    return True
                if name == "WordPress" and major < 6:
                    return True
                if name == "jQuery" and major < 3:
                    return True
        except Exception:
            pass
        return False

    async def detect(self, host: str, port: int = 443, use_ssl: bool = True) -> List[Dict[str, Any]]:
        """
        Analyzes a web service on host:port and returns all detected technologies.
        """
        protocol = "https" if use_ssl or port in [443, 8443] else "http"
        target_url = f"{protocol}://{host}:{port}" if port not in [80, 443] else f"{protocol}://{host}"

        detected: Dict[str, Dict[str, Any]] = {}

        # 1. Fetch Homepage
        headers = {}
        cookies = {}
        body = ""
        status_code = None

        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(target_url, headers={"User-Agent": "Mozilla/5.0 AEGIS-TechDetector/1.0"})
                headers = {k.lower(): v for k, v in resp.headers.items()}
                cookies = {k.lower(): v for k, v in resp.cookies.items()}
                body = resp.text[:150000]  # First 150KB
                status_code = resp.status_code
        except Exception as e:
            logger.debug(f"HTTP request to {target_url} failed: {e}")
            # If HTTPS failed, try HTTP on port 80 if on 443
            if protocol == "https" and port == 443:
                return await self.detect(host, port=80, use_ssl=False)
            return []

        # 2. Match against Signatures
        for sig in TECH_SIGNATURES:
            name = sig["name"]
            matched = False
            version = None
            method = "heuristic"

            # Check Headers
            for h_key, pattern in sig["headers"].items():
                if h_key in headers:
                    m = re.search(pattern, headers[h_key], re.IGNORECASE)
                    if m:
                        matched = True
                        method = f"Header: {h_key}"
                        if m.groups() and m.group(1):
                            version = m.group(1)

            # Check Cookies
            if not matched and sig.get("cookies"):
                for cookie_pattern in sig["cookies"]:
                    for c_name in cookies.keys():
                        if re.search(cookie_pattern, c_name, re.IGNORECASE):
                            matched = True
                            method = f"Cookie: {c_name}"

            # Check HTML regex
            if not matched and body:
                for regex in sig["html_regex"]:
                    if re.search(regex, body, re.IGNORECASE):
                        matched = True
                        method = "HTML Pattern"
                        break

            # Check Meta tags
            if not matched and body and sig.get("meta"):
                for meta_name, meta_val in sig["meta"].items():
                    meta_pattern = rf'<meta\s+name=["\']{meta_name}["\']\s+content=["\']([^"\']*{meta_val}[^"\']*)["\']'
                    m = re.search(meta_pattern, body, re.IGNORECASE)
                    if m:
                        matched = True
                        method = f"Meta: {meta_name}"
                        # Try to extract version from content
                        ver_match = re.search(r"([0-9]+(?:\.[0-9]+)+)", m.group(1))
                        if ver_match:
                            version = ver_match.group(1)

            if matched:
                detected[name] = {
                    "name": name,
                    "category": sig["category"],
                    "version": version,
                    "confidence": 100 if version or "Header" in method else 85,
                    "is_outdated": self._check_outdated(name, version),
                    "detection_method": method
                }

        # 3. Favicon MurmurHash3 Detection
        fav_hash = await self.compute_favicon_hash(target_url)
        if fav_hash and fav_hash in FAVICON_HASHES:
            fav_info = FAVICON_HASHES[fav_hash]
            name = fav_info["name"]
            detected[name] = {
                "name": name,
                "category": fav_info["category"],
                "version": None,
                "confidence": 95,
                "is_outdated": False,
                "detection_method": f"Favicon mmh3 ({fav_hash})"
            }

        return list(detected.values())
