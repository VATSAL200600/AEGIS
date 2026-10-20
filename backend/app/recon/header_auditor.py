"""AEGIS Reconnaissance Engine — Security Headers & CORS Auditor

Audits HTTP response headers against OWASP security best practices,
computes a letter grade (A+ to F), and tests for arbitrary CORS origin reflection.
"""
import logging
from typing import Dict, Any, List, Optional
import httpx

logger = logging.getLogger("aegis.recon.headers")


class SecurityHeaderAuditor:
    """Evaluates security headers and CORS policy posture for a web service."""

    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout

    def calculate_grade(self, score: int) -> str:
        """Map a numeric 0-100 score to a standard cybersecurity letter grade."""
        if score >= 90:
            return "A+"
        if score >= 80:
            return "A"
        if score >= 70:
            return "B"
        if score >= 55:
            return "C"
        if score >= 40:
            return "D"
        return "F"

    async def audit(self, host: str, port: int = 443, use_ssl: bool = True) -> Dict[str, Any]:
        """
        Fetches headers and audits security posture and CORS misconfigurations.
        """
        protocol = "https" if use_ssl or port in [443, 8443] else "http"
        target_url = f"{protocol}://{host}:{port}" if port not in [80, 443] else f"{protocol}://{host}"

        raw_headers: Dict[str, str] = {}
        cors_misconfigured = False
        score = 0
        findings: List[Dict[str, Any]] = []

        # 1. Main Headers Request
        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(target_url, headers={"User-Agent": "AEGIS-HeaderAuditor/1.0"})
                raw_headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception as e:
            logger.debug(f"Failed to fetch headers for {target_url}: {e}")
            # Try HTTP if HTTPS failed
            if protocol == "https" and port == 443:
                return await self.audit(host, port=80, use_ssl=False)
            return {
                "grade": "F",
                "score": 0,
                "hsts": False,
                "csp": False,
                "x_frame_options": None,
                "x_content_type": False,
                "referrer_policy": None,
                "permissions_policy": False,
                "cors_misconfigured": False,
                "raw_headers": {},
                "findings": [{"severity": "high", "message": f"Service did not respond to HTTP probe: {e}"}]
            }

        # 2. Audit Individual Security Headers

        # HSTS (25 points)
        hsts_header = raw_headers.get("strict-transport-security")
        hsts_present = bool(hsts_header)
        if hsts_present:
            score += 25
            if "includesubdomains" in hsts_header.lower() and "preload" in hsts_header.lower():
                pass
            else:
                findings.append({
                    "header": "Strict-Transport-Security",
                    "severity": "low",
                    "recommendation": "Add 'includeSubDomains' and 'preload' to HSTS directive."
                })
        else:
            findings.append({
                "header": "Strict-Transport-Security",
                "severity": "medium",
                "recommendation": "Enable HSTS with max-age >= 31536000."
            })

        # CSP (25 points)
        csp_header = raw_headers.get("content-security-policy")
        csp_present = bool(csp_header)
        if csp_present:
            score += 25
            if "unsafe-inline" in csp_header or "unsafe-eval" in csp_header:
                findings.append({
                    "header": "Content-Security-Policy",
                    "severity": "low",
                    "recommendation": "CSP contains 'unsafe-inline' or 'unsafe-eval' keywords."
                })
        else:
            findings.append({
                "header": "Content-Security-Policy",
                "severity": "high",
                "recommendation": "Deploy a restrictive Content-Security-Policy to mitigate XSS."
            })

        # X-Frame-Options (15 points)
        xfo = raw_headers.get("x-frame-options")
        xfo_upper = xfo.upper() if xfo else None
        if xfo_upper in ["DENY", "SAMEORIGIN"]:
            score += 15
        else:
            findings.append({
                "header": "X-Frame-Options",
                "severity": "medium",
                "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN to prevent Clickjacking."
            })

        # X-Content-Type-Options (15 points)
        xcto = raw_headers.get("x-content-type-options", "").lower()
        xcto_present = ("nosniff" in xcto)
        if xcto_present:
            score += 15
        else:
            findings.append({
                "header": "X-Content-Type-Options",
                "severity": "medium",
                "recommendation": "Set X-Content-Type-Options: nosniff to prevent MIME sniffing."
            })

        # Referrer-Policy (10 points)
        referrer_policy = raw_headers.get("referrer-policy")
        if referrer_policy:
            score += 10
        else:
            findings.append({
                "header": "Referrer-Policy",
                "severity": "low",
                "recommendation": "Set Referrer-Policy: strict-origin-when-cross-origin."
            })

        # Permissions-Policy (10 points)
        permissions_policy = raw_headers.get("permissions-policy") or raw_headers.get("feature-policy")
        perm_present = bool(permissions_policy)
        if perm_present:
            score += 10
        else:
            findings.append({
                "header": "Permissions-Policy",
                "severity": "low",
                "recommendation": "Define a Permissions-Policy to restrict browser features."
            })

        # 3. Active CORS Misconfiguration Probe
        try:
            evil_origin = "https://evil-attacker.com"
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                cors_resp = await client.get(
                    target_url,
                    headers={"Origin": evil_origin, "User-Agent": "AEGIS-CORSProbe/1.0"}
                )
                acao = cors_resp.headers.get("access-control-allow-origin", "")
                acac = cors_resp.headers.get("access-control-allow-credentials", "").lower()

                # If the evil origin is reflected and credentials are allowed
                if acao == evil_origin and acac == "true":
                    cors_misconfigured = True
                    score = max(0, score - 30)  # Penalize score
                    findings.append({
                        "header": "CORS",
                        "severity": "critical",
                        "recommendation": "CRITICAL: Arbitrary Origin Reflection with credentials allowed (evil-attacker.com accepted)."
                    })
        except Exception:
            pass

        grade = self.calculate_grade(score)

        return {
            "grade": grade,
            "score": score,
            "hsts": hsts_present,
            "csp": csp_present,
            "x_frame_options": xfo_upper,
            "x_content_type": xcto_present,
            "referrer_policy": referrer_policy,
            "permissions_policy": perm_present,
            "cors_misconfigured": cors_misconfigured,
            "raw_headers": raw_headers,
            "findings": findings
        }
