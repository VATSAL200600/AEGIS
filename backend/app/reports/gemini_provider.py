"""AEGIS Report Generator -- Google Gemini AI Provider

Uses the Gemini REST API (via httpx) to generate AI-powered narrative
security reports. Falls back gracefully to template provider if the
API key is missing or the request fails.
"""
import json
import logging
from typing import Dict, Any, Optional

import httpx

from app.config import settings

logger = logging.getLogger("aegis.reports.gemini")

# Gemini API endpoint (v1beta generateContent)
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"


class GeminiReportProvider:
    """AI-powered report generator using Google Gemini."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.GEMINI_API_KEY
        self._timeout = 60.0

    @property
    def is_available(self) -> bool:
        """Check if the Gemini API key is configured."""
        return bool(self.api_key and len(self.api_key) > 10)

    async def generate(self, scan_data: Dict[str, Any], report_type: str = "executive") -> Optional[Dict[str, Any]]:
        """Generate an AI-powered report using Gemini.

        Args:
            scan_data: Dict with keys: scan, assets, vulnerabilities, stats
            report_type: 'executive', 'technical', or 'compliance'

        Returns:
            Dict with: title, executive_summary, attack_surface_analysis,
                        remediation_plan (list), or None on failure.
        """
        if not self.is_available:
            logger.warning("Gemini API key not configured, cannot generate AI report")
            return None

        prompt = self._build_prompt(scan_data, report_type)

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    GEMINI_API_URL,
                    params={"key": self.api_key},
                    json={
                        "contents": [{"parts": [{"text": prompt}]}],
                        "generationConfig": {
                            "temperature": 0.3,
                            "topP": 0.85,
                            "maxOutputTokens": 8192,
                            "responseMimeType": "application/json",
                        },
                    },
                    headers={"Content-Type": "application/json"},
                )

            if response.status_code != 200:
                logger.error(f"Gemini API returned status {response.status_code}: {response.text[:500]}")
                return None

            result = response.json()
            content_text = (
                result.get("candidates", [{}])[0]
                .get("content", {})
                .get("parts", [{}])[0]
                .get("text", "")
            )

            if not content_text:
                logger.error("Gemini returned empty content")
                return None

            # Parse the JSON response from Gemini
            parsed = json.loads(content_text)
            return self._validate_response(parsed)

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Gemini JSON response: {e}")
            return None
        except httpx.TimeoutException:
            logger.error("Gemini API request timed out")
            return None
        except Exception as e:
            logger.error(f"Gemini API request failed: {e}")
            return None

    def _build_prompt(self, scan_data: Dict[str, Any], report_type: str) -> str:
        """Construct the Gemini prompt with scan data context."""
        scan = scan_data.get("scan", {})
        assets = scan_data.get("assets", [])
        vulns = scan_data.get("vulnerabilities", [])
        stats = scan_data.get("stats", {})

        domain = scan.get("target_domain", "Unknown")
        total_assets = len(assets)
        total_vulns = len(vulns)

        # Build concise asset summaries (limit to avoid token overflow)
        asset_summaries = []
        for a in sorted(assets, key=lambda x: x.get("risk_score", 0), reverse=True)[:20]:
            entry = {
                "hostname": a.get("hostname"),
                "ip_address": a.get("ip_address"),
                "risk_score": a.get("risk_score", 0),
                "risk_level": a.get("risk_level", "info"),
                "open_ports": [p.get("port_number") for p in a.get("ports", [])],
                "technologies": [t.get("name") for t in a.get("technologies", [])],
            }
            shap = a.get("shap_explanation", {})
            if shap and shap.get("summary"):
                entry["ai_risk_summary"] = shap["summary"]
            asset_summaries.append(entry)

        # Build concise vuln summaries
        vuln_summaries = []
        for v in sorted(vulns, key=lambda x: x.get("cvss_score", 0) or 0, reverse=True)[:30]:
            vuln_summaries.append({
                "title": v.get("title"),
                "cve_id": v.get("cve_id"),
                "severity": v.get("severity"),
                "cvss_score": v.get("cvss_score"),
                "epss_score": v.get("epss_score"),
                "is_cisa_kev": v.get("is_cisa_kev", False),
                "hostname": v.get("hostname", "N/A"),
            })

        report_type_instructions = {
            "executive": (
                "Generate an EXECUTIVE security report for C-level leadership. "
                "Use business-oriented language, avoid deep technical jargon, "
                "focus on risk posture, business impact, and strategic recommendations."
            ),
            "technical": (
                "Generate a TECHNICAL security assessment report for the security engineering team. "
                "Include detailed per-asset findings, specific CVE references, port/service analysis, "
                "and precise remediation commands or configuration changes."
            ),
            "compliance": (
                "Generate a COMPLIANCE-oriented report mapping findings to OWASP Top 10 (2021), "
                "CIS Critical Security Controls v8, and NIST CSF. Provide pass/fail status for each "
                "control and specific evidence for non-compliance."
            ),
        }

        instruction = report_type_instructions.get(report_type, report_type_instructions["executive"])

        prompt = f"""You are AEGIS, an AI-powered Attack Surface Management platform.
{instruction}

TARGET DOMAIN: {domain}
TOTAL ASSETS DISCOVERED: {total_assets}
TOTAL VULNERABILITIES: {total_vulns}
AVERAGE RISK SCORE: {stats.get('avg_risk_score', 0):.1f}/100
MAX RISK SCORE: {stats.get('max_risk_score', 0):.1f}/100

ASSET DATA (top {len(asset_summaries)} by risk):
{json.dumps(asset_summaries, indent=2, default=str)}

VULNERABILITY DATA (top {len(vuln_summaries)} by CVSS):
{json.dumps(vuln_summaries, indent=2, default=str)}

Generate a comprehensive report in the following JSON structure:
{{
  "title": "Report title string",
  "executive_summary": "Multi-paragraph Markdown executive summary with ## headings",
  "attack_surface_analysis": "Multi-paragraph Markdown analysis with ### sub-headings and tables",
  "remediation_plan": [
    {{
      "priority": 1,
      "severity": "critical|high|medium|low",
      "action": "Short action title",
      "description": "Detailed description of what to do",
      "timeline": "e.g. Immediate, Within 7 days, Within 30 days",
      "affected_assets": ["hostname1", "hostname2"]
    }}
  ]
}}

Requirements:
- Use Markdown formatting with ## and ### headings, bold text, tables, and bullet points
- Include specific data from the scan results (hostnames, CVE IDs, risk scores)
- Remediation plan must be ordered by priority (critical first)
- Be specific and actionable, not generic
- Reference the AI risk analysis (SHAP explanations) where available
"""
        return prompt

    def _validate_response(self, parsed: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Validate and normalize the Gemini response."""
        required_keys = ["title", "executive_summary", "attack_surface_analysis", "remediation_plan"]

        for key in required_keys:
            if key not in parsed:
                logger.error(f"Gemini response missing required key: {key}")
                return None

        # Ensure remediation_plan is a list
        if not isinstance(parsed["remediation_plan"], list):
            parsed["remediation_plan"] = []

        return {
            "title": str(parsed["title"]),
            "executive_summary": str(parsed["executive_summary"]),
            "attack_surface_analysis": str(parsed["attack_surface_analysis"]),
            "remediation_plan": parsed["remediation_plan"],
        }
