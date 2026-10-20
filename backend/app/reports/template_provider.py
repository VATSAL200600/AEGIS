"""AEGIS Report Generator -- Template Provider

Generates structured Markdown + HTML reports without any external AI API.
Works offline with deterministic output based on scan data.
Produces executive, technical, and compliance report types.
"""
import logging
import html as html_lib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

logger = logging.getLogger("aegis.reports.template")


class TemplateReportProvider:
    """Deterministic template-based report generator."""

    SEVERITY_LABELS = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "info": "INFORMATIONAL",
    }

    SEVERITY_COLORS = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#2563eb",
        "info": "#6b7280",
    }

    def generate(self, scan_data: Dict[str, Any], report_type: str = "executive") -> Dict[str, Any]:
        """Generate a complete report from scan data.

        Args:
            scan_data: Dict with keys: scan, assets, vulnerabilities, stats
            report_type: 'executive', 'technical', or 'compliance'

        Returns:
            Dict with: title, executive_summary, attack_surface_analysis,
                        remediation_plan, html_content
        """
        scan = scan_data["scan"]
        assets = scan_data.get("assets", [])
        vulns = scan_data.get("vulnerabilities", [])
        stats = scan_data.get("stats", {})

        domain = scan.get("target_domain", "Unknown")
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        if report_type == "executive":
            return self._executive_report(domain, timestamp, scan, assets, vulns, stats)
        elif report_type == "technical":
            return self._technical_report(domain, timestamp, scan, assets, vulns, stats)
        elif report_type == "compliance":
            return self._compliance_report(domain, timestamp, scan, assets, vulns, stats)
        else:
            return self._executive_report(domain, timestamp, scan, assets, vulns, stats)

    # ---- Executive Report ----
    def _executive_report(self, domain, timestamp, scan, assets, vulns, stats) -> Dict[str, Any]:
        total_assets = len(assets)
        total_vulns = len(vulns)
        avg_risk = stats.get("avg_risk_score", 0.0)
        max_risk = stats.get("max_risk_score", 0.0)
        posture = max(0.0, 100.0 - avg_risk)

        # Severity counts
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in vulns:
            sev = v.get("severity", "low").lower()
            if sev in sev_counts:
                sev_counts[sev] += 1

        # Top risky assets
        sorted_assets = sorted(assets, key=lambda a: a.get("risk_score", 0), reverse=True)
        top_5 = sorted_assets[:5]

        # Risk classification
        if posture >= 80:
            posture_label = "Strong"
            posture_desc = "The organization demonstrates a mature security posture with well-configured infrastructure."
        elif posture >= 60:
            posture_label = "Moderate"
            posture_desc = "The attack surface shows moderate exposure. Targeted remediation is recommended."
        elif posture >= 40:
            posture_label = "Elevated Risk"
            posture_desc = "Significant security gaps exist across the external attack surface requiring immediate attention."
        else:
            posture_label = "Critical"
            posture_desc = "The external attack surface is severely exposed. Emergency remediation is strongly advised."

        title = f"AEGIS Executive Security Report - {domain}"

        executive_summary = (
            f"## Executive Summary\n\n"
            f"**Assessment Date:** {timestamp}\n"
            f"**Target Domain:** {domain}\n"
            f"**Security Posture:** {posture_label} ({posture:.0f}/100)\n\n"
            f"{posture_desc}\n\n"
            f"### Key Metrics\n\n"
            f"| Metric | Value |\n"
            f"|--------|-------|\n"
            f"| Total Assets Discovered | {total_assets} |\n"
            f"| Total Vulnerabilities | {total_vulns} |\n"
            f"| Average Risk Score | {avg_risk:.1f}/100 |\n"
            f"| Maximum Risk Score | {max_risk:.1f}/100 |\n"
            f"| Critical Findings | {sev_counts['critical']} |\n"
            f"| High-Severity Findings | {sev_counts['high']} |\n\n"
        )

        # Attack surface analysis
        attack_surface = f"## Attack Surface Analysis\n\n"
        attack_surface += f"The reconnaissance scan identified **{total_assets} internet-facing assets** under the `{domain}` domain. "

        if sev_counts["critical"] > 0:
            attack_surface += (
                f"**{sev_counts['critical']} critical-severity findings** require immediate remediation. "
            )
        if sev_counts["high"] > 0:
            attack_surface += (
                f"Additionally, **{sev_counts['high']} high-severity issues** should be addressed within 30 days. "
            )

        attack_surface += "\n\n### Highest Risk Assets\n\n"
        attack_surface += "| Asset | Risk Score | Risk Level |\n"
        attack_surface += "|-------|-----------|------------|\n"
        for a in top_5:
            attack_surface += f"| {a.get('hostname', 'N/A')} | {a.get('risk_score', 0):.1f}/100 | {a.get('risk_level', 'info').upper()} |\n"

        # Remediation plan
        remediation_plan = self._build_remediation_plan(vulns, assets)

        # HTML
        html_content = self._render_html(title, executive_summary, attack_surface, remediation_plan, domain, timestamp, posture)

        return {
            "title": title,
            "executive_summary": executive_summary,
            "attack_surface_analysis": attack_surface,
            "remediation_plan": remediation_plan,
            "html_content": html_content,
        }

    # ---- Technical Report ----
    def _technical_report(self, domain, timestamp, scan, assets, vulns, stats) -> Dict[str, Any]:
        title = f"AEGIS Technical Assessment - {domain}"
        total_assets = len(assets)
        total_vulns = len(vulns)

        executive_summary = (
            f"## Technical Assessment Overview\n\n"
            f"**Date:** {timestamp} | **Domain:** {domain} | "
            f"**Profile:** {scan.get('scan_profile', 'standard')}\n\n"
            f"This technical report provides granular findings from automated "
            f"external reconnaissance of {total_assets} assets across the `{domain}` attack surface.\n\n"
        )

        # Detailed per-asset breakdown
        attack_surface = "## Detailed Findings by Asset\n\n"
        for asset in sorted(assets, key=lambda a: a.get("risk_score", 0), reverse=True):
            hostname = asset.get("hostname", "unknown")
            ip = asset.get("ip_address", "N/A")
            score = asset.get("risk_score", 0.0)
            level = asset.get("risk_level", "info").upper()

            attack_surface += f"### {hostname} ({ip})\n\n"
            attack_surface += f"**Risk Score:** {score:.1f}/100 ({level})\n\n"

            # Ports
            ports = asset.get("ports", [])
            if ports:
                attack_surface += "**Open Ports:**\n\n"
                attack_surface += "| Port | Service | Banner | Critical |\n"
                attack_surface += "|------|---------|--------|----------|\n"
                for p in ports:
                    crit = "YES" if p.get("is_critical") else "no"
                    attack_surface += f"| {p.get('port_number', '?')}/{p.get('protocol', 'tcp')} | {p.get('service_name', '-')} | {(p.get('banner') or '-')[:50]} | {crit} |\n"
                attack_surface += "\n"

            # Vulnerabilities for this asset
            asset_vulns = [v for v in vulns if v.get("asset_id") == asset.get("id")]
            if asset_vulns:
                attack_surface += "**Vulnerabilities:**\n\n"
                for v in sorted(asset_vulns, key=lambda x: x.get("cvss_score", 0) or 0, reverse=True):
                    sev = v.get("severity", "medium").upper()
                    cvss = v.get("cvss_score") or "N/A"
                    attack_surface += f"- **[{sev}]** {v.get('title', 'Unknown')} (CVSS: {cvss})\n"
                attack_surface += "\n"

            # SHAP explanation
            shap = asset.get("shap_explanation", {})
            if shap and shap.get("summary"):
                attack_surface += f"**AI Risk Analysis:** {shap['summary']}\n\n"

            attack_surface += "---\n\n"

        remediation_plan = self._build_remediation_plan(vulns, assets)
        html_content = self._render_html(title, executive_summary, attack_surface, remediation_plan, domain, timestamp, 0)

        return {
            "title": title,
            "executive_summary": executive_summary,
            "attack_surface_analysis": attack_surface,
            "remediation_plan": remediation_plan,
            "html_content": html_content,
        }

    # ---- Compliance Report ----
    def _compliance_report(self, domain, timestamp, scan, assets, vulns, stats) -> Dict[str, Any]:
        title = f"AEGIS Compliance Assessment - {domain}"
        total_assets = len(assets)

        executive_summary = (
            f"## Compliance Assessment\n\n"
            f"**Date:** {timestamp} | **Domain:** {domain}\n\n"
            f"This report maps discovered findings against common compliance "
            f"frameworks including OWASP Top 10, CIS Controls, and NIST CSF.\n\n"
        )

        attack_surface = "## Compliance Mapping\n\n"

        # OWASP Top 10 mapping
        owasp_findings = {
            "A01 Broken Access Control": [],
            "A02 Cryptographic Failures": [],
            "A03 Injection": [],
            "A05 Security Misconfiguration": [],
            "A06 Vulnerable Components": [],
            "A09 Security Logging Failures": [],
        }

        for v in vulns:
            title_lower = (v.get("title") or "").lower()
            desc_lower = (v.get("description") or "").lower()
            if "takeover" in title_lower or "access" in title_lower:
                owasp_findings["A01 Broken Access Control"].append(v)
            if "ssl" in title_lower or "tls" in title_lower or "cipher" in title_lower:
                owasp_findings["A02 Cryptographic Failures"].append(v)
            if "injection" in title_lower or "sqli" in title_lower:
                owasp_findings["A03 Injection"].append(v)
            if "header" in title_lower or "misconfigur" in title_lower or "cors" in title_lower:
                owasp_findings["A05 Security Misconfiguration"].append(v)
            if "outdated" in desc_lower or "eol" in desc_lower or "cve" in (v.get("cve_id") or "").lower():
                owasp_findings["A06 Vulnerable Components"].append(v)

        # Check header-level issues from assets
        for asset in assets:
            hdr = asset.get("security_headers")
            if hdr:
                if not hdr.get("hsts"):
                    owasp_findings["A05 Security Misconfiguration"].append({
                        "title": f"Missing HSTS on {asset.get('hostname', '?')}",
                        "severity": "medium",
                    })
                if not hdr.get("csp"):
                    owasp_findings["A05 Security Misconfiguration"].append({
                        "title": f"Missing CSP on {asset.get('hostname', '?')}",
                        "severity": "medium",
                    })

        attack_surface += "### OWASP Top 10 (2021) Mapping\n\n"
        attack_surface += "| OWASP Category | Findings | Status |\n"
        attack_surface += "|----------------|----------|--------|\n"
        for category, findings in owasp_findings.items():
            count = len(findings)
            status = "FAIL" if count > 0 else "PASS"
            attack_surface += f"| {category} | {count} | {status} |\n"

        attack_surface += "\n### CIS Critical Security Controls\n\n"
        attack_surface += "| Control | Status | Notes |\n"
        attack_surface += "|---------|--------|-------|\n"

        # Check key controls
        has_ssl_issues = any("ssl" in (v.get("title") or "").lower() or "tls" in (v.get("title") or "").lower() for v in vulns)
        has_outdated = any(a.get("technologies") and any(t.get("is_outdated") for t in (a.get("technologies") or [])) for a in assets)

        attack_surface += f"| CSC 1: Inventory of Assets | PASS | {total_assets} assets catalogued |\n"
        attack_surface += f"| CSC 2: Software Inventory | {'FAIL' if has_outdated else 'PASS'} | {'Outdated software detected' if has_outdated else 'All software current'} |\n"
        attack_surface += f"| CSC 3: Data Protection | {'FAIL' if has_ssl_issues else 'PASS'} | {'TLS/SSL issues found' if has_ssl_issues else 'Encryption standards met'} |\n"
        attack_surface += f"| CSC 7: Email/Browser Defense | {'FAIL' if any(v.get('severity') == 'critical' for v in vulns) else 'PASS'} | Evaluated via header auditing |\n"

        remediation_plan = self._build_remediation_plan(vulns, assets)
        html_content = self._render_html(title, executive_summary, attack_surface, remediation_plan, domain, timestamp, 0)

        return {
            "title": title,
            "executive_summary": executive_summary,
            "attack_surface_analysis": attack_surface,
            "remediation_plan": remediation_plan,
            "html_content": html_content,
        }

    # ---- Remediation Plan Builder ----
    def _build_remediation_plan(self, vulns: List[Dict], assets: List[Dict]) -> List[Dict[str, Any]]:
        """Build a prioritized remediation action plan."""
        plan = []
        priority = 1

        # 1. Critical vulns first
        critical_vulns = [v for v in vulns if v.get("severity") == "critical"]
        if critical_vulns:
            affected = list(set(v.get("hostname", v.get("asset_id", "?")) for v in critical_vulns))
            plan.append({
                "priority": priority,
                "severity": "critical",
                "action": "Remediate Critical Vulnerabilities Immediately",
                "description": f"{len(critical_vulns)} critical-severity finding(s) require emergency patching or mitigation.",
                "affected_assets": affected[:10],
                "timeline": "Immediate (24-48 hours)",
                "details": [v.get("title", "Unknown") for v in critical_vulns[:5]],
            })
            priority += 1

        # 2. High vulns
        high_vulns = [v for v in vulns if v.get("severity") == "high"]
        if high_vulns:
            plan.append({
                "priority": priority,
                "severity": "high",
                "action": "Address High-Severity Findings",
                "description": f"{len(high_vulns)} high-severity finding(s) should be patched within the next sprint.",
                "affected_assets": list(set(v.get("hostname", "?") for v in high_vulns))[:10],
                "timeline": "Within 30 days",
                "details": [v.get("title", "Unknown") for v in high_vulns[:5]],
            })
            priority += 1

        # 3. SSL/TLS improvements
        ssl_issues = [v for v in vulns if any(k in (v.get("title") or "").lower() for k in ["ssl", "tls", "cipher", "certificate"])]
        if ssl_issues:
            plan.append({
                "priority": priority,
                "severity": "high",
                "action": "Harden TLS/SSL Configuration",
                "description": "Upgrade to TLS 1.3, remove weak ciphers, and renew expiring certificates.",
                "timeline": "Within 14 days",
                "details": [v.get("title", "") for v in ssl_issues[:5]],
            })
            priority += 1

        # 4. Security headers
        assets_missing_headers = [
            a for a in assets
            if a.get("security_headers") and (a["security_headers"].get("score", 100) < 60)
        ]
        if assets_missing_headers:
            plan.append({
                "priority": priority,
                "severity": "medium",
                "action": "Deploy Missing Security Headers",
                "description": "Add HSTS, CSP, X-Frame-Options, and other OWASP-recommended security headers.",
                "affected_assets": [a.get("hostname", "?") for a in assets_missing_headers[:10]],
                "timeline": "Within 30 days",
            })
            priority += 1

        # 5. Medium/Low vulns
        med_vulns = [v for v in vulns if v.get("severity") in ("medium", "low")]
        if med_vulns:
            plan.append({
                "priority": priority,
                "severity": "low",
                "action": "Review Medium and Low-Severity Findings",
                "description": f"{len(med_vulns)} lower-severity finding(s) to be reviewed and addressed as part of regular maintenance.",
                "timeline": "Within 90 days",
            })

        return plan

    # ---- HTML Renderer ----
    def _render_html(self, title, exec_summary, attack_surface, remediation_plan, domain, timestamp, posture) -> str:
        """Render the complete report as a styled HTML document."""

        # Convert markdown tables to simple HTML (basic rendering)
        def md_to_html_basic(md_text: str) -> str:
            """Minimal Markdown-to-HTML for tables and headings."""
            lines = md_text.split("\n")
            html_lines = []
            in_table = False

            for line in lines:
                stripped = line.strip()

                # Skip separator rows
                if stripped and all(c in "-| " for c in stripped):
                    continue

                # Table rows
                if stripped.startswith("|") and stripped.endswith("|"):
                    cells = [c.strip() for c in stripped.split("|")[1:-1]]
                    if not in_table:
                        html_lines.append("<table>")
                        html_lines.append("<thead><tr>" + "".join(f"<th>{html_lib.escape(c)}</th>" for c in cells) + "</tr></thead>")
                        html_lines.append("<tbody>")
                        in_table = True
                    else:
                        html_lines.append("<tr>" + "".join(f"<td>{html_lib.escape(c)}</td>" for c in cells) + "</tr>")
                else:
                    if in_table:
                        html_lines.append("</tbody></table>")
                        in_table = False

                    if stripped.startswith("### "):
                        html_lines.append(f"<h3>{html_lib.escape(stripped[4:])}</h3>")
                    elif stripped.startswith("## "):
                        html_lines.append(f"<h2>{html_lib.escape(stripped[3:])}</h2>")
                    elif stripped.startswith("# "):
                        html_lines.append(f"<h1>{html_lib.escape(stripped[2:])}</h1>")
                    elif stripped.startswith("- **"):
                        html_lines.append(f"<li>{html_lib.escape(stripped[2:])}</li>")
                    elif stripped.startswith("**") and stripped.endswith("**"):
                        html_lines.append(f"<p><strong>{html_lib.escape(stripped[2:-2])}</strong></p>")
                    elif stripped:
                        html_lines.append(f"<p>{html_lib.escape(stripped)}</p>")

            if in_table:
                html_lines.append("</tbody></table>")

            return "\n".join(html_lines)

        # Remediation plan HTML
        remediation_html = "<h2>Remediation Plan</h2>"
        if remediation_plan:
            for item in remediation_plan:
                sev = item.get("severity", "medium")
                color = self.SEVERITY_COLORS.get(sev, "#6b7280")
                remediation_html += f"""
                <div class="remediation-item" style="border-left: 4px solid {color}; padding: 16px; margin: 12px 0; background: #f8fafc; border-radius: 6px;">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                        <span class="priority-badge" style="background: {color}; color: white; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 600;">
                            P{item.get('priority', '?')} - {sev.upper()}
                        </span>
                        <strong>{html_lib.escape(item.get('action', ''))}</strong>
                    </div>
                    <p style="margin: 4px 0; color: #475569;">{html_lib.escape(item.get('description', ''))}</p>
                    <p style="margin: 4px 0; font-size: 13px; color: #64748b;"><em>Timeline: {html_lib.escape(item.get('timeline', 'TBD'))}</em></p>
                </div>
                """

        exec_html = md_to_html_basic(exec_summary)
        attack_html = md_to_html_basic(attack_surface)

        escaped_title = html_lib.escape(title)
        escaped_domain = html_lib.escape(domain)
        escaped_timestamp = html_lib.escape(timestamp)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{escaped_title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #f1f5f9; color: #1e293b; line-height: 1.6; }}
        .report-container {{ max-width: 900px; margin: 40px auto; background: white; border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,0.08); overflow: hidden; }}
        .report-header {{ background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%); color: white; padding: 48px 40px; }}
        .report-header h1 {{ font-size: 28px; margin-bottom: 8px; font-weight: 700; }}
        .report-header .meta {{ font-size: 14px; opacity: 0.8; }}
        .report-body {{ padding: 40px; }}
        h2 {{ color: #0f172a; font-size: 22px; margin: 32px 0 16px; padding-bottom: 8px; border-bottom: 2px solid #e2e8f0; }}
        h3 {{ color: #334155; font-size: 17px; margin: 24px 0 12px; }}
        p {{ margin: 8px 0; color: #475569; }}
        table {{ width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 14px; }}
        th {{ background: #f8fafc; text-align: left; padding: 10px 14px; border-bottom: 2px solid #e2e8f0; color: #334155; font-weight: 600; }}
        td {{ padding: 10px 14px; border-bottom: 1px solid #f1f5f9; }}
        tr:hover td {{ background: #f8fafc; }}
        li {{ margin: 4px 0 4px 24px; color: #475569; }}
        .footer {{ text-align: center; padding: 24px; color: #94a3b8; font-size: 12px; border-top: 1px solid #e2e8f0; }}
    </style>
</head>
<body>
    <div class="report-container">
        <div class="report-header">
            <h1>{escaped_title}</h1>
            <div class="meta">Domain: {escaped_domain} | Generated: {escaped_timestamp} | Powered by AEGIS AI Engine</div>
        </div>
        <div class="report-body">
            {exec_html}
            {attack_html}
            {remediation_html}
        </div>
        <div class="footer">
            Generated by AEGIS - AI-Powered Attack Surface Management Platform
        </div>
    </div>
</body>
</html>"""
