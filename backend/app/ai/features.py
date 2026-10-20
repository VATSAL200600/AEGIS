"""AEGIS AI/ML Engine — 30-Feature Vector Definitions and Explanations

Defines the exact 30 security features used by the XGBoost Risk Regression Model
and human-readable templates for SHAP explainability.
"""
from typing import List, Dict

FEATURE_NAMES: List[str] = [
    # Network & Port Exposure (1-6)
    "num_open_ports",
    "num_critical_ports",
    "has_rdp_exposed",
    "has_ssh_exposed",
    "has_db_exposed",
    "has_smb_exposed",

    # SSL / TLS Security (7-12)
    "ssl_days_until_expiry",
    "ssl_is_expired",
    "ssl_is_self_signed",
    "ssl_has_weak_cipher",
    "ssl_has_weak_protocol",
    "ssl_missing_san",

    # Security Headers & Web Posture (13-17)
    "header_missing_count",
    "header_has_hsts",
    "header_has_csp",
    "header_cors_misconfigured",
    "header_score",

    # DNS & Email Integrity (18-20)
    "dns_spf_vulnerable",
    "dns_dmarc_missing_or_none",
    "dns_zone_transfer_vulnerable",

    # Subdomain Takeover (21)
    "takeover_is_vulnerable",

    # Vulnerability & Threat Intel (22-27)
    "vuln_total_count",
    "vuln_max_cvss",
    "vuln_avg_cvss",
    "vuln_max_epss",
    "vuln_has_cisa_kev",
    "vuln_critical_count",

    # Technology Stack & Host Info (28-30)
    "tech_total_count",
    "tech_has_outdated",
    "is_apex_domain"
]

# Human-readable labels and descriptions for SHAP factor explanations
FEATURE_METADATA: Dict[str, Dict[str, str]] = {
    "num_open_ports": {
        "label": "Total Open Ports",
        "high_risk_desc": "Broad attack surface with {val:.0f} open ports",
        "low_risk_desc": "Minimal port exposure ({val:.0f} ports)"
    },
    "num_critical_ports": {
        "label": "Critical Exposed Ports",
        "high_risk_desc": "{val:.0f} highly sensitive administrative/database ports exposed",
        "low_risk_desc": "No sensitive administrative ports exposed"
    },
    "has_rdp_exposed": {
        "label": "Remote Desktop (RDP) Exposure",
        "high_risk_desc": "Port 3389 (RDP) exposed publicly to the internet",
        "low_risk_desc": "RDP port 3389 is securely closed"
    },
    "has_ssh_exposed": {
        "label": "SSH Exposure",
        "high_risk_desc": "Port 22 (SSH) accessible publicly",
        "low_risk_desc": "SSH port closed"
    },
    "has_db_exposed": {
        "label": "Database Service Exposed",
        "high_risk_desc": "Direct database port (MySQL, Postgres, MSSQL, Redis, or Mongo) open to the internet",
        "low_risk_desc": "No public database exposure"
    },
    "has_smb_exposed": {
        "label": "SMB / NetBIOS Exposure",
        "high_risk_desc": "Port 445/139 (SMB) exposed publicly (high risk of worm/ransomware exploitation)",
        "low_risk_desc": "SMB file sharing securely blocked"
    },
    "ssl_days_until_expiry": {
        "label": "SSL Expiry Timeline",
        "high_risk_desc": "SSL certificate is nearing or past expiration ({val:.0f} days remaining)",
        "low_risk_desc": "Valid SSL certificate ({val:.0f} days remaining)"
    },
    "ssl_is_expired": {
        "label": "Expired SSL Certificate",
        "high_risk_desc": "Active TLS certificate has expired, triggering browser security warnings",
        "low_risk_desc": "TLS certificate is currently valid"
    },
    "ssl_is_self_signed": {
        "label": "Self-Signed Certificate",
        "high_risk_desc": "Certificate is self-signed and untrusted by browsers",
        "low_risk_desc": "Signed by a recognized Certificate Authority"
    },
    "ssl_has_weak_cipher": {
        "label": "Weak SSL/TLS Cipher",
        "high_risk_desc": "Negotiates insecure/deprecated ciphers (RC4, DES, 3DES, or MD5)",
        "low_risk_desc": "Strong modern cipher suite enforced"
    },
    "ssl_has_weak_protocol": {
        "label": "Deprecated TLS Protocol",
        "high_risk_desc": "Supports deprecated protocols (TLS 1.0, 1.1, or SSLv3)",
        "low_risk_desc": "Enforces modern TLS 1.2 or TLS 1.3"
    },
    "ssl_missing_san": {
        "label": "Missing SAN Extension",
        "high_risk_desc": "Certificate lacks Subject Alternative Names (SAN)",
        "low_risk_desc": "Valid SAN entries present"
    },
    "header_missing_count": {
        "label": "Missing Security Headers",
        "high_risk_desc": "{val:.0f} recommended OWASP security headers missing",
        "low_risk_desc": "Standard security headers implemented"
    },
    "header_has_hsts": {
        "label": "HTTP Strict Transport Security (HSTS)",
        "high_risk_desc": "Missing HSTS allows SSL stripping and MITM attacks",
        "low_risk_desc": "Strict HSTS enforced (-10.0 risk credit)"
    },
    "header_has_csp": {
        "label": "Content Security Policy (CSP)",
        "high_risk_desc": "No Content-Security-Policy to prevent Cross-Site Scripting (XSS)",
        "low_risk_desc": "Active Content-Security-Policy mitigates XSS"
    },
    "header_cors_misconfigured": {
        "label": "CORS Origin Reflection",
        "high_risk_desc": "Reflects arbitrary cross-origin requests with credentials allowed",
        "low_risk_desc": "Safe CORS policy"
    },
    "header_score": {
        "label": "Header Audit Score",
        "high_risk_desc": "Poor header configuration score ({val:.0f}/100)",
        "low_risk_desc": "Excellent header configuration score ({val:.0f}/100)"
    },
    "dns_spf_vulnerable": {
        "label": "SPF Spoofing Exposure",
        "high_risk_desc": "Missing SPF or configured with '+all' allowing email impersonation",
        "low_risk_desc": "SPF record strictly enforces authorized mail senders"
    },
    "dns_dmarc_missing_or_none": {
        "label": "DMARC Phishing Protection",
        "high_risk_desc": "DMARC missing or set to 'p=none' (unauthorized mail is not rejected)",
        "low_risk_desc": "Strict DMARC policy (quarantine or reject) enforced"
    },
    "dns_zone_transfer_vulnerable": {
        "label": "DNS Zone Transfer (AXFR) Leak",
        "high_risk_desc": "Authoritative nameserver allows unauthorized AXFR zone transfer",
        "low_risk_desc": "AXFR zone transfers securely disabled"
    },
    "takeover_is_vulnerable": {
        "label": "Subdomain Takeover Risk",
        "high_risk_desc": "Dangling CNAME points to unclaimed cloud resource (GitHub, S3, Heroku)",
        "low_risk_desc": "No dangling DNS pointers detected"
    },
    "vuln_total_count": {
        "label": "Known Vulnerabilities",
        "high_risk_desc": "{val:.0f} known vulnerabilities detected on asset",
        "low_risk_desc": "Zero known CVEs identified"
    },
    "vuln_max_cvss": {
        "label": "Highest CVSS Score",
        "high_risk_desc": "Maximum CVSS score of {val:.1f}/10 on detected vulnerability",
        "low_risk_desc": "No high-severity CVSS scores"
    },
    "vuln_avg_cvss": {
        "label": "Average CVSS Score",
        "high_risk_desc": "Average CVSS severity of {val:.1f}/10",
        "low_risk_desc": "Low average CVSS score"
    },
    "vuln_max_epss": {
        "label": "Exploit Prediction (EPSS)",
        "high_risk_desc": "High EPSS score ({val:.1%}) indicates imminent active in-the-wild exploitation",
        "low_risk_desc": "Low EPSS exploit probability"
    },
    "vuln_has_cisa_kev": {
        "label": "CISA Known Exploited Vulnerability",
        "high_risk_desc": "Active in-the-wild weaponized exploit listed on CISA KEV catalog",
        "low_risk_desc": "Not listed on CISA KEV"
    },
    "vuln_critical_count": {
        "label": "Critical Vulnerability Count",
        "high_risk_desc": "{val:.0f} critical-tier vulnerabilities present",
        "low_risk_desc": "No critical vulnerabilities"
    },
    "tech_total_count": {
        "label": "Technology Footprint",
        "high_risk_desc": "Complex stack with {val:.0f} detected frameworks/technologies",
        "low_risk_desc": "Minimal technology footprint"
    },
    "tech_has_outdated": {
        "label": "Outdated Software / EOL",
        "high_risk_desc": "Running outdated software with known security deprecation",
        "low_risk_desc": "Technologies are modern and supported"
    },
    "is_apex_domain": {
        "label": "Apex Domain",
        "high_risk_desc": "Primary organizational root domain",
        "low_risk_desc": "Subdomain asset"
    }
}
