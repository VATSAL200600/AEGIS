"""AEGIS AI/ML Engine — Feature Vector Extractor

Transforms an Asset database entity (or dictionary finding) into the normalized
30-feature vector expected by the XGBoost Risk Engine.
"""
from typing import Dict, Any, List
import numpy as np
from app.ai.features import FEATURE_NAMES

CRITICAL_PORTS = {21, 22, 23, 135, 139, 445, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 9200, 27017}
DB_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 27017}
SMB_PORTS = {135, 137, 138, 139, 445}


class FeatureExtractor:
    """Extracts mathematical feature vector from an asset's attack surface findings."""

    @staticmethod
    def extract_from_dict(asset_data: Dict[str, Any]) -> np.ndarray:
        """
        Extract 30 features from an asset dictionary.
        Returns a 1D numpy array of shape (30,).
        """
        feature_dict = FeatureExtractor.extract_feature_dict(asset_data)
        return np.array([feature_dict[name] for name in FEATURE_NAMES], dtype=np.float32)

    @staticmethod
    def extract_feature_dict(asset_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract named feature dictionary from an asset dictionary.
        """
        ports = asset_data.get("ports", [])
        ssl_cert = asset_data.get("ssl_cert")
        headers = asset_data.get("security_headers")
        dns_records = asset_data.get("dns_records", [])
        vulns = asset_data.get("vulnerabilities", [])
        techs = asset_data.get("technologies", [])
        is_apex = 1.0 if asset_data.get("is_apex", False) else 0.0

        # --- 1. Ports & Services ---
        num_open_ports = float(len(ports))
        num_crit_ports = 0.0
        has_rdp = 0.0
        has_ssh = 0.0
        has_db = 0.0
        has_smb = 0.0

        for p in ports:
            # Handle both Port ORM object and dictionary
            port_num = p.port_number if hasattr(p, "port_number") else p.get("port_number", 0)
            if port_num in CRITICAL_PORTS:
                num_crit_ports += 1.0
            if port_num == 3389:
                has_rdp = 1.0
            if port_num == 22:
                has_ssh = 1.0
            if port_num in DB_PORTS:
                has_db = 1.0
            if port_num in SMB_PORTS:
                has_smb = 1.0

        # --- 2. SSL/TLS ---
        ssl_days = 90.0
        ssl_is_expired = 0.0
        ssl_is_self_signed = 0.0
        ssl_has_weak_cipher = 0.0
        ssl_has_weak_protocol = 0.0
        ssl_missing_san = 0.0

        if ssl_cert:
            def _get_ssl(attr, default=None):
                return getattr(ssl_cert, attr, default) if hasattr(ssl_cert, attr) else ssl_cert.get(attr, default)

            ssl_days = float(_get_ssl("expires_in_days", 90))
            ssl_is_expired = 1.0 if _get_ssl("is_expired", False) else 0.0
            ssl_is_self_signed = 1.0 if _get_ssl("is_self_signed", False) else 0.0
            ssl_has_weak_cipher = 1.0 if _get_ssl("has_weak_cipher", False) else 0.0
            ssl_has_weak_protocol = 1.0 if _get_ssl("has_weak_protocol", False) else 0.0
            san_entries = _get_ssl("san_entries", [])
            ssl_missing_san = 1.0 if not san_entries else 0.0

        # --- 3. Headers ---
        header_missing_count = 6.0
        header_has_hsts = 0.0
        header_has_csp = 0.0
        header_cors_misconfigured = 0.0
        header_score = 0.0

        if headers:
            def _get_hdr(attr, default=None):
                return getattr(headers, attr, default) if hasattr(headers, attr) else headers.get(attr, default)

            hsts = _get_hdr("hsts", False)
            csp = _get_hdr("csp", False)
            xfo = _get_hdr("x_frame_options")
            xcto = _get_hdr("x_content_type", False)
            rp = _get_hdr("referrer_policy")
            pp = _get_hdr("permissions_policy", False)

            present_count = sum([bool(hsts), bool(csp), bool(xfo), bool(xcto), bool(rp), bool(pp)])
            header_missing_count = float(6 - present_count)
            header_has_hsts = 1.0 if hsts else 0.0
            header_has_csp = 1.0 if csp else 0.0
            header_cors_misconfigured = 1.0 if _get_hdr("cors_misconfigured", False) else 0.0
            header_score = float(_get_hdr("score", 0))

        # --- 4. DNS Posture ---
        dns_spf_vulnerable = 0.0
        dns_dmarc_missing_or_none = 0.0
        dns_zone_transfer_vulnerable = 0.0
        takeover_is_vulnerable = 0.0

        for r in dns_records:
            def _get_dns(attr, default=None):
                return getattr(r, attr, default) if hasattr(r, attr) else r.get(attr, default)

            rec_type = _get_dns("record_type", "")
            finding = _get_dns("finding", "")
            is_misconfig = _get_dns("is_misconfigured", False)
            is_dangling = _get_dns("is_dangling", False)

            if is_dangling or "takeover" in str(finding).lower():
                takeover_is_vulnerable = 1.0
            if "zone transfer" in str(finding).lower() or "axfr" in str(finding).lower():
                dns_zone_transfer_vulnerable = 1.0
            if "spf" in str(finding).lower() and is_misconfig:
                dns_spf_vulnerable = 1.0
            if "dmarc" in str(finding).lower() and is_misconfig:
                dns_dmarc_missing_or_none = 1.0

        # --- 5. Vulnerabilities ---
        vuln_total_count = float(len(vulns))
        cvss_list = []
        epss_list = []
        has_cisa_kev = 0.0
        crit_vuln_count = 0.0

        for v in vulns:
            def _get_v(attr, default=None):
                return getattr(v, attr, default) if hasattr(v, attr) else v.get(attr, default)

            cvss = _get_v("cvss_score")
            if cvss is not None:
                cvss_list.append(float(cvss))

            epss = _get_v("epss_score")
            if epss is not None:
                epss_list.append(float(epss))

            if _get_v("is_cisa_kev", False):
                has_cisa_kev = 1.0

            sev = str(_get_v("severity", "")).lower()
            if sev == "critical":
                crit_vuln_count += 1.0

        vuln_max_cvss = max(cvss_list) if cvss_list else 0.0
        vuln_avg_cvss = (sum(cvss_list) / len(cvss_list)) if cvss_list else 0.0
        vuln_max_epss = max(epss_list) if epss_list else 0.0

        # --- 6. Technologies ---
        tech_total_count = float(len(techs))
        tech_has_outdated = 0.0
        for t in techs:
            def _get_t(attr, default=None):
                return getattr(t, attr, default) if hasattr(t, attr) else t.get(attr, default)
            if _get_t("is_outdated", False):
                tech_has_outdated = 1.0
                break

        return {
            "num_open_ports": num_open_ports,
            "num_critical_ports": num_crit_ports,
            "has_rdp_exposed": has_rdp,
            "has_ssh_exposed": has_ssh,
            "has_db_exposed": has_db,
            "has_smb_exposed": has_smb,
            "ssl_days_until_expiry": ssl_days,
            "ssl_is_expired": ssl_is_expired,
            "ssl_is_self_signed": ssl_is_self_signed,
            "ssl_has_weak_cipher": ssl_has_weak_cipher,
            "ssl_has_weak_protocol": ssl_has_weak_protocol,
            "ssl_missing_san": ssl_missing_san,
            "header_missing_count": header_missing_count,
            "header_has_hsts": header_has_hsts,
            "header_has_csp": header_has_csp,
            "header_cors_misconfigured": header_cors_misconfigured,
            "header_score": header_score,
            "dns_spf_vulnerable": dns_spf_vulnerable,
            "dns_dmarc_missing_or_none": dns_dmarc_missing_or_none,
            "dns_zone_transfer_vulnerable": dns_zone_transfer_vulnerable,
            "takeover_is_vulnerable": takeover_is_vulnerable,
            "vuln_total_count": vuln_total_count,
            "vuln_max_cvss": vuln_max_cvss,
            "vuln_avg_cvss": vuln_avg_cvss,
            "vuln_max_epss": vuln_max_epss,
            "vuln_has_cisa_kev": has_cisa_kev,
            "vuln_critical_count": crit_vuln_count,
            "tech_total_count": tech_total_count,
            "tech_has_outdated": tech_has_outdated,
            "is_apex_domain": is_apex
        }
