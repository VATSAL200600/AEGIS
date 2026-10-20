"""AEGIS AI/ML Engine — Calibrated Synthetic Training Data Generator

Generates high-fidelity training data based on CVSS v3.1, FIRST.org EPSS,
CISA KEV, and CIS benchmarks with independent feature variation to ensure
orthogonal risk learning and robust SHAP attributions.
"""
from typing import Tuple, List, Dict
import numpy as np
import pandas as pd
from app.ai.features import FEATURE_NAMES


def generate_training_data(n_samples: int = 5000, seed: int = 42) -> Tuple[pd.DataFrame, np.ndarray]:
    """
    Generates synthetic training dataset with ground-truth calibrated risk scores.
    Uses independent feature randomization across security domains to avoid artificial
    feature co-dependency (e.g. allowing RDP exposure to be evaluated independently of CVEs).
    """
    np.random.seed(seed)
    records: List[Dict[str, float]] = []
    targets: List[float] = []

    profiles = ["critical", "high", "medium", "low", "info"]
    profile_probs = [0.15, 0.25, 0.25, 0.20, 0.15]
    chosen_profiles = np.random.choice(profiles, size=n_samples, p=profile_probs)

    for profile in chosen_profiles:
        if profile == "critical":
            # Critical: At least one major severe security flaw
            # (RDP, active KEV, takeover, database, or SMB)
            flaw_type = np.random.choice(["rdp", "kev", "takeover", "db_smb", "multi"])

            has_rdp = 1.0 if flaw_type in ["rdp", "multi"] or np.random.rand() < 0.25 else 0.0
            has_db = 1.0 if flaw_type in ["db_smb", "multi"] or np.random.rand() < 0.3 else 0.0
            has_smb = 1.0 if flaw_type in ["db_smb", "multi"] or np.random.rand() < 0.25 else 0.0
            takeover = 1.0 if flaw_type in ["takeover", "multi"] or np.random.rand() < 0.25 else 0.0
            has_ssh = float(np.random.choice([0, 1], p=[0.4, 0.6]))
            num_crit_ports = float(has_rdp + has_db + has_smb + (1 if has_ssh else 0))
            num_open_ports = float(num_crit_ports + np.random.randint(1, 10))

            ssl_is_expired = float(np.random.choice([0, 1], p=[0.5, 0.5]))
            ssl_days = float(np.random.randint(-180, -1) if ssl_is_expired else np.random.randint(10, 180))
            ssl_is_self_signed = float(np.random.choice([0, 1], p=[0.6, 0.4]))
            ssl_has_weak_cipher = float(np.random.choice([0, 1], p=[0.6, 0.4]))
            ssl_has_weak_proto = float(np.random.choice([0, 1], p=[0.6, 0.4]))
            ssl_missing_san = float(np.random.choice([0, 1], p=[0.7, 0.3]))

            header_missing_count = float(np.random.randint(3, 7))
            header_has_hsts = float(np.random.choice([0, 1], p=[0.8, 0.2]))
            header_has_csp = 0.0
            header_cors_misconfigured = float(np.random.choice([0, 1], p=[0.6, 0.4]))
            header_score = float(np.random.randint(10, 45))

            dns_spf_vuln = float(np.random.choice([0, 1], p=[0.4, 0.6]))
            dns_dmarc_vuln = float(np.random.choice([0, 1], p=[0.3, 0.7]))
            dns_axfr = float(np.random.choice([0, 1], p=[0.8, 0.2]))

            if flaw_type in ["kev", "multi"] or np.random.rand() < 0.4:
                vuln_count = float(np.random.randint(2, 12))
                vuln_max_cvss = float(np.random.uniform(8.5, 10.0))
                vuln_avg_cvss = float(np.random.uniform(7.0, 9.5))
                vuln_max_epss = float(np.random.uniform(0.55, 0.98))
                vuln_has_cisa_kev = 1.0
                vuln_crit_count = float(np.random.randint(1, 5))
            else:
                vuln_count = float(np.random.randint(0, 4))
                vuln_max_cvss = float(np.random.uniform(0.0, 5.0)) if vuln_count > 0 else 0.0
                vuln_avg_cvss = vuln_max_cvss
                vuln_max_epss = float(np.random.uniform(0.0, 0.1)) if vuln_count > 0 else 0.0
                vuln_has_cisa_kev = 0.0
                vuln_crit_count = 0.0

            tech_count = float(np.random.randint(2, 8))
            tech_outdated = float(np.random.choice([0, 1], p=[0.3, 0.7]))
            is_apex = float(np.random.choice([0, 1], p=[0.8, 0.2]))

        elif profile == "high":
            # High: Serious misconfigurations (database open, expired SSL, or high CVEs)
            has_rdp = 0.0
            has_db = float(np.random.choice([0, 1], p=[0.5, 0.5]))
            has_smb = float(np.random.choice([0, 1], p=[0.8, 0.2]))
            has_ssh = float(np.random.choice([0, 1], p=[0.5, 0.5]))
            takeover = 0.0
            num_crit_ports = float(has_db + has_smb + (1 if has_ssh else 0))
            num_open_ports = float(num_crit_ports + np.random.randint(1, 8))

            ssl_is_expired = float(np.random.choice([0, 1], p=[0.6, 0.4]))
            ssl_days = float(np.random.randint(-60, -1) if ssl_is_expired else np.random.randint(5, 60))
            ssl_is_self_signed = float(np.random.choice([0, 1], p=[0.7, 0.3]))
            ssl_has_weak_cipher = float(np.random.choice([0, 1], p=[0.6, 0.4]))
            ssl_has_weak_proto = float(np.random.choice([0, 1], p=[0.7, 0.3]))
            ssl_missing_san = float(np.random.choice([0, 1], p=[0.8, 0.2]))

            header_missing_count = float(np.random.randint(3, 6))
            header_has_hsts = float(np.random.choice([0, 1], p=[0.7, 0.3]))
            header_has_csp = 0.0
            header_cors_misconfigured = float(np.random.choice([0, 1], p=[0.8, 0.2]))
            header_score = float(np.random.randint(25, 55))

            dns_spf_vuln = float(np.random.choice([0, 1], p=[0.5, 0.5]))
            dns_dmarc_vuln = float(np.random.choice([0, 1], p=[0.4, 0.6]))
            dns_axfr = 0.0

            vuln_count = float(np.random.randint(1, 6))
            vuln_max_cvss = float(np.random.uniform(6.5, 8.5)) if vuln_count > 0 else 0.0
            vuln_avg_cvss = vuln_max_cvss * float(np.random.uniform(0.7, 1.0))
            vuln_max_epss = float(np.random.uniform(0.15, 0.50)) if vuln_count > 0 else 0.0
            vuln_has_cisa_kev = 0.0
            vuln_crit_count = 0.0

            tech_count = float(np.random.randint(2, 6))
            tech_outdated = float(np.random.choice([0, 1], p=[0.5, 0.5]))
            is_apex = float(np.random.choice([0, 1], p=[0.7, 0.3]))

        elif profile == "medium":
            has_rdp = 0.0
            has_db = 0.0
            has_smb = 0.0
            has_ssh = float(np.random.choice([0, 1], p=[0.7, 0.3]))
            takeover = 0.0
            num_crit_ports = float(has_ssh)
            num_open_ports = float(num_crit_ports + np.random.randint(1, 5))

            ssl_is_expired = 0.0
            ssl_days = float(np.random.randint(20, 120))
            ssl_is_self_signed = 0.0
            ssl_has_weak_cipher = float(np.random.choice([0, 1], p=[0.8, 0.2]))
            ssl_has_weak_proto = 0.0
            ssl_missing_san = 0.0

            header_missing_count = float(np.random.randint(2, 5))
            header_has_hsts = float(np.random.choice([0, 1], p=[0.5, 0.5]))
            header_has_csp = float(np.random.choice([0, 1], p=[0.7, 0.3]))
            header_cors_misconfigured = 0.0
            header_score = float(np.random.randint(45, 75))

            dns_spf_vuln = float(np.random.choice([0, 1], p=[0.6, 0.4]))
            dns_dmarc_vuln = float(np.random.choice([0, 1], p=[0.5, 0.5]))
            dns_axfr = 0.0

            vuln_count = float(np.random.randint(0, 3))
            vuln_max_cvss = float(np.random.uniform(3.5, 6.0)) if vuln_count > 0 else 0.0
            vuln_avg_cvss = vuln_max_cvss
            vuln_max_epss = float(np.random.uniform(0.01, 0.15)) if vuln_count > 0 else 0.0
            vuln_has_cisa_kev = 0.0
            vuln_crit_count = 0.0

            tech_count = float(np.random.randint(1, 5))
            tech_outdated = float(np.random.choice([0, 1], p=[0.6, 0.4]))
            is_apex = float(np.random.choice([0, 1], p=[0.6, 0.4]))

        elif profile == "low":
            has_rdp = 0.0
            has_db = 0.0
            has_smb = 0.0
            has_ssh = 0.0
            takeover = 0.0
            num_crit_ports = 0.0
            num_open_ports = float(np.random.randint(1, 3))

            ssl_is_expired = 0.0
            ssl_days = float(np.random.randint(60, 300))
            ssl_is_self_signed = 0.0
            ssl_has_weak_cipher = 0.0
            ssl_has_weak_proto = 0.0
            ssl_missing_san = 0.0

            header_missing_count = float(np.random.randint(1, 3))
            header_has_hsts = 1.0
            header_has_csp = float(np.random.choice([0, 1], p=[0.4, 0.6]))
            header_cors_misconfigured = 0.0
            header_score = float(np.random.randint(70, 88))

            dns_spf_vuln = 0.0
            dns_dmarc_vuln = float(np.random.choice([0, 1], p=[0.7, 0.3]))
            dns_axfr = 0.0

            vuln_count = float(np.random.choice([0, 1], p=[0.8, 0.2]))
            vuln_max_cvss = float(np.random.uniform(2.0, 4.0)) if vuln_count > 0 else 0.0
            vuln_avg_cvss = vuln_max_cvss
            vuln_max_epss = float(np.random.uniform(0.001, 0.03)) if vuln_count > 0 else 0.0
            vuln_has_cisa_kev = 0.0
            vuln_crit_count = 0.0

            tech_count = float(np.random.randint(1, 4))
            tech_outdated = 0.0
            is_apex = float(np.random.choice([0, 1], p=[0.5, 0.5]))

        else:
            # Info / Clean
            has_rdp = 0.0
            has_db = 0.0
            has_smb = 0.0
            has_ssh = 0.0
            takeover = 0.0
            num_crit_ports = 0.0
            num_open_ports = float(np.random.choice([1, 2], p=[0.7, 0.3]))

            ssl_is_expired = 0.0
            ssl_days = float(np.random.randint(90, 365))
            ssl_is_self_signed = 0.0
            ssl_has_weak_cipher = 0.0
            ssl_has_weak_proto = 0.0
            ssl_missing_san = 0.0

            header_missing_count = float(np.random.choice([0, 1], p=[0.8, 0.2]))
            header_has_hsts = 1.0
            header_has_csp = 1.0
            header_cors_misconfigured = 0.0
            header_score = float(np.random.randint(90, 100))

            dns_spf_vuln = 0.0
            dns_dmarc_vuln = 0.0
            dns_axfr = 0.0

            vuln_count = 0.0
            vuln_max_cvss = 0.0
            vuln_avg_cvss = 0.0
            vuln_max_epss = 0.0
            vuln_has_cisa_kev = 0.0
            vuln_crit_count = 0.0

            tech_count = float(np.random.randint(1, 3))
            tech_outdated = 0.0
            is_apex = float(np.random.choice([0, 1], p=[0.4, 0.6]))

        # Mathematical Ground Truth Formula
        raw_score = 10.0  # Baseline minimal asset presence
        raw_score += has_rdp * 38.0
        raw_score += takeover * 35.0
        raw_score += vuln_has_cisa_kev * 28.0
        raw_score += has_db * 22.0
        raw_score += has_smb * 22.0
        raw_score += dns_axfr * 25.0
        raw_score += ssl_is_expired * 18.0
        raw_score += ssl_is_self_signed * 14.0
        raw_score += ssl_has_weak_proto * 10.0
        raw_score += ssl_has_weak_cipher * 8.0
        raw_score += header_cors_misconfigured * 12.0

        raw_score += vuln_max_epss * 22.0
        raw_score += vuln_max_cvss * 2.8
        raw_score += vuln_crit_count * 5.0
        raw_score += num_crit_ports * 3.5
        raw_score += num_open_ports * 0.6
        raw_score += tech_outdated * 6.0
        raw_score += dns_spf_vuln * 8.0
        raw_score += dns_dmarc_vuln * 6.0
        raw_score += header_missing_count * 1.2

        if header_has_hsts > 0:
            raw_score -= 8.0
        if header_has_csp > 0:
            raw_score -= 6.0
        raw_score -= (header_score / 100.0) * 8.0

        # Gaussian regression jitter
        noise = np.random.normal(0, 1.0)
        final_score = float(np.clip(raw_score + noise, 0.0, 100.0))

        feat_dict = {
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
            "ssl_has_weak_protocol": ssl_has_weak_proto,
            "ssl_missing_san": ssl_missing_san,
            "header_missing_count": header_missing_count,
            "header_has_hsts": header_has_hsts,
            "header_has_csp": header_has_csp,
            "header_cors_misconfigured": header_cors_misconfigured,
            "header_score": header_score,
            "dns_spf_vulnerable": dns_spf_vuln,
            "dns_dmarc_missing_or_none": dns_dmarc_vuln,
            "dns_zone_transfer_vulnerable": dns_axfr,
            "takeover_is_vulnerable": takeover,
            "vuln_total_count": vuln_count,
            "vuln_max_cvss": vuln_max_cvss,
            "vuln_avg_cvss": vuln_avg_cvss,
            "vuln_max_epss": vuln_max_epss,
            "vuln_has_cisa_kev": vuln_has_cisa_kev,
            "vuln_critical_count": vuln_crit_count,
            "tech_total_count": tech_count,
            "tech_has_outdated": tech_outdated,
            "is_apex_domain": is_apex
        }

        records.append(feat_dict)
        targets.append(round(final_score, 2))

    df_X = pd.DataFrame(records, columns=FEATURE_NAMES)
    arr_y = np.array(targets, dtype=np.float32)

    return df_X, arr_y
