"""AEGIS Reconnaissance Engine — DNS & Email Posture Analyzer

Audits DNS zone records, parses SPF mechanisms, evaluates DMARC enforcement policies,
probes DKIM selectors, and tests authoritative nameservers for DNS Zone Transfers (AXFR).
"""
import logging
import re
from typing import Dict, Any, List, Optional
import dns.resolver
import dns.query
import dns.zone
import dns.exception

logger = logging.getLogger("aegis.recon.dns")

COMMON_DKIM_SELECTORS = ["default", "google", "k1", "selector1", "mail", "s1", "s2"]


class DNSAnalyzer:
    """Performs comprehensive DNS analysis and email spoofing defense posture audit."""

    def __init__(self, timeout: float = 5.0, nameservers: Optional[List[str]] = None):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = nameservers or ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def query_records(self, domain: str) -> Dict[str, List[str]]:
        """Query standard DNS record types for a domain."""
        record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]
        results: Dict[str, List[str]] = {}

        for r_type in record_types:
            try:
                answers = self.resolver.resolve(domain, r_type)
                results[r_type] = [r.to_text().strip('"') for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                results[r_type] = []
            except Exception as e:
                logger.debug(f"Error querying {r_type} for {domain}: {e}")
                results[r_type] = []

        return results

    def audit_spf(self, txt_records: List[str]) -> Dict[str, Any]:
        """
        Parses SPF string and scores email authentication security.
        Mechanisms:
          +all (Vulnerable to spoofing, score 0)
          ?all (Neutral, score 5)
          ~all (SoftFail, score 15)
          -all (HardFail / Strict, score 25)
        """
        spf_record = None
        for txt in txt_records:
            if txt.startswith("v=spf1"):
                spf_record = txt
                break

        if not spf_record:
            return {
                "present": False,
                "record": None,
                "all_mechanism": None,
                "score": 0,
                "is_vulnerable": True,
                "finding": "Missing SPF record: Domain is vulnerable to email spoofing."
            }

        all_match = re.search(r"([\+\-\~\?])all", spf_record)
        qualifier = all_match.group(1) if all_match else None

        if qualifier == "+":
            return {
                "present": True,
                "record": spf_record,
                "all_mechanism": "+all",
                "score": 0,
                "is_vulnerable": True,
                "finding": "CRITICAL: SPF configured with '+all' allowing anyone to spoof emails from this domain."
            }
        elif qualifier == "?":
            return {
                "present": True,
                "record": spf_record,
                "all_mechanism": "?all",
                "score": 5,
                "is_vulnerable": True,
                "finding": "Weak SPF: '?all' (neutral) policy provides no spoofing protection."
            }
        elif qualifier == "~":
            return {
                "present": True,
                "record": spf_record,
                "all_mechanism": "~all",
                "score": 15,
                "is_vulnerable": False,
                "finding": "Acceptable SPF: '~all' (SoftFail) configured. Recommend '-all' for strict enforcement."
            }
        elif qualifier == "-":
            return {
                "present": True,
                "record": spf_record,
                "all_mechanism": "-all",
                "score": 25,
                "is_vulnerable": False,
                "finding": "Strong SPF: '-all' (HardFail) strictly blocks unauthorized senders."
            }

        return {
            "present": True,
            "record": spf_record,
            "all_mechanism": None,
            "score": 10,
            "is_vulnerable": False,
            "finding": "SPF record present but missing explicit 'all' qualifier."
        }

    def audit_dmarc(self, domain: str) -> Dict[str, Any]:
        """
        Queries and evaluates DMARC policy from _dmarc.<domain>.
        Policies:
          p=none (Monitoring only, score 5)
          p=quarantine (Spam folder, score 15)
          p=reject (Drop unauthorized emails, score 25)
        """
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_record = None

        try:
            answers = self.resolver.resolve(dmarc_domain, "TXT")
            for a in answers:
                txt = a.to_text().strip('"')
                if txt.startswith("v=DMARC1"):
                    dmarc_record = txt
                    break
        except Exception:
            pass

        if not dmarc_record:
            return {
                "present": False,
                "record": None,
                "policy": None,
                "score": 0,
                "is_vulnerable": True,
                "finding": "Missing DMARC record: Domain has no enforcement against phishing and impersonation."
            }

        policy_match = re.search(r"p=(none|quarantine|reject)", dmarc_record, re.IGNORECASE)
        policy = policy_match.group(1).lower() if policy_match else "none"

        if policy == "none":
            return {
                "present": True,
                "record": dmarc_record,
                "policy": "none",
                "score": 5,
                "is_vulnerable": True,
                "finding": "DMARC policy set to 'p=none' (monitoring only). Unauthorized emails are not blocked."
            }
        elif policy == "quarantine":
            return {
                "present": True,
                "record": dmarc_record,
                "policy": "quarantine",
                "score": 15,
                "is_vulnerable": False,
                "finding": "DMARC policy set to 'p=quarantine'. Unauthorized emails routed to spam."
            }
        elif policy == "reject":
            return {
                "present": True,
                "record": dmarc_record,
                "policy": "reject",
                "score": 25,
                "is_vulnerable": False,
                "finding": "Strict DMARC: 'p=reject' strictly blocks spoofed emails."
            }

        return {
            "present": True,
            "record": dmarc_record,
            "policy": policy,
            "score": 10,
            "is_vulnerable": False,
            "finding": f"DMARC record present with policy: {policy}"
        }

    def probe_dkim(self, domain: str) -> List[Dict[str, str]]:
        """Check for active DKIM public keys across common selectors."""
        found_selectors: List[Dict[str, str]] = []

        for selector in COMMON_DKIM_SELECTORS:
            dkim_query = f"{selector}._domainkey.{domain}"
            try:
                answers = self.resolver.resolve(dkim_query, "TXT")
                for a in answers:
                    txt = a.to_text().strip('"')
                    if "v=DKIM1" in txt or "p=" in txt:
                        found_selectors.append({
                            "selector": selector,
                            "record": txt[:100] + "..." if len(txt) > 100 else txt
                        })
                        break
            except Exception:
                continue

        return found_selectors

    def test_zone_transfer(self, domain: str, nameservers: List[str]) -> Dict[str, Any]:
        """
        Attempts a DNS AXFR zone transfer against authoritative nameservers.
        A successful zone transfer reveals all internal DNS mappings.
        """
        vulnerable_servers: List[str] = []

        for ns in nameservers:
            ns_clean = ns.rstrip(".")
            try:
                # Resolve nameserver IP
                ns_ips = [r.to_text() for r in self.resolver.resolve(ns_clean, "A")]
                for ip in ns_ips:
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(ip, domain, timeout=self.timeout))
                        if len(zone.nodes) > 0:
                            vulnerable_servers.append(ns_clean)
                            break
                    except Exception:
                        pass
            except Exception:
                pass

        if vulnerable_servers:
            return {
                "is_vulnerable": True,
                "vulnerable_nameservers": vulnerable_servers,
                "finding": f"CRITICAL: Nameserver(s) {vulnerable_servers} allow unauthorized AXFR DNS zone transfers!"
            }

        return {
            "is_vulnerable": False,
            "vulnerable_nameservers": [],
            "finding": "Zone transfer (AXFR) securely disabled across all authoritative nameservers."
        }

    def analyze(self, domain: str) -> Dict[str, Any]:
        """
        Full DNS audit orchestration.
        Returns DNS records and overall email/DNS security score.
        """
        domain = domain.strip().lower()
        records = self.query_records(domain)
        ns_list = records.get("NS", [])
        txt_list = records.get("TXT", [])

        spf_result = self.audit_spf(txt_list)
        dmarc_result = self.audit_dmarc(domain)
        dkim_result = self.probe_dkim(domain)
        axfr_result = self.test_zone_transfer(domain, ns_list)

        total_posture_score = spf_result["score"] + dmarc_result["score"]
        if dkim_result:
            total_posture_score += 25
        if not axfr_result["is_vulnerable"]:
            total_posture_score += 25

        findings: List[Dict[str, Any]] = []
        if spf_result["finding"]:
            findings.append({"category": "SPF", "severity": "high" if spf_result["is_vulnerable"] else "info", "message": spf_result["finding"]})
        if dmarc_result["finding"]:
            findings.append({"category": "DMARC", "severity": "high" if dmarc_result["is_vulnerable"] else "info", "message": dmarc_result["finding"]})
        if axfr_result["is_vulnerable"]:
            findings.append({"category": "AXFR", "severity": "critical", "message": axfr_result["finding"]})

        return {
            "domain": domain,
            "records": records,
            "spf": spf_result,
            "dmarc": dmarc_result,
            "dkim_selectors_found": dkim_result,
            "axfr": axfr_result,
            "dns_posture_score": total_posture_score,
            "findings": findings
        }
