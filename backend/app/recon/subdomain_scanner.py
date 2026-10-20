"""AEGIS Reconnaissance Engine — Subdomain Discovery Module

Discovers subdomains through passive intelligence (Certificate Transparency logs,
AlienVault OTX, HackerTarget) and active DNS brute-force with wildcard filtering.
"""
import asyncio
import logging
import re
import uuid
from typing import List, Set, Dict, Any, Optional
import httpx
import dns.asyncresolver
import dns.resolver

logger = logging.getLogger("aegis.recon.subdomains")

# Built-in top 120 common subdomains for active brute-forcing
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "api", "dev", "staging", "test", "portal", "admin",
    "app", "dashboard", "auth", "login", "sso", "git", "gitlab", "jenkins",
    "jira", "confluence", "kibana", "grafana", "monitor", "status", "shop",
    "store", "cpanel", "whm", "autodiscover", "sip", "m", "mobile", "cdn",
    "cloud", "dns1", "dns2", "host", "mx", "pop", "imap", "support", "help",
    "beta", "demo", "stage", "preview", "prod", "production", "internal",
    "corp", "office", "gw", "gateway", "relay", "router", "firewall", "idp",
    "vault", "bastion", "mysql", "postgres", "redis", "elastic", "db", "database",
    "assets", "static", "media", "images", "img", "files", "download", "docs",
    "wiki", "kb", "crm", "erp", "hr", "billing", "pay", "payment", "checkout",
    "v1", "v2", "graphql", "rest", "ws", "socket", "hub", "proxy", "edge",
    "lb", "traefik", "ingress", "k8s", "docker", "registry", "nexus", "artifactory",
    "metrics", "prometheus", "alertmanager", "sentry", "graylog", "splunk"
]


class SubdomainScanner:
    """Orchestrates passive and active subdomain enumeration for a target domain."""

    def __init__(self, timeout: float = 10.0, nameservers: Optional[List[str]] = None):
        self.timeout = timeout
        self.nameservers = nameservers or ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    def _get_async_resolver(self) -> dns.asyncresolver.Resolver:
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = self.nameservers
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        return resolver

    async def query_crtsh(self, domain: str) -> Set[str]:
        """Query crt.sh Certificate Transparency logs."""
        subdomains: Set[str] = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AEGIS-Recon/1.0"}

        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for item in name_value.split("\n"):
                            sub = item.strip().lower()
                            if sub.startswith("*."):
                                sub = sub[2:]
                            # Ensure it belongs strictly to this domain
                            if (sub.endswith(f".{domain}") or sub == domain) and "*" not in sub:
                                subdomains.add(sub)
        except Exception as e:
            logger.warning(f"crt.sh query for {domain} failed or timed out: {e}")

        return subdomains

    async def query_hackertarget(self, domain: str) -> Set[str]:
        """Query HackerTarget Host Search API."""
        subdomains: Set[str] = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        headers = {"User-Agent": "AEGIS-Recon/1.0"}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200 and "error" not in resp.text.lower():
                    for line in resp.text.splitlines():
                        parts = line.strip().split(",")
                        if parts:
                            sub = parts[0].strip().lower()
                            if sub.endswith(f".{domain}") or sub == domain:
                                subdomains.add(sub)
        except Exception as e:
            logger.warning(f"HackerTarget query for {domain} failed: {e}")

        return subdomains

    async def query_alienvault(self, domain: str) -> Set[str]:
        """Query AlienVault OTX Passive DNS."""
        subdomains: Set[str] = set()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        headers = {"User-Agent": "AEGIS-Recon/1.0"}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    for record in data.get("passive_dns", []):
                        hostname = record.get("hostname", "").strip().lower()
                        if hostname.endswith(f".{domain}") or hostname == domain:
                            subdomains.add(hostname)
        except Exception as e:
            logger.warning(f"AlienVault query for {domain} failed: {e}")

        return subdomains

    async def detect_wildcard(self, domain: str) -> Set[str]:
        """
        Detect wildcard DNS by resolving 3 non-existent random subdomains.
        Returns the set of wildcard IP addresses if wildcarding is active.
        """
        resolver = self._get_async_resolver()
        wildcard_ips: Set[str] = set()
        results = []

        for _ in range(3):
            rand_sub = f"aegis-rnd-{uuid.uuid4().hex[:8]}.{domain}"
            try:
                answers = await resolver.resolve(rand_sub, "A")
                ips = {r.to_text() for r in answers}
                results.append(ips)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
                results.append(set())

        # If at least 2 queries resolved to the same non-empty set of IPs, wildcard is enabled
        if len(results) == 3:
            if results[0] and (results[0] == results[1] or results[0] == results[2]):
                wildcard_ips = results[0]
            elif results[1] and results[1] == results[2]:
                wildcard_ips = results[1]

        if wildcard_ips:
            logger.info(f"Wildcard DNS detected for {domain}: {wildcard_ips}")

        return wildcard_ips

    async def resolve_host(self, hostname: str, resolver: dns.asyncresolver.Resolver) -> List[str]:
        """Resolve A records for a hostname with DNS and system socket fallback."""
        clean = hostname.strip().lower()
        if ":" in clean:
            clean = clean.split(":")[0]

        import ipaddress, socket
        try:
            ipaddress.ip_address(clean)
            return [clean]
        except ValueError:
            pass

        # 1. Try async DNS resolver
        try:
            answers = await resolver.resolve(clean, "A")
            ips = [r.to_text() for r in answers]
            if ips:
                return ips
        except Exception:
            pass

        # 2. Fallback to system socket getaddrinfo
        try:
            loop = asyncio.get_running_loop()
            addr_info = await loop.getaddrinfo(clean, None, family=socket.AF_INET)
            ips = list({res[4][0] for res in addr_info if res and len(res) > 4 and res[4]})
            if ips:
                return ips
        except Exception:
            pass

        return []

    async def brute_force(
        self,
        domain: str,
        wordlist: Optional[List[str]] = None,
        wildcard_ips: Optional[Set[str]] = None,
        concurrency: int = 20,
    ) -> Dict[str, List[str]]:
        """
        Active DNS brute-force with concurrency control and wildcard filtering.
        """
        words = wordlist or COMMON_SUBDOMAINS
        wildcard_ips = wildcard_ips or set()
        resolver = self._get_async_resolver()
        sem = asyncio.Semaphore(concurrency)
        discovered: Dict[str, List[str]] = {}

        async def _check_sub(sub: str):
            hostname = f"{sub}.{domain}".lower()
            async with sem:
                ips = await self.resolve_host(hostname, resolver)
                if ips:
                    # Filter out wildcard responses
                    filtered_ips = [ip for ip in ips if ip not in wildcard_ips]
                    if filtered_ips:
                        discovered[hostname] = filtered_ips

        tasks = [_check_sub(word) for word in words]
        await asyncio.gather(*tasks, return_exceptions=True)
        return discovered

    async def enumerate(
        self,
        domain: str,
        include_bruteforce: bool = True,
        wordlist: Optional[List[str]] = None,
        concurrency: int = 25,
    ) -> List[Dict[str, Any]]:
        """
        Runs comprehensive passive + active enumeration.
        Returns deduplicated assets list with IP resolution and discovery provenance.
        """
        # Clean domain
        clean = domain.strip().lower()
        if "://" in clean:
            from urllib.parse import urlparse
            clean = urlparse(clean).hostname or clean
        if ":" in clean:
            clean = clean.split(":")[0]
        domain = clean.split("/")[0].strip()
        logger.info(f"Starting subdomain enumeration for {domain}")

        # 1. Passive Recon Tasks
        passive_tasks = [
            self.query_crtsh(domain),
            self.query_hackertarget(domain),
            self.query_alienvault(domain),
            self.detect_wildcard(domain),
        ]
        crt_subs, ht_subs, otx_subs, wildcard_ips = await asyncio.gather(*passive_tasks)

        all_hostnames: Dict[str, Set[str]] = {}

        # Add apex domain by default
        all_hostnames[domain] = {"apex"}

        for s in crt_subs:
            all_hostnames.setdefault(s, set()).add("crt.sh")
        for s in ht_subs:
            all_hostnames.setdefault(s, set()).add("hackertarget")
        for s in otx_subs:
            all_hostnames.setdefault(s, set()).add("alienvault")

        # 2. Active Brute Force
        if include_bruteforce:
            bf_results = await self.brute_force(
                domain,
                wordlist=wordlist,
                wildcard_ips=wildcard_ips,
                concurrency=concurrency,
            )
            for h, ips in bf_results.items():
                all_hostnames.setdefault(h, set()).add("bruteforce")

        # 3. Resolve all passive hostnames that weren't resolved by brute force
        resolver = self._get_async_resolver()
        resolve_sem = asyncio.Semaphore(concurrency)
        resolved_results: Dict[str, List[str]] = {}

        async def _resolve_passive(h: str):
            async with resolve_sem:
                ips = await self.resolve_host(h, resolver)
                if ips:
                    filtered = [ip for ip in ips if ip not in wildcard_ips]
                    if filtered:
                        resolved_results[h] = filtered

        await asyncio.gather(*[_resolve_passive(h) for h in all_hostnames.keys()])

        # 4. Assemble final structured result
        assets: List[Dict[str, Any]] = []
        for hostname, sources in all_hostnames.items():
            ips = resolved_results.get(hostname, [])
            # If apex did not resolve via async resolver, force direct resolution
            if not ips and hostname == domain:
                ips = await self.resolve_host(hostname, resolver)
            if ips or hostname == domain:
                assets.append({
                    "hostname": hostname,
                    "ip_address": ips[0] if ips else None,
                    "all_ips": ips,
                    "is_apex": (hostname == domain),
                    "sources": sorted(list(sources)),
                })

        logger.info(f"Enumeration completed for {domain}: {len(assets)} valid assets discovered")
        return assets
