"""AEGIS Reconnaissance Engine — Asynchronous TCP Port Scanner & Service Prober

High-performance native socket scanner supporting top-100 port enumeration,
banner grabbing, service identification, and critical exposure classification.
"""
import asyncio
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger("aegis.recon.ports")

# Top 100 Critical & Common Internet-Facing Ports
TOP_100_PORTS = [
    20, 21, 22, 23, 25, 53, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 179, 389, 443, 445, 465, 500, 514, 515, 520, 523, 548, 554,
    587, 631, 636, 873, 902, 990, 993, 995, 1025, 1080, 1194, 1433, 1434,
    1521, 1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2222, 3000,
    3128, 3306, 3389, 4000, 4443, 4500, 5000, 5060, 5222, 5432, 5601, 5672,
    5900, 5901, 5984, 5985, 5986, 6379, 7001, 8000, 8008, 8080, 8081, 8088,
    8090, 8443, 8500, 8888, 9000, 9042, 9090, 9092, 9100, 9200, 9300, 9418,
    9999, 10000, 11211, 27017, 27018, 28017, 50000, 6443
]

# Quick Scan Profile: Top 20 Most Exposed Ports
TOP_20_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389,
    5432, 5900, 6379, 8080, 8443, 27017
]

# Ports that represent severe security liabilities if exposed publicly
CRITICAL_PORTS = {
    21: "FTP (Plaintext Credentials)",
    22: "SSH (Remote Administration)",
    23: "Telnet (Unencrypted Remote Shell)",
    135: "MSRPC (Windows RPC Endpoint)",
    139: "NetBIOS (Windows File Sharing)",
    445: "SMB (EternalBlue/WannaCry Vector)",
    1433: "MSSQL (Database Exposure)",
    1521: "Oracle DB (Database Exposure)",
    2049: "NFS (Network File System)",
    3306: "MySQL (Database Exposure)",
    3389: "RDP (Remote Desktop Protocol)",
    5432: "PostgreSQL (Database Exposure)",
    5900: "VNC (Unencrypted Screen Share)",
    6379: "Redis (Unauthenticated Key-Value Store)",
    9200: "Elasticsearch (Search Index Data Exposure)",
    27017: "MongoDB (NoSQL Database Exposure)"
}

# Standard Port-to-Service Mapping
PORT_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 69: "tftp", 80: "http", 88: "kerberos", 110: "pop3",
    111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    179: "bgp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 500: "isakmp", 514: "syslog", 587: "submission",
    631: "ipp", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s",
    1080: "socks", 1194: "openvpn", 1433: "ms-sql-s", 1521: "oracle",
    1723: "pptp", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
    3000: "node-http", 3128: "squid-proxy", 3306: "mysql", 3389: "ms-wbt-server",
    4000: "dev-http", 5000: "flask-http", 5432: "postgresql", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 6379: "redis", 7001: "weblogic",
    8000: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8443: "https-alt",
    8500: "consul", 8888: "http-alt", 9000: "sonarqube", 9090: "prometheus",
    9092: "kafka", 9200: "elasticsearch", 9418: "git", 10000: "webmin",
    11211: "memcached", 27017: "mongodb", 6443: "k8s-api", 4280: "http-alt"
}


class PortScanner:
    """High-performance async port scanner with service fingerprinting."""

    def __init__(self, timeout: float = 1.5, concurrency: int = 50):
        self.timeout = timeout
        self.concurrency = concurrency
        self.semaphore = asyncio.Semaphore(concurrency)

    async def probe_port(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """
        Scan a single TCP port using asyncio.open_connection.
        Grabs banner if connection succeeds.
        """
        async with self.semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )

                banner = ""
                try:
                    # Send appropriate probe based on port type
                    if port in [80, 8080, 8000, 8081, 8888, 3000, 5000, 4280]:
                        writer.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: AEGIS-Scanner\r\n\r\n".encode())
                        await writer.drain()
                    elif port in [21, 22, 25, 110, 143, 6379]:
                        # Protocol banners are sent by server on initial connect
                        pass

                    # Read up to 512 bytes with short 1.0s timeout
                    banner_bytes = await asyncio.wait_for(reader.read(512), timeout=1.0)
                    banner = banner_bytes.decode("utf-8", errors="ignore").strip()
                except Exception:
                    pass
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

                service = self._identify_service(port, banner)
                is_critical = port in CRITICAL_PORTS

                return {
                    "port_number": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service_name": service,
                    "service_version": self._extract_version(banner),
                    "banner": banner[:300] if banner else None,
                    "is_critical": is_critical,
                    "critical_reason": CRITICAL_PORTS.get(port) if is_critical else None
                }
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
            except Exception as e:
                logger.debug(f"Error scanning {host}:{port}: {e}")
                return None

    def _identify_service(self, port: int, banner: str) -> str:
        """Infer service name from port and banner content."""
        if banner:
            b_lower = banner.lower()
            if "ssh" in b_lower:
                return "ssh"
            if "nginx" in b_lower:
                return "nginx"
            if "apache" in b_lower:
                return "apache"
            if "microsoft-httpapi" in b_lower or "iis" in b_lower:
                return "iis"
            if "redis" in b_lower:
                return "redis"
            if "mysql" in b_lower or "mariadb" in b_lower:
                return "mysql"
            if "postgres" in b_lower:
                return "postgresql"
            if "postfix" in b_lower or "esmtp" in b_lower:
                return "smtp"
            if "ftp" in b_lower:
                return "ftp"

        return PORT_SERVICES.get(port, f"unknown-{port}")

    def _extract_version(self, banner: str) -> Optional[str]:
        """Extract software version from raw banner string."""
        if not banner:
            return None
        import re
        # Look for Server: <name>/<version> or SSH-2.0-<name>_<version>
        match = re.search(r"(?:Server:\s*|SSH-2\.0-)?([A-Za-z0-9_-]+)[/_\s]([0-9]+(?:\.[0-9]+)+(?:-[a-zA-Z0-9]+)?)", banner)
        if match:
            return f"{match.group(1)} {match.group(2)}"
        return None

    async def scan_host(
        self,
        host: str,
        ports: Optional[List[int]] = None,
        profile: str = "standard"
    ) -> List[Dict[str, Any]]:
        """
        Scan a host for open ports.
        Profiles:
          - 'quick': TOP_20_PORTS
          - 'standard' or 'deep': TOP_100_PORTS
        """
        if ports is None:
            ports = TOP_20_PORTS if profile == "quick" else TOP_100_PORTS

        logger.info(f"Port scanning {host} across {len(ports)} ports (profile={profile})")
        tasks = [self.probe_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks)

        open_ports = [r for r in results if r is not None]
        # Sort ports ascending
        open_ports.sort(key=lambda x: x["port_number"])
        logger.info(f"Scan complete for {host}: found {len(open_ports)} open ports")
        return open_ports
