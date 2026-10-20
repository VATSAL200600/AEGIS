# AEGIS — Reconnaissance Engine Specification

**Document**: 04_RECON_ENGINE_SPEC.md  
**Version**: 1.0  
**Target Audience**: AI Agents & Engineers implementing the AEGIS scanning engine  

---

## 1. Architecture Overview

The Reconnaissance Engine is designed as a pipeline of independent, concurrent, and fault-tolerant scanner modules coordinated by the `ScanOrchestrator`.

```
Target Domain (e.g., example.com)
       │
       ▼
┌────────────────────────────────────────┐
│  Stage 1: Asset Discovery              │
│  - crt.sh (Passive CT Logs)            │
│  - AlienVault OTX & HackerTarget APIs  │
│  - Active DNS Brute-Force (Wordlist)   │
│  - Wildcard DNS Filtering Engine       │
└───────────────────┬────────────────────┘
                    │ List of Unique FQDNs & Resolved IPs
                    ▼
┌────────────────────────────────────────┐
│  Stage 2: Network & Service Mapping    │
│  - Async TCP Socket Scanner (Top 100)  │
│  - Banner Grabbing & Service Probes    │
│  - HTTP/HTTPS Service Detection        │
└───────────────────┬────────────────────┘
                    │ Open Ports & Endpoints
                    ▼
┌────────────────────────────────────────┐
│  Stage 3: Deep Asset Inspection        │
│  - Tech Detector (Wappalyzer + mmh3)   │
│  - SSL/TLS Certificate & Cipher Audit  │
│  - Security Header & CORS Evaluator    │
│  - DNS Posture (SPF, DMARC, DKIM, AXFR)│
│  - Subdomain Takeover Risk Auditor     │
└───────────────────┬────────────────────┘
                    │ Raw Findings
                    ▼
┌────────────────────────────────────────┐
│  Stage 4: Threat Intelligence & AI     │
│  - CVE Lookup & CISA KEV Cross-Ref     │
│  - FIRST.org EPSS Exploit Probability  │
│  - AbuseIPDB & Shodan InternetDB       │
│  - XGBoost Risk Scoring + SHAP Explains│
└────────────────────────────────────────┘
```

---

## 2. Module 1: Subdomain Discovery (`subdomain_scanner.py`)

### 2.1 Purpose
Discover all valid fully-qualified domain names (FQDNs) associated with the target apex domain without triggering active intrusion detection systems on the target network.

### 2.2 Passive Sources (Zero-Packet Footprint)

#### A. Certificate Transparency Logs (`crt.sh`)
- **Endpoint**: `https://crt.sh/?q=%.{domain}&output=json`
- **Method**: HTTP GET with User-Agent header and 15s timeout
- **Parsing Logic**:
  ```python
  import httpx
  import re

  async def query_crtsh(domain: str) -> set[str]:
      subdomains = set()
      url = f"https://crt.sh/?q=%.{domain}&output=json"
      try:
          async with httpx.AsyncClient(timeout=15.0) as client:
              resp = await client.get(url, headers={"User-Agent": "AEGIS-Recon/1.0"})
              if resp.status_code == 200:
                  data = resp.json()
                  for entry in data:
                      name_value = entry.get("name_value", "")
                      # Entries may contain newlines or wildcards
                      for sub in name_value.split("\n"):
                          sub = sub.strip().lower()
                          if sub.startswith("*."):
                              sub = sub[2:]
                          if sub.endswith(f".{domain}") and sub != domain:
                              subdomains.add(sub)
      except Exception as e:
          # Log warning; crt.sh can be rate-limited or slow
          pass
      return subdomains
  ```

#### B. HackerTarget API
- **Endpoint**: `https://api.hackertarget.com/hostsearch/?q={domain}`
- **Parsing**: Returns plain text lines in `subdomain,ip` format. Split lines by comma, extract item 0.

#### C. AlienVault OTX
- **Endpoint**: `https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns`
- **Parsing**: Extract `entry['hostname']` from `data.get('passive_dns', [])`.

### 2.3 Active DNS Brute-Force with Wildcard Detection

#### A. Wildcard DNS Filtering Algorithm
Many domains configure a wildcard DNS record (`*.example.com -> IP`). Without filtering, brute force returns thousands of false positives.
```python
import dns.resolver
import uuid

async def detect_wildcard(domain: str, resolver: dns.resolver.Resolver) -> set[str]:
    """
    Query 3 guaranteed non-existent random subdomains.
    If they resolve to the same IP set, wildcard DNS is enabled.
    """
    wildcard_ips = set()
    random_subdomains = [f"nonexistent-{uuid.uuid4().hex[:8]}.{domain}" for _ in range(3)]
    results = []
    
    for rand_sub in random_subdomains:
        try:
            answers = resolver.resolve(rand_sub, 'A')
            ips = {r.to_text() for r in answers}
            results.append(ips)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            results.append(set())
            
    # If at least 2 of 3 resolved to common IPs, mark as wildcard IPs
    if len(results) == 3 and results[0] and (results[0] == results[1] or results[0] == results[2]):
        wildcard_ips = results[0]
    return wildcard_ips
```

#### B. Brute-Force Enumeration
- Uses top 500 common subdomains list (`www`, `mail`, `api`, `dev`, `staging`, `vpn`, etc.).
- Concurrency controlled by `asyncio.Semaphore(20)`.
- Custom public resolvers (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`) to avoid ISP rate-limiting or poisoning.
- Filter out any resolved IP that matches `wildcard_ips`.

---

## 3. Module 2: Port Scanner & Service Prober (`port_scanner.py`)

### 3.1 Scanning Strategy
Rather than spawning heavy external tools like Nmap, AEGIS implements an ultra-fast, native asynchronous TCP connect scanner using Python's `asyncio.open_connection`.

### 3.2 Top 100 Port List
AEGIS scans the top 100 most critical ports covering:
- Web: `80, 443, 8080, 8443, 8000, 8888, 9000, 9090, 3000, 5000`
- Remote Admin: `22 (SSH), 23 (Telnet), 3389 (RDP), 5900 (VNC)`
- Database: `1433 (MSSQL), 1521 (Oracle), 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 27017 (MongoDB), 9200 (Elasticsearch)`
- Directory/File: `21 (FTP), 445 (SMB), 139 (NetBIOS), 389 (LDAP), 636 (LDAPS)`
- Email/Network: `25 (SMTP), 53 (DNS), 110 (POP3), 143 (IMAP), 993 (IMAPS), 995 (POP3S)`

### 3.3 Port Scan Core Engine
```python
import asyncio
import socket

class PortScanner:
    def __init__(self, timeout: float = 1.5, concurrency: int = 50):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)

    async def scan_port(self, host: str, port: int) -> dict | None:
        async with self.semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )
                
                # Attempt light banner grabbing
                banner = ""
                try:
                    # For HTTP/HTTPS ports, send a quick HEAD request
                    if port in [80, 8080, 8000, 8888]:
                        writer.write(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                        await writer.drain()
                    elif port in [21, 22, 25, 110]:
                        # Plain banner is sent on connect
                        pass
                        
                    banner_bytes = await asyncio.wait_for(reader.read(512), timeout=1.0)
                    banner = banner_bytes.decode('utf-8', errors='ignore').strip()
                except Exception:
                    pass
                finally:
                    writer.close()
                    await writer.wait_closed()

                service = self.identify_service(port, banner)
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner[:255] if banner else None,
                    "is_critical": port in [21, 22, 23, 445, 1433, 3306, 3389, 5432, 6379, 27017]
                }
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None

    def identify_service(self, port: int, banner: str) -> str:
        # Match banner signatures or fall back to standard IANA mappings
        if banner:
            b_lower = banner.lower()
            if "ssh" in b_lower: return "ssh"
            if "nginx" in b_lower: return "nginx-http"
            if "apache" in b_lower: return "apache-http"
            if "redis" in b_lower: return "redis"
            if "mysql" in b_lower or "mariadb" in b_lower: return "mysql"
            if "postfix" in b_lower or "esmtp" in b_lower: return "smtp"
        return PORT_SERVICES.get(port, f"unknown-{port}")
```

---

## 4. Module 3: Technology Detector (`tech_detector.py`)

### 4.1 Fingerprinting Techniques
AEGIS combines 4 distinct fingerprinting layers:
1. **HTTP Response Headers**: `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`, `Via`.
2. **HTML Meta Tags & Scripts**: `<meta name="generator">`, inline script sources (e.g. `wp-content`, `/_next/static/`, `runtime.esm.js`).
3. **HTML DOM Elements & Comments**: Specific IDs, classes, React root divs (`id="__next"`, `id="root"`, `<app-root>`).
4. **MurmurHash3 Favicon Fingerprinting**: Downloading `/favicon.ico` and calculating its MurmurHash3 value to match known databases (Spring Boot, Jenkins, Grafana, etc.).

### 4.2 MurmurHash3 Algorithm Specification
The exact Shodan-compatible favicon hash implementation:
```python
import base64
import mmh3
import httpx

async def get_favicon_hash(target_url: str) -> int | None:
    """
    Computes Shodan-compatible MurmurHash3 of a favicon.
    Format: base64-encoded with RFC2048-style 76-char line wraps, hashed with mmh3.
    """
    try:
        fav_url = f"{target_url.rstrip('/')}/favicon.ico"
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            resp = await client.get(fav_url)
            if resp.status_code == 200 and len(resp.content) > 0:
                # Encode in base64 with newlines every 76 characters
                b64 = base64.encodebytes(resp.content)
                return mmh3.hash(b64)
    except Exception:
        pass
    return None
```

### 4.3 Embedded Signature Rules
```python
TECH_SIGNATURES = [
    {"name": "WordPress", "category": "CMS", "header": {}, "html_regex": [r"wp-content", r"wp-includes"], "meta": {"generator": r"WordPress"}},
    {"name": "Next.js", "category": "Framework", "header": {"x-powered-by": r"Next\.js"}, "html_regex": [r"/_next/static/", r"<div id=\"__next\">"]},
    {"name": "React", "category": "Frontend Library", "header": {}, "html_regex": [r"react-dom", r"__reactFiber"]},
    {"name": "Vue.js", "category": "Frontend Library", "header": {}, "html_regex": [r"vue\.min\.js", r"data-v-[a-f0-9]+"]},
    {"name": "Angular", "category": "Frontend Framework", "header": {}, "html_regex": [r"<app-root", r"ng-version"]},
    {"name": "Laravel", "category": "Backend Framework", "header": {"set-cookie": r"laravel_session"}, "html_regex": []},
    {"name": "Django", "category": "Backend Framework", "header": {"set-cookie": r"csrftoken"}, "html_regex": [r"csrfmiddlewaretoken"]},
    {"name": "Nginx", "category": "Web Server", "header": {"server": r"nginx(?:/([\d.]+))?"}, "html_regex": []},
    {"name": "Apache", "category": "Web Server", "header": {"server": r"Apache(?:/([\d.]+))?"}, "html_regex": []},
    {"name": "Cloudflare", "category": "CDN / WAF", "header": {"cf-ray": r".+", "server": r"cloudflare"}, "html_regex": []},
    {"name": "Swagger UI", "category": "API Documentation", "header": {}, "html_regex": [r"swagger-ui\.css", r"SwaggerUIBundle"]}
]
```

---

## 5. Module 4: SSL/TLS & Certificate Inspector (`ssl_analyzer.py`)

### 5.1 Analysis Pipeline
For any asset running on port 443, 8443, or web services:
1. Establish TLS connection using `ssl.create_default_context()`.
2. Extract Peer Certificate using `cryptography.x509`.
3. Check Expiration Date (`not_valid_after`) and calculate remaining days.
4. Verify Subject Alternative Names (SANs) to identify additional asset subdomains.
5. Check for Self-Signed certificates (`issuer == subject`).
6. Enumerate supported TLS protocol versions (flagging deprecated TLS 1.0, TLS 1.1).
7. Flag weak cipher suites (DES, 3DES, RC4, MD5, NULL, export ciphers).

### 5.2 Implementation
```python
import ssl
import socket
from datetime import datetime, timezone
from cryptography import x509

def inspect_ssl(hostname: str, port: int = 443) -> dict:
    result = {
        "is_valid": False,
        "issuer": None,
        "subject": None,
        "expires_in_days": 0,
        "is_expired": False,
        "is_self_signed": False,
        "protocol_version": None,
        "cipher": None,
        "san_list": [],
        "errors": []
    }
    
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Allow inspecting untrusted certs
    
    try:
        with socket.create_connection((hostname, port), timeout=3.0) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                protocol = ssock.version()
                
                result["protocol_version"] = protocol
                result["cipher"] = cipher[0] if cipher else None
                
                # Parse with cryptography
                cert = x509.load_der_x509_certificate(der_cert)
                now = datetime.now(timezone.utc)
                expire_date = cert.not_valid_after_utc
                days_left = (expire_date - now).days
                
                result["expires_in_days"] = days_left
                result["is_expired"] = days_left < 0
                result["issuer"] = cert.issuer.rfc4514_string()
                result["subject"] = cert.subject.rfc4514_string()
                result["is_self_signed"] = result["issuer"] == result["subject"]
                
                # Extract SANs
                try:
                    san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    result["san_list"] = san_ext.value.get_values_for_type(x509.DNSName)
                except Exception:
                    pass
                
                result["is_valid"] = (not result["is_expired"]) and (not result["is_self_signed"])
    except Exception as e:
        result["errors"].append(str(e))
        
    return result
```

---

## 6. Module 5: Security Header & CORS Evaluator (`header_auditor.py`)

### 6.1 Graded Headers
| Header | Recommended Configuration | Weight |
|---|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | 20 pts |
| `Content-Security-Policy` | Well-defined directives, no `unsafe-inline` | 25 pts |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | 15 pts |
| `X-Content-Type-Options` | `nosniff` | 15 pts |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or `no-referrer` | 10 pts |
| `Permissions-Policy` | Restricting camera, microphone, geolocation | 10 pts |
| `CORS Evaluation` | No wildcard `*` with credentials | 5 pts |

### 6.2 Letter Grade Algorithm
- **Score >= 90**: **A+**
- **Score 80–89**: **A**
- **Score 70–79**: **B**
- **Score 55–69**: **C**
- **Score 40–54**: **D**
- **Score < 40**: **F**

### 6.3 CORS Misconfiguration Checker
Send test request with custom Origin header: `Origin: https://evil-attacker.com`.
- If response contains `Access-Control-Allow-Origin: https://evil-attacker.com` AND `Access-Control-Allow-Credentials: true`:
  - **Flag Critical Severity Vulnerability**: Arbitrary Origin Reflection with Credentials.

---

## 7. Module 6: DNS & Email Security Analyzer (`dns_analyzer.py`)

### 7.1 Checks Performed
1. **SPF Record (`TXT`)**:
   - Check if SPF string `v=spf1 ...` exists.
   - Parse mechanism: `+all` (Vulnerable, score = 0), `?all` (Neutral, score = 5), `~all` (SoftFail, score = 15), `-all` (HardFail, score = 25).
2. **DMARC Record (`_dmarc.{domain}`)**:
   - Check if `v=DMARC1 ...` exists.
   - Parse policy: `p=none` (Monitoring only, score = 5), `p=quarantine` (score = 15), `p=reject` (Strict protection, score = 25).
3. **DKIM Record Probing**:
   - Check common selectors: `default._domainkey.{domain}`, `google._domainkey.{domain}`, `selector1._domainkey.{domain}`, `k1._domainkey.{domain}`.
4. **Zone Transfer (AXFR) Test**:
   - Attempt DNS AXFR query against authoritative name servers. If successful, flag as **Critical Severity**: Full DNS Zone Leak.

---

## 8. Module 7: Subdomain Takeover Detector (`takeover_auditor.py`)

### 8.1 Mechanism
When a subdomain's `CNAME` record points to a third-party service (e.g. AWS S3, GitHub Pages), but the bucket or tenant has been deleted, an attacker can register the resource on that cloud provider and take full control of the subdomain.

### 8.2 Fingerprint Signatures Database
```python
TAKEOVER_SIGNATURES = [
    {
        "service": "GitHub Pages",
        "cname_suffix": [".github.io"],
        "response_regex": r"There isn't a GitHub Pages site here\.",
        "status_code": 404
    },
    {
        "service": "Amazon S3",
        "cname_suffix": [".s3.amazonaws.com", ".s3-website"],
        "response_regex": r"<Code>NoSuchBucket</Code>",
        "status_code": 404
    },
    {
        "service": "Heroku",
        "cname_suffix": [".herokuapp.com", ".herokudns.com"],
        "response_regex": r"No such app",
        "status_code": 503
    },
    {
        "service": "Azure App Service",
        "cname_suffix": [".azurewebsites.net"],
        "response_regex": r"404 Web Site not found",
        "status_code": 404
    },
    {
        "service": "Shopify",
        "cname_suffix": [".myshopify.com"],
        "response_regex": r"Sorry, this shop is currently unavailable",
        "status_code": 404
    },
    {
        "service": "Surge.sh",
        "cname_suffix": [".surge.sh"],
        "response_regex": r"project not found",
        "status_code": 404
    },
    {
        "service": "Ghost",
        "cname_suffix": [".ghost.io"],
        "response_regex": r"The thing you were looking for is no longer here",
        "status_code": 404
    },
    {
        "service": "Pantheon",
        "cname_suffix": [".pantheonsite.io"],
        "response_regex": r"404 error unknown site!",
        "status_code": 404
    }
]
```

---

## 9. Module 8: Threat Intelligence Clients (`intel/`)

### 9.1 FIRST.org EPSS Client (`epss_client.py`)
- **API URL**: `https://api.first.org/data/v1/epss?cve={cve_id}`
- **Response**:
  ```json
  {
    "status": "OK",
    "data": [
      {
        "cve": "CVE-2021-44228",
        "epss": "0.975420000",
        "percentile": "0.999880000"
      }
    ]
  }
  ```
- **Caching**: Cache all EPSS queries in SQLite `threat_intel` table with 24-hour TTL.

### 9.2 CISA Known Exploited Vulnerabilities (`cisa_kev.py`)
- **Data Source**: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- **Logic**:
  - Download JSON on backend startup or daily cron.
  - Store indexed set of active CVE IDs in memory: `cisa_kev_set: set[str]`.
  - O(1) instantaneous lookup for any identified CVE.
  - If `cve_id in cisa_kev_set`: Mark `is_kev = True`, immediately boost risk score feature.

### 9.3 Shodan InternetDB (Free, Zero-API-Key Enrichment)
- **API URL**: `https://internetdb.shodan.io/{ip_address}`
- **Returns**: Open ports, known CVEs, hostnames, and CPEs for any public IPv4 address without needing an API key.

---

## 10. Scan Orchestrator Engine (`orchestrator.py`)

### 10.1 Execution Workflow & State Machine
```python
class ScanStatus(str, Enum):
    PENDING = "pending"
    DISCOVERING_SUBDOMAINS = "discovering_subdomains"
    PORT_SCANNING = "port_scanning"
    INSPECTING_ASSETS = "inspecting_assets"
    ENRICHING_INTEL = "enriching_intel"
    SCORING_RISK = "scoring_risk"
    GENERATING_REPORT = "generating_report"
    COMPLETED = "completed"
    FAILED = "failed"
```

### 10.2 Progress Callback System
The orchestrator emits progress events stored in the database and streamed to the UI via SSE:
```json
{
  "scan_id": "scan_8f12a",
  "phase": "port_scanning",
  "progress_percent": 45,
  "current_asset": "api.example.com",
  "assets_found": 14,
  "ports_found": 26,
  "vulns_found": 3,
  "log_message": "Port 3389 (RDP) detected open on dev.example.com"
}
```
