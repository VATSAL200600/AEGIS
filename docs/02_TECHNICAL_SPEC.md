# AEGIS — Technical Specification

**Version**: 1.0  
**For**: Any AI or developer building this project  

---

## 1. System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        FRONTEND (React + Vite)                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │Dashboard │ │ Assets   │ │  Scans   │ │ Reports  │           │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘           │
│       └─────────────┴─────────────┴────────────┘                │
│                          │  HTTP/REST                           │
└──────────────────────────┼──────────────────────────────────────┘
                           │
┌──────────────────────────┼──────────────────────────────────────┐
│                    BACKEND (FastAPI)                             │
│                          │                                      │
│  ┌───────────────────────┴───────────────────────────┐          │
│  │                  REST API Layer                    │          │
│  │  /api/scans  /api/assets  /api/reports  /api/dash │          │
│  └───────┬──────────┬──────────────┬─────────────────┘          │
│          │          │              │                             │
│  ┌───────▼────┐ ┌───▼────────┐ ┌──▼──────────┐                 │
│  │   Scan     │ │  AI Risk   │ │   Report    │                 │
│  │Orchestrator│ │  Engine    │ │  Generator  │                 │
│  └──┬──┬──┬───┘ │(XGBoost+  │ │(LLM/Jinja2)│                 │
│     │  │  │     │  SHAP)     │ └─────────────┘                 │
│     │  │  │     └────────────┘                                  │
│  ┌──▼──▼──▼────────────────────────────────────────┐            │
│  │              RECON MODULES                       │            │
│  │ ┌───────┐ ┌───────┐ ┌────────┐ ┌──────┐        │            │
│  │ │CT Logs│ │DNS BF │ │PortScan│ │TechFP│        │            │
│  │ └───────┘ └───────┘ └────────┘ └──────┘        │            │
│  │ ┌───────┐ ┌───────┐ ┌────────┐ ┌──────┐        │            │
│  │ │SSL/TLS│ │Headers│ │DNS Rec │ │Takevr│        │            │
│  │ └───────┘ └───────┘ └────────┘ └──────┘        │            │
│  └─────────────────────────────────────────────────┘            │
│                          │                                      │
│  ┌───────────────────────▼─────────────────────────┐            │
│  │            THREAT INTEL CLIENTS                  │            │
│  │  NVD/CVE │ EPSS │ CISA KEV │ Shodan │ VT │ Abuse│           │
│  └─────────────────────────────────────────────────┘            │
│                          │                                      │
│  ┌───────────────────────▼─────────────────────────┐            │
│  │              SQLite DATABASE                     │            │
│  │  scans │ assets │ ports │ techs │ vulns │ ssl   │            │
│  │  headers │ dns_records │ threat_intel │ reports  │            │
│  └─────────────────────────────────────────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Tech Stack (Final)

| Layer | Technology | Version | Purpose |
|---|---|---|---|
| **Frontend Framework** | React | 18+ | Component-based UI |
| **Frontend Build** | Vite | 5+ | Fast dev server & bundling |
| **Frontend Routing** | React Router DOM | 6+ | Client-side routing |
| **Frontend Charts** | Recharts | 2+ | Risk charts, distributions |
| **Frontend Styling** | Vanilla CSS | — | Dark theme, glassmorphism, animations |
| **Frontend Icons** | Lucide React | latest | Icon set |
| **Backend Framework** | FastAPI | 0.115+ | Async REST API |
| **Python Version** | Python | 3.10+ | Runtime |
| **ORM** | SQLAlchemy | 2.0+ | Database ORM |
| **Database** | SQLite | 3 | Data storage (file-based, zero config) |
| **Validation** | Pydantic | 2.9+ | Request/response schemas |
| **DNS** | dnspython | 2.7+ | DNS queries |
| **HTTP Client** | httpx | 0.27+ | Async HTTP requests |
| **Crypto** | cryptography | 43+ | SSL certificate analysis |
| **ML Model** | XGBoost | 2.1+ | Risk scoring classifier |
| **Explainability** | SHAP | 0.46+ | Feature importance explanations |
| **Data** | pandas, numpy | latest | Data manipulation |
| **HTML Parsing** | BeautifulSoup4 | 4.12+ | HTML body analysis |
| **Favicon Hash** | mmh3 | 5+ | MurmurHash3 for favicon fingerprinting |
| **Templates** | Jinja2 | 3.1+ | Report template rendering |

---

## 3. Directory Structure

```
PROJ1/
│
├── docs/                              # Documentation (this folder)
│   ├── 01_PRD.md                      # Product Requirements Document
│   ├── 02_TECHNICAL_SPEC.md           # This file
│   └── 03_API_SPEC.md                 # API endpoint specification
│
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                    # FastAPI application entry point
│   │   ├── config.py                  # Settings via pydantic-settings + .env
│   │   ├── database.py                # SQLAlchemy engine, session, Base
│   │   ├── models.py                  # All ORM models (9 tables)
│   │   ├── schemas.py                 # All Pydantic request/response schemas
│   │   │
│   │   ├── api/                       # API route handlers
│   │   │   ├── __init__.py
│   │   │   ├── scans.py               # POST /scans, GET /scans, GET /scans/{id}
│   │   │   ├── assets.py              # GET /assets, GET /assets/{id}
│   │   │   ├── reports.py             # POST /reports/generate, GET /reports/{id}
│   │   │   └── dashboard.py           # GET /dashboard/stats, GET /dashboard/distribution
│   │   │
│   │   ├── recon/                     # Reconnaissance modules
│   │   │   ├── __init__.py
│   │   │   ├── orchestrator.py        # Coordinates all recon modules in sequence
│   │   │   ├── subdomain_enum.py      # CT logs + DNS brute-force + permutations
│   │   │   ├── port_scanner.py        # Async TCP port scanning
│   │   │   ├── tech_detector.py       # Multi-layer technology fingerprinting
│   │   │   ├── ssl_analyzer.py        # SSL/TLS certificate and cipher analysis
│   │   │   ├── header_auditor.py      # Security header checks
│   │   │   ├── dns_analyzer.py        # DNS records + SPF/DKIM/DMARC + takeover
│   │   │   └── wordlists.py           # Embedded subdomain wordlist (top 500)
│   │   │
│   │   ├── intel/                     # Threat intelligence clients
│   │   │   ├── __init__.py
│   │   │   ├── cve_lookup.py          # NVD API + EPSS API + CISA KEV
│   │   │   ├── shodan_client.py       # Shodan API wrapper
│   │   │   ├── virustotal_client.py   # VirusTotal API wrapper
│   │   │   └── abuseipdb_client.py    # AbuseIPDB API wrapper
│   │   │
│   │   └── ai/                        # AI/ML components
│   │       ├── __init__.py
│   │       ├── risk_scorer.py         # XGBoost model loading + prediction + SHAP
│   │       ├── feature_engineer.py    # Extract feature vector from asset data
│   │       ├── report_generator.py    # LLM + Jinja2 report generation
│   │       └── risk_model.pkl         # Pre-trained model (generated by train_model.py)
│   │
│   ├── train_model.py                 # Script to generate synthetic data + train XGBoost
│   ├── requirements.txt               # Python dependencies
│   └── run.py                         # Quick start: uvicorn app.main:app
│
├── frontend/
│   ├── index.html                     # HTML entry point
│   ├── package.json                   # npm dependencies
│   ├── vite.config.js                 # Vite configuration with API proxy
│   │
│   └── src/
│       ├── main.jsx                   # React entry point
│       ├── App.jsx                    # Root component with routing
│       ├── index.css                  # Global styles + design system + animations
│       │
│       ├── pages/
│       │   ├── Dashboard.jsx          # Overview with stats, charts, recent scans
│       │   ├── Assets.jsx             # Asset inventory table with filters
│       │   ├── AssetDetail.jsx        # Single asset deep dive with tabs
│       │   ├── ScanManager.jsx        # New scan form + scan history + progress
│       │   └── Reports.jsx            # Report generation + viewing
│       │
│       ├── components/
│       │   ├── Sidebar.jsx            # Navigation sidebar
│       │   ├── RiskGauge.jsx          # Circular risk score gauge (0-100)
│       │   ├── RiskBadge.jsx          # Colored severity badge
│       │   ├── StatsCard.jsx          # Dashboard stat card
│       │   ├── AssetTable.jsx         # Sortable, filterable asset table
│       │   ├── ScanProgress.jsx       # Real-time scan progress indicator
│       │   ├── ShapChart.jsx          # Horizontal bar chart for SHAP values
│       │   ├── RiskDistribution.jsx   # Donut chart for risk distribution
│       │   └── EmptyState.jsx         # Empty state placeholder
│       │
│       └── utils/
│           └── api.js                 # Fetch wrapper for backend API calls
│
├── .env.example                       # Environment variable template
├── .gitignore
└── README.md                          # Project overview, setup, screenshots
```

---

## 4. Database Schema (SQLite)

### Table: `scans`
| Column | Type | Constraints | Description |
|---|---|---|---|
| id | INTEGER | PRIMARY KEY, AUTOINCREMENT | Scan ID |
| target_domain | VARCHAR(255) | NOT NULL, INDEX | Domain being scanned |
| status | VARCHAR(50) | DEFAULT 'pending' | pending/running/completed/failed |
| scan_type | VARCHAR(50) | DEFAULT 'full' | quick/standard/full |
| started_at | DATETIME | DEFAULT CURRENT_TIMESTAMP | Scan start time |
| completed_at | DATETIME | NULLABLE | Scan completion time |
| total_assets | INTEGER | DEFAULT 0 | Count of discovered assets |
| critical_findings | INTEGER | DEFAULT 0 | Critical severity count |
| high_findings | INTEGER | DEFAULT 0 | High severity count |
| medium_findings | INTEGER | DEFAULT 0 | Medium severity count |
| low_findings | INTEGER | DEFAULT 0 | Low severity count |
| overall_risk_score | FLOAT | DEFAULT 0.0 | Average risk score (0-100) |
| scan_log | TEXT | DEFAULT '' | Timestamped log of scan progress |

### Table: `assets`
| Column | Type | Constraints | Description |
|---|---|---|---|
| id | INTEGER | PRIMARY KEY | Asset ID |
| scan_id | INTEGER | FOREIGN KEY → scans.id | Parent scan |
| hostname | VARCHAR(255) | NOT NULL, INDEX | FQDN |
| ip_address | VARCHAR(45) | NULLABLE | Resolved IPv4/IPv6 |
| asset_type | VARCHAR(50) | DEFAULT 'subdomain' | subdomain/ip/service |
| discovery_method | VARCHAR(100) | NULLABLE | ct_logs/dns_bruteforce/permutation |
| risk_score | FLOAT | DEFAULT 0.0 | AI-assigned score (0-100) |
| risk_level | VARCHAR(20) | DEFAULT 'info' | critical/high/medium/low/info |
| risk_factors | JSON | DEFAULT '[]' | SHAP explanation list |
| is_alive | BOOLEAN | DEFAULT TRUE | HTTP probe result |
| http_status | INTEGER | NULLABLE | HTTP response code |
| http_title | VARCHAR(500) | NULLABLE | Page `<title>` text |
| discovered_at | DATETIME | DEFAULT CURRENT_TIMESTAMP | Discovery timestamp |

### Table: `ports`
| Column | Type | Constraints | Description |
|---|---|---|---|
| id | INTEGER | PRIMARY KEY | Port record ID |
| asset_id | INTEGER | FOREIGN KEY → assets.id | Parent asset |
| port_number | INTEGER | NOT NULL | TCP/UDP port number |
| protocol | VARCHAR(10) | DEFAULT 'tcp' | tcp/udp |
| state | VARCHAR(20) | DEFAULT 'open' | open/closed/filtered |
| service_name | VARCHAR(100) | NULLABLE | Service (ssh, http, mysql, etc.) |
| service_version | VARCHAR(200) | NULLABLE | Version string |
| banner | TEXT | NULLABLE | Raw banner text |
| is_critical | BOOLEAN | DEFAULT FALSE | Is this a high-risk port? |

### Table: `technologies`
| Column | Type | Constraints | Description |
|---|---|---|---|
| id | INTEGER | PRIMARY KEY | Tech record ID |
| asset_id | INTEGER | FOREIGN KEY → assets.id | Parent asset |
| name | VARCHAR(200) | NOT NULL | Technology name |
| version | VARCHAR(100) | NULLABLE | Detected version |
| category | VARCHAR(100) | NULLABLE | web-server/framework/cms/language/os |
| confidence | INTEGER | DEFAULT 100 | Detection confidence 0-100 |
| detection_method | VARCHAR(100) | NULLABLE | header/cookie/html/favicon/error |

### Table: `vulnerabilities`
| Column | Type | Constraints | Description |
|---|---|---|---|
| id | INTEGER | PRIMARY KEY | Vuln record ID |
| asset_id | INTEGER | FOREIGN KEY → assets.id | Parent asset |
| cve_id | VARCHAR(20) | NULLABLE | CVE-YYYY-NNNNN |
| title | VARCHAR(500) | NOT NULL | Vulnerability title |
| description | TEXT | NULLABLE | Full description |
| severity | VARCHAR(20) | DEFAULT 'medium' | critical/high/medium/low/info |
| cvss_score | FLOAT | NULLABLE | CVSS v3.1 base score |
| epss_score | FLOAT | NULLABLE | EPSS probability (0-1) |
| is_on_cisa_kev | BOOLEAN | DEFAULT FALSE | On CISA Known Exploited list? |
| affected_component | VARCHAR(200) | NULLABLE | What tech is affected |
| remediation | TEXT | NULLABLE | Fix instructions |
| references | JSON | DEFAULT '[]' | URL references |

### Table: `ssl_certificates`
| Column | Type | Constraints | Description |
|---|---|---|---|
| id | INTEGER | PRIMARY KEY | Cert record ID |
| asset_id | INTEGER | FOREIGN KEY → assets.id, UNIQUE | Parent asset (one-to-one) |
| issuer | VARCHAR(500) | NULLABLE | CA issuer name |
| subject | VARCHAR(500) | NULLABLE | Certificate subject |
| valid_from | DATETIME | NULLABLE | Not Before date |
| valid_to | DATETIME | NULLABLE | Not After date |
| serial_number | VARCHAR(100) | NULLABLE | Cert serial |
| signature_algorithm | VARCHAR(100) | NULLABLE | sha256WithRSAEncryption, etc. |
| key_size | INTEGER | NULLABLE | RSA key bits |
| key_type | VARCHAR(50) | NULLABLE | RSA/EC/DSA |
| protocol_versions | JSON | DEFAULT '[]' | Supported TLS versions |
| cipher_suites | JSON | DEFAULT '[]' | Supported cipher suites |
| is_expired | BOOLEAN | DEFAULT FALSE | |
| is_self_signed | BOOLEAN | DEFAULT FALSE | |
| has_weak_cipher | BOOLEAN | DEFAULT FALSE | RC4/DES/NULL/EXPORT |
| has_weak_protocol | BOOLEAN | DEFAULT FALSE | TLS 1.0/1.1/SSLv3 |
| days_until_expiry | INTEGER | NULLABLE | Negative = expired |
| grade | VARCHAR(5) | NULLABLE | A+/A/B/C/D/F |

### Table: `security_headers`
| Column | Type | Constraints | Description |
|---|---|---|---|
| id | INTEGER | PRIMARY KEY | Header record ID |
| asset_id | INTEGER | FOREIGN KEY → assets.id | Parent asset |
| header_name | VARCHAR(100) | NOT NULL | Header name |
| header_value | TEXT | NULLABLE | Actual value if present |
| is_present | BOOLEAN | DEFAULT FALSE | Was it found? |
| severity | VARCHAR(20) | DEFAULT 'medium' | Missing header severity |
| recommendation | TEXT | NULLABLE | What to add |

### Table: `dns_records`
| Column | Type | Constraints | Description |
|---|---|---|---|
| id | INTEGER | PRIMARY KEY | DNS record ID |
| asset_id | INTEGER | FOREIGN KEY → assets.id | Parent asset |
| record_type | VARCHAR(10) | NOT NULL | A/AAAA/CNAME/MX/TXT/NS/SOA/SRV |
| record_value | TEXT | NOT NULL | Record value |
| ttl | INTEGER | NULLABLE | Time to live |
| is_misconfigured | BOOLEAN | DEFAULT FALSE | Is there a problem? |
| finding | TEXT | NULLABLE | Description of misconfiguration |

### Table: `threat_intel`
| Column | Type | Constraints | Description |
|---|---|---|---|
| id | INTEGER | PRIMARY KEY | Intel record ID |
| asset_id | INTEGER | FOREIGN KEY → assets.id | Parent asset |
| source | VARCHAR(100) | NOT NULL | shodan/virustotal/abuseipdb |
| intel_type | VARCHAR(100) | NULLABLE | reputation/ports/vulns |
| data | JSON | DEFAULT '{}' | Raw API response data |
| risk_indicator | VARCHAR(20) | NULLABLE | Risk level from this source |
| retrieved_at | DATETIME | DEFAULT CURRENT_TIMESTAMP | When retrieved |

### Table: `reports`
| Column | Type | Constraints | Description |
|---|---|---|---|
| id | INTEGER | PRIMARY KEY | Report ID |
| scan_id | INTEGER | FOREIGN KEY → scans.id | Parent scan |
| report_type | VARCHAR(50) | DEFAULT 'executive' | executive/technical/remediation |
| title | VARCHAR(500) | NULLABLE | Report title |
| content | TEXT | NULLABLE | Full report content (Markdown) |
| generated_at | DATETIME | DEFAULT CURRENT_TIMESTAMP | Generation time |

### Relationships
```
scans 1──N assets
scans 1──N reports
assets 1──N ports
assets 1──N technologies
assets 1──N vulnerabilities
assets 1──1 ssl_certificates
assets 1──N security_headers
assets 1──N dns_records
assets 1──N threat_intel
```

---

## 5. API Specification

**Base URL**: `http://localhost:8000/api`  
**Content-Type**: `application/json`

### 5.1 Scans

#### `POST /api/scans`
Create and start a new scan.

**Request Body**:
```json
{
  "target_domain": "example.com",
  "scan_type": "full"
}
```

**Response** (201 Created):
```json
{
  "id": 1,
  "target_domain": "example.com",
  "status": "running",
  "scan_type": "full",
  "started_at": "2026-10-17T18:00:00Z",
  "completed_at": null,
  "total_assets": 0,
  "critical_findings": 0,
  "high_findings": 0,
  "medium_findings": 0,
  "low_findings": 0,
  "overall_risk_score": 0.0
}
```

**Behavior**: 
- Validates domain format
- Creates scan record with status="running"
- Launches scan orchestrator in background thread (asyncio.create_task or BackgroundTasks)
- Returns immediately with scan ID

**Errors**:
- 400: Invalid domain format
- 429: Max concurrent scans reached

#### `GET /api/scans`
List all scans.

**Query Parameters**:
- `status` (optional): Filter by status (pending/running/completed/failed)
- `limit` (optional, default=50): Max results
- `offset` (optional, default=0): Pagination offset

**Response** (200 OK):
```json
[
  {
    "id": 1,
    "target_domain": "example.com",
    "status": "completed",
    "scan_type": "full",
    "started_at": "2026-10-17T18:00:00Z",
    "completed_at": "2026-10-17T18:12:00Z",
    "total_assets": 47,
    "critical_findings": 3,
    "high_findings": 8,
    "medium_findings": 15,
    "low_findings": 12,
    "overall_risk_score": 62.4
  }
]
```

#### `GET /api/scans/{scan_id}`
Get scan details with summary.

**Response** (200 OK): Same as ScanResponse schema.

**Errors**: 404: Scan not found

#### `GET /api/scans/{scan_id}/progress`
Get real-time scan progress.

**Response** (200 OK):
```json
{
  "scan_id": 1,
  "status": "running",
  "current_stage": "port_scanning",
  "stages": {
    "subdomain_enum": {"status": "completed", "found": 23},
    "http_probing": {"status": "completed", "alive": 18},
    "port_scanning": {"status": "running", "scanned": 12, "total": 18},
    "tech_detection": {"status": "pending"},
    "ssl_analysis": {"status": "pending"},
    "header_audit": {"status": "pending"},
    "dns_analysis": {"status": "pending"},
    "threat_intel": {"status": "pending"},
    "risk_scoring": {"status": "pending"}
  },
  "log": "[18:00:01] Starting scan for example.com\n[18:00:02] Querying Certificate Transparency logs...\n..."
}
```

#### `DELETE /api/scans/{scan_id}`
Delete scan and all associated data.

**Response** (204 No Content)

**Errors**: 404: Scan not found, 409: Cannot delete running scan

### 5.2 Assets

#### `GET /api/scans/{scan_id}/assets`
List all assets for a scan.

**Query Parameters**:
- `risk_level` (optional): Filter by critical/high/medium/low/info
- `search` (optional): Search hostname
- `sort_by` (optional, default="risk_score"): Sort field
- `sort_order` (optional, default="desc"): asc/desc
- `limit` (optional, default=100)
- `offset` (optional, default=0)

**Response** (200 OK):
```json
{
  "total": 47,
  "assets": [
    {
      "id": 1,
      "hostname": "admin.example.com",
      "ip_address": "93.184.216.34",
      "asset_type": "subdomain",
      "risk_score": 87.3,
      "risk_level": "critical",
      "is_alive": true,
      "http_status": 200,
      "http_title": "Admin Panel",
      "discovered_at": "2026-10-17T18:01:00Z",
      "port_count": 5,
      "vuln_count": 3,
      "tech_count": 4
    }
  ]
}
```

#### `GET /api/assets/{asset_id}`
Get full asset detail with all related data.

**Response** (200 OK): Full AssetDetail schema including ports, technologies, vulnerabilities, ssl_cert, security_headers, dns_records, threat_intel, risk_factors.

**Errors**: 404: Asset not found

### 5.3 Dashboard

#### `GET /api/dashboard/stats?scan_id={id}`
Get dashboard statistics for a specific scan (or latest scan if no scan_id).

**Response** (200 OK):
```json
{
  "total_scans": 5,
  "total_assets": 47,
  "critical_count": 3,
  "high_count": 8,
  "medium_count": 15,
  "low_count": 12,
  "info_count": 9,
  "avg_risk_score": 62.4,
  "total_vulnerabilities": 28,
  "total_open_ports": 156,
  "assets_with_expired_ssl": 2,
  "assets_missing_headers": 31
}
```

#### `GET /api/dashboard/distribution?scan_id={id}`
Risk level distribution for charts.

**Response** (200 OK):
```json
[
  {"level": "critical", "count": 3, "percentage": 6.4},
  {"level": "high", "count": 8, "percentage": 17.0},
  {"level": "medium", "count": 15, "percentage": 31.9},
  {"level": "low", "count": 12, "percentage": 25.5},
  {"level": "info", "count": 9, "percentage": 19.1}
]
```

#### `GET /api/dashboard/trends`
Risk score trends across scans for the same domain.

**Response** (200 OK):
```json
[
  {"scan_id": 1, "date": "2026-10-10", "risk_score": 72.1, "asset_count": 42},
  {"scan_id": 3, "date": "2026-10-17", "risk_score": 62.4, "asset_count": 47}
]
```

### 5.4 Reports

#### `POST /api/reports/generate`
Generate a report for a scan.

**Request Body**:
```json
{
  "scan_id": 1,
  "report_type": "executive"
}
```

**Response** (201 Created):
```json
{
  "id": 1,
  "scan_id": 1,
  "report_type": "executive",
  "title": "AEGIS Security Report - example.com",
  "content": "# Executive Summary\n\n...",
  "generated_at": "2026-10-17T18:15:00Z"
}
```

**Errors**: 404: Scan not found, 400: Scan not completed yet

#### `GET /api/reports/{report_id}`
Get a generated report.

**Response** (200 OK): ReportResponse schema.

#### `GET /api/scans/{scan_id}/reports`
List all reports for a scan.

**Response** (200 OK): List of ReportResponse.

### 5.5 Error Responses

All errors follow this format:
```json
{
  "detail": "Human-readable error message"
}
```

| Status Code | Meaning |
|---|---|
| 400 | Bad request (invalid input) |
| 404 | Resource not found |
| 409 | Conflict (e.g., deleting running scan) |
| 429 | Too many requests (max concurrent scans) |
| 500 | Internal server error |

---

## 6. Scan Orchestrator Flow

The orchestrator runs all recon modules in a defined sequence. Each stage updates the scan progress and log.

```python
async def run_scan(scan_id: int, domain: str, scan_type: str):
    """
    Orchestration sequence:
    
    1. SUBDOMAIN ENUMERATION
       a. Query CT logs (crt.sh)
       b. DNS brute-force (if standard/full)
       c. Permutation scanning (if full)
       d. Deduplicate all results
       → Creates Asset records for each subdomain
    
    2. HTTP PROBING
       a. For each subdomain, probe HTTPS then HTTP
       b. Record: is_alive, http_status, http_title, response_headers
       → Updates Asset records
    
    3. DNS RESOLUTION
       a. Resolve A/AAAA records for each hostname
       b. Store IP addresses
       → Updates Asset.ip_address
    
    4. PORT SCANNING (if standard/full)
       a. For each unique IP, scan ports
       b. Banner grab on open ports
       c. Service identification
       → Creates Port records
    
    5. TECHNOLOGY FINGERPRINTING (if standard/full)
       a. For each alive asset, analyze response
       b. Multi-layer detection (headers → cookies → HTML → favicon → errors)
       → Creates Technology records
    
    6. SSL/TLS ANALYSIS
       a. For each HTTPS asset, analyze certificate and ciphers
       b. Grade assignment
       → Creates SSLCertificate records
    
    7. SECURITY HEADER AUDIT
       a. For each alive asset, check all security headers
       b. Check CORS, cookie flags
       → Creates SecurityHeader records
    
    8. DNS RECORD ANALYSIS
       a. For root domain + each subdomain, query DNS records
       b. SPF/DKIM/DMARC checks on root domain
       c. Subdomain takeover detection (CNAME analysis)
       → Creates DNSRecord records
    
    9. THREAT INTELLIGENCE (if full)
       a. CVE/NVD lookup for detected technologies
       b. EPSS scoring for found CVEs
       c. CISA KEV cross-reference
       d. Shodan enrichment (if API key)
       e. VirusTotal enrichment (if API key)
       f. AbuseIPDB check (if API key)
       → Creates Vulnerability and ThreatIntel records
    
    10. AI RISK SCORING
        a. For each asset, extract feature vector
        b. Run XGBoost prediction → risk score (0-100)
        c. Compute SHAP values → risk factors
        d. Apply vulnerability prioritization (CVSS+EPSS+KEV)
        → Updates Asset.risk_score, risk_level, risk_factors
    
    11. SCAN FINALIZATION
        a. Count findings by severity
        b. Calculate overall risk score (weighted average)
        c. Update scan status to "completed"
        d. Record completion time
    """
```

### Error Handling Per Stage
- Each stage is wrapped in try/except
- On failure: log error to scan_log, skip stage, continue to next
- Scan only fails entirely if stage 1 (subdomain enumeration) finds zero results
- Individual asset errors don't fail the scan

---

## 7. Frontend Design System

### Color Palette
```css
/* Background */
--bg-primary: #0a0a1a;        /* Deep navy black */
--bg-secondary: #111128;      /* Slightly lighter */
--bg-card: #1a1a3e;           /* Card background */
--bg-card-hover: #222255;     /* Card hover */

/* Glass effect */
--glass-bg: rgba(255, 255, 255, 0.05);
--glass-border: rgba(255, 255, 255, 0.1);

/* Text */
--text-primary: #e8e8ff;      /* Near white with blue tint */
--text-secondary: #8888aa;    /* Muted */
--text-muted: #555577;        /* Very muted */

/* Risk Colors */
--risk-critical: #ff4757;     /* Red */
--risk-high: #ff6b35;         /* Orange */
--risk-medium: #ffa726;       /* Amber */
--risk-low: #42a5f5;          /* Blue */
--risk-info: #66bb6a;         /* Green */

/* Accent */
--accent-primary: #7c4dff;    /* Purple */
--accent-secondary: #00e5ff;  /* Cyan */
--accent-gradient: linear-gradient(135deg, #7c4dff, #00e5ff);
```

### Typography
- **Font**: 'Inter' from Google Fonts (fallback: system-ui, sans-serif)
- **Headings**: 600/700 weight
- **Body**: 400 weight
- **Monospace**: 'JetBrains Mono' or 'Fira Code' for technical data

### Component Styling
- **Cards**: Glassmorphism with backdrop-filter blur, subtle border
- **Tables**: Alternating row backgrounds, hover highlight
- **Buttons**: Gradient backgrounds, subtle glow on hover
- **Inputs**: Dark backgrounds, glowing border on focus
- **Badges**: Colored pills for risk levels
- **Animations**: Smooth transitions (300ms), fade-in on load, pulse on critical items

### Layout
- **Sidebar**: Fixed left, 260px wide, collapsible
- **Main content**: Flexible, max-width 1400px, centered
- **Responsive breakpoints**: 768px (tablet), 1024px (desktop)

---

## 8. Deployment & Setup Instructions

### Prerequisites
- Python 3.10+
- Node.js 18+
- npm 9+

### Backend Setup
```bash
cd backend
python -m venv venv
source venv/bin/activate    # Linux/Mac
# or: venv\Scripts\activate  # Windows
pip install -r requirements.txt
cp ../.env.example .env     # Edit with your API keys
python train_model.py       # Generate the ML model
python run.py               # Start backend at http://localhost:8000
```

### Frontend Setup
```bash
cd frontend
npm install
npm run dev                 # Start frontend at http://localhost:5173
```

### Vite Proxy Configuration
The frontend must proxy API requests to the backend. In `vite.config.js`:
```javascript
export default defineConfig({
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true
      }
    }
  }
})
```

---

## 9. Testing Strategy

### Backend Tests
- **Unit tests**: Each recon module independently testable with mocked responses
- **Integration tests**: Full scan orchestration on a known test domain
- **API tests**: Every endpoint with valid and invalid inputs

### Test Domain
- Use `scanme.nmap.org` (explicitly allows scanning) for integration testing
- Use `example.com` for DNS-only tests (no active scanning)
- Include a "demo mode" with pre-loaded synthetic results for safe demonstrations

### Demo Mode
When `DEMO_MODE=true` in .env:
- Skip all real network calls
- Load pre-built synthetic scan results from a JSON fixture file
- Allows safe demos without scanning real infrastructure
