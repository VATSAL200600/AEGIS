# AEGIS — API and Database Specification

**Document**: 05_API_AND_DATABASE_SPEC.md  
**Version**: 1.0  
**Target Audience**: Backend Developers, Frontend Engineers, and AI Coding Agents  

---

## 1. Database Schema Specification (SQLAlchemy 2.0)

AEGIS utilizes SQLite (`aegis.db`) with Foreign Key support enabled (`PRAGMA foreign_keys=ON`), structured to seamlessly migrate to PostgreSQL for enterprise deployments.

### 1.1 Entity Relationship Diagram

```
┌──────────────────┐
│      scans       │
│  id (PK)         │◄──────────────┐
│  target_domain   │               │
│  status          │               │
│  risk_score      │               │
└────────┬─────────┘               │
         │ 1:N                     │
         ▼                         │
┌──────────────────┐               │
│      assets      │               │
│  id (PK)         │               │
│  scan_id (FK)    │               │
│  hostname        │               │
│  ip_address      │               │
│  risk_score      │               │
└────────┬─────────┘               │
         │ 1:N                     │
         ├──────────────────┬──────┴───────────┬──────────────────┐
         ▼                  ▼                  ▼                  ▼
┌──────────────────┐┌──────────────────┐┌──────────────────┐┌──────────────────┐
│      ports       ││   technologies   ││   ssl_certs      ││ security_headers │
│  id (PK)         ││  id (PK)         ││  id (PK)         ││  id (PK)         │
│  asset_id (FK)   ││  asset_id (FK)   ││  asset_id (FK)   ││  asset_id (FK)   │
│  port_number     ││  name            ││  issuer          ││  grade (A-F)     │
│  service         ││  version         ││  expires_in_days ││  missing_headers │
└──────────────────┘└──────────────────┘└──────────────────┘└──────────────────┘
         │                  │
         ├──────────────────┴──────────┐
         ▼                             ▼
┌──────────────────┐          ┌──────────────────┐
│  vulnerabilities │          │   dns_records    │
│  id (PK)         │          │  id (PK)         │
│  asset_id (FK)   │          │  asset_id (FK)   │
│  cve_id          │          │  record_type     │
│  cvss_score      │          │  value           │
│  epss_score      │          │  is_dangling     │
└──────────────────┘          └──────────────────┘
```

### 1.2 Table Definitions & Field Types

#### Table: `scans`
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `VARCHAR(36)` | PRIMARY KEY | UUID string identifier |
| `target_domain` | `VARCHAR(255)` | NOT NULL, INDEX | Root domain scanned (e.g. `example.com`) |
| `scan_profile` | `VARCHAR(32)` | NOT NULL, DEFAULT 'standard' | `quick`, `standard`, `deep` |
| `status` | `VARCHAR(32)` | NOT NULL, DEFAULT 'pending' | `pending`, `running`, `completed`, `failed` |
| `progress_percent` | `INTEGER` | NOT NULL, DEFAULT 0 | 0 to 100 progress indicator |
| `current_phase` | `VARCHAR(64)` | NULL | Current scan sub-step |
| `total_assets` | `INTEGER` | NOT NULL, DEFAULT 0 | Count of discovered assets |
| `avg_risk_score` | `FLOAT` | NULL | Average risk score across assets (0-100) |
| `max_risk_score` | `FLOAT` | NULL | Highest asset risk score (0-100) |
| `critical_count` | `INTEGER` | NOT NULL, DEFAULT 0 | Assets with risk >= 80 |
| `high_count` | `INTEGER` | NOT NULL, DEFAULT 0 | Assets with risk 60-79.9 |
| `medium_count` | `INTEGER` | NOT NULL, DEFAULT 0 | Assets with risk 40-59.9 |
| `low_count` | `INTEGER` | NOT NULL, DEFAULT 0 | Assets with risk 20-39.9 |
| `info_count` | `INTEGER` | NOT NULL, DEFAULT 0 | Assets with risk < 20 |
| `error_message` | `TEXT` | NULL | Failure reason if status == 'failed' |
| `started_at` | `DATETIME` | NULL | Timestamp scan was initiated |
| `completed_at` | `DATETIME` | NULL | Timestamp scan completed |
| `created_at` | `DATETIME` | NOT NULL, DEFAULT UTC_NOW | Record creation timestamp |

#### Table: `assets`
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `VARCHAR(36)` | PRIMARY KEY | UUID string identifier |
| `scan_id` | `VARCHAR(36)` | NOT NULL, FK(`scans.id`, ON DELETE CASCADE) | Associated scan session |
| `hostname` | `VARCHAR(255)` | NOT NULL, INDEX | FQDN (e.g. `api.example.com`) |
| `ip_address` | `VARCHAR(45)` | NULL, INDEX | IPv4 or IPv6 address |
| `is_apex` | `BOOLEAN` | NOT NULL, DEFAULT FALSE | True if apex domain |
| `is_live` | `BOOLEAN` | NOT NULL, DEFAULT TRUE | Responded to ping/TCP/DNS |
| `risk_score` | `FLOAT` | NOT NULL, DEFAULT 0.0 | ML-predicted risk (0-100) |
| `risk_level` | `VARCHAR(16)` | NOT NULL, DEFAULT 'info' | `critical`, `high`, `medium`, `low`, `info` |
| `shap_explanation` | `JSON` | NULL | Top SHAP feature contributions |
| `country` | `VARCHAR(64)` | NULL | Geolocation country name |
| `asn` | `VARCHAR(64)` | NULL | Autonomous System Number & Org |
| `screenshot_path` | `VARCHAR(512)` | NULL | Relative path to web screenshot |
| `created_at` | `DATETIME` | NOT NULL, DEFAULT UTC_NOW | Record creation timestamp |

#### Table: `ports`
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `VARCHAR(36)` | PRIMARY KEY | UUID identifier |
| `asset_id` | `VARCHAR(36)` | NOT NULL, FK(`assets.id`, ON DELETE CASCADE) | Owning asset |
| `port_number` | `INTEGER` | NOT NULL | Port (e.g. `443`, `22`, `3389`) |
| `protocol` | `VARCHAR(8)` | NOT NULL, DEFAULT 'tcp' | `tcp`, `udp` |
| `state` | `VARCHAR(16)` | NOT NULL, DEFAULT 'open' | `open`, `filtered`, `closed` |
| `service_name` | `VARCHAR(64)` | NULL | Identified service (`ssh`, `http`, etc.) |
| `banner` | `TEXT` | NULL | Raw service banner grabbed |
| `is_critical` | `BOOLEAN` | NOT NULL, DEFAULT FALSE | True if high-risk port (22, 3389, 445, etc.) |

#### Table: `technologies`
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `VARCHAR(36)` | PRIMARY KEY | UUID identifier |
| `asset_id` | `VARCHAR(36)` | NOT NULL, FK(`assets.id`, ON DELETE CASCADE) | Owning asset |
| `name` | `VARCHAR(128)` | NOT NULL | Tech name (e.g. `WordPress`, `React`, `Nginx`) |
| `category` | `VARCHAR(64)` | NULL | `CMS`, `Web Server`, `Framework`, `CDN` |
| `version` | `VARCHAR(64)` | NULL | Detected version string (e.g. `1.18.0`) |
| `is_outdated` | `BOOLEAN` | NOT NULL, DEFAULT FALSE | Known EOL or superseded version |
| `confidence` | `INTEGER` | NOT NULL, DEFAULT 100 | Percentage confidence (0-100) |

#### Table: `vulnerabilities`
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `VARCHAR(36)` | PRIMARY KEY | UUID identifier |
| `asset_id` | `VARCHAR(36)` | NOT NULL, FK(`assets.id`, ON DELETE CASCADE) | Affected asset |
| `cve_id` | `VARCHAR(32)` | NOT NULL, INDEX | e.g. `CVE-2021-44228` |
| `title` | `VARCHAR(255)` | NOT NULL | Vulnerability summary |
| `description` | `TEXT` | NULL | Detailed CVE description |
| `cvss_score` | `FLOAT` | NULL | Base CVSS v3 score (0.0 - 10.0) |
| `severity` | `VARCHAR(16)` | NOT NULL | `critical`, `high`, `medium`, `low` |
| `epss_score` | `FLOAT` | NULL | EPSS probability (0.0 - 1.0) |
| `epss_percentile` | `FLOAT` | NULL | EPSS percentile ranking |
| `is_cisa_kev` | `BOOLEAN` | NOT NULL, DEFAULT FALSE | Present in CISA KEV catalog |
| `remediation` | `TEXT` | NULL | Remediation recommendation |

#### Table: `ssl_certs`
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `VARCHAR(36)` | PRIMARY KEY | UUID identifier |
| `asset_id` | `VARCHAR(36)` | NOT NULL, UNIQUE, FK(`assets.id`, ON DELETE CASCADE) | 1:1 relationship |
| `issuer` | `VARCHAR(255)` | NULL | CA issuer string |
| `subject` | `VARCHAR(255)` | NULL | Cert subject common name |
| `valid_from` | `DATETIME` | NULL | Issue timestamp |
| `valid_to` | `DATETIME` | NULL | Expiration timestamp |
| `expires_in_days` | `INTEGER` | NOT NULL, DEFAULT 0 | Days remaining before expiry |
| `is_expired` | `BOOLEAN` | NOT NULL, DEFAULT FALSE | Expiry boolean flag |
| `is_self_signed` | `BOOLEAN` | NOT NULL, DEFAULT FALSE | True if issuer == subject |
| `tls_version` | `VARCHAR(16)` | NULL | e.g. `TLSv1.3`, `TLSv1.0` |
| `cipher_suite` | `VARCHAR(128)` | NULL | Negotiated cipher suite |
| `san_entries` | `JSON` | NULL | Array of SAN DNS names |

#### Table: `security_headers`
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `VARCHAR(36)` | PRIMARY KEY | UUID identifier |
| `asset_id` | `VARCHAR(36)` | NOT NULL, UNIQUE, FK(`assets.id`, ON DELETE CASCADE) | 1:1 relationship |
| `grade` | `VARCHAR(4)` | NOT NULL, DEFAULT 'F' | `A+`, `A`, `B`, `C`, `D`, `F` |
| `score` | `INTEGER` | NOT NULL, DEFAULT 0 | 0 to 100 calculated score |
| `hsts` | `BOOLEAN` | NOT NULL, DEFAULT FALSE | HSTS present |
| `csp` | `BOOLEAN` | NOT NULL, DEFAULT FALSE | CSP present |
| `x_frame_options` | `VARCHAR(32)` | NULL | `DENY`, `SAMEORIGIN`, or NULL |
| `x_content_type` | `BOOLEAN` | NOT NULL, DEFAULT FALSE | `nosniff` present |
| `referrer_policy` | `VARCHAR(64)` | NULL | Referrer policy value |
| `permissions_policy` | `BOOLEAN` | NOT NULL, DEFAULT FALSE | Feature/Permissions policy present |
| `cors_misconfigured`| `BOOLEAN` | NOT NULL, DEFAULT FALSE | Reflects arbitrary origin with creds |
| `raw_headers` | `JSON` | NULL | Serialized HTTP response headers |

#### Table: `reports`
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `VARCHAR(36)` | PRIMARY KEY | UUID identifier |
| `scan_id` | `VARCHAR(36)` | NOT NULL, FK(`scans.id`, ON DELETE CASCADE) | Target scan |
| `report_type` | `VARCHAR(32)` | NOT NULL, DEFAULT 'executive' | `executive`, `technical`, `compliance` |
| `title` | `VARCHAR(255)` | NOT NULL | Report title |
| `executive_summary` | `TEXT` | NOT NULL | LLM or template generated executive briefing |
| `attack_surface_analysis` | `TEXT` | NOT NULL | Deep technical breakdown |
| `remediation_plan` | `JSON` | NOT NULL | Prioritized action items array |
| `html_content` | `TEXT` | NULL | Pre-rendered HTML report |
| `created_at` | `DATETIME` | NOT NULL, DEFAULT UTC_NOW | Generation timestamp |

---

## 2. REST API Specification

### 2.1 Standard API Response Formats

#### Success Envelope
```json
{
  "success": true,
  "data": { ... },
  "message": "Operation completed successfully"
}
```

#### Error Envelope (RFC 7807 Compliant)
```json
{
  "success": false,
  "error": {
    "code": "SCAN_NOT_FOUND",
    "message": "The scan with ID '550e8400-e29b-41d4-a716-446655440000' was not found",
    "details": null
  }
}
```

---

### 2.2 Scan Management Endpoints

#### `POST /api/scans`
Initiates a new external attack surface scan against a target domain.

- **Request Body**:
  ```json
  {
    "target_domain": "example.com",
    "scan_profile": "standard",
    "enable_threat_intel": true,
    "enable_port_scan": true
  }
  ```
  - `scan_profile`: Enum (`quick`: CT logs + top 20 ports; `standard`: full subdomains + top 100 ports + headers + SSL + CVEs; `deep`: brute force + banner grabs + takeovers + full enrichment).
- **Response (201 Created)**:
  ```json
  {
    "success": true,
    "data": {
      "scan_id": "8f12a3c4-7b98-4e56-9a01-2c3d4e5f6a7b",
      "target_domain": "example.com",
      "status": "pending",
      "created_at": "2026-10-18T00:50:00Z"
    },
    "message": "Scan scheduled and queued"
  }
  ```

#### `GET /api/scans`
Lists previous scan operations with pagination and status filtering.

- **Query Parameters**:
  - `page`: int (default: 1)
  - `limit`: int (default: 10, max: 100)
  - `status`: string (optional: `pending`, `running`, `completed`, `failed`)
  - `domain`: string (optional search term)
- **Response (200 OK)**:
  ```json
  {
    "success": true,
    "data": {
      "items": [
        {
          "id": "8f12a3c4-7b98-4e56-9a01-2c3d4e5f6a7b",
          "target_domain": "example.com",
          "scan_profile": "standard",
          "status": "completed",
          "progress_percent": 100,
          "total_assets": 28,
          "avg_risk_score": 64.2,
          "critical_count": 3,
          "high_count": 7,
          "started_at": "2026-10-18T00:50:00Z",
          "completed_at": "2026-10-18T00:53:14Z"
        }
      ],
      "total": 45,
      "page": 1,
      "pages": 5
    }
  }
  ```

#### `GET /api/scans/{scan_id}`
Retrieves detailed status, phase breakdown, and aggregate statistics for a scan.

#### `GET /api/scans/{scan_id}/stream`
**Server-Sent Events (SSE)** endpoint providing real-time scanning feedback to the frontend terminal and progress bar.

- **Event Stream Protocol**:
  ```text
  event: scan_progress
  data: {"scan_id": "8f12a...", "phase": "port_scanning", "percent": 45, "message": "Scanned 14/28 assets..."}

  event: asset_discovered
  data: {"hostname": "api.example.com", "ip": "93.184.216.34"}

  event: risk_scored
  data: {"hostname": "dev.example.com", "score": 88.5, "level": "critical", "reason": "Exposed RDP port 3389 and expired SSL"}

  event: scan_completed
  data: {"scan_id": "8f12a...", "total_assets": 28, "avg_risk": 64.2}
  ```

---

### 2.3 Asset Management Endpoints

#### `GET /api/assets`
Filterable, searchable endpoint querying discovered assets.

- **Query Parameters**:
  - `scan_id`: string (optional: filter by scan)
  - `risk_level`: string (`critical`, `high`, `medium`, `low`, `info`)
  - `has_critical_ports`: boolean
  - `has_cves`: boolean
  - `search`: string (matches hostname or IP)
  - `sort_by`: string (`risk_score`, `hostname`, `created_at`; default: `-risk_score`)
- **Response (200 OK)**:
  ```json
  {
    "success": true,
    "data": {
      "items": [
        {
          "id": " asset_981a",
          "scan_id": "8f12a3c4",
          "hostname": "dev.example.com",
          "ip_address": "192.0.2.45",
          "risk_score": 91.4,
          "risk_level": "critical",
          "open_ports": [22, 80, 443, 3389],
          "technologies": ["Nginx", "Django"],
          "vulnerabilities_count": 4,
          "ssl_status": "expired",
          "header_grade": "F"
        }
      ],
      "total": 1
    }
  }
  ```

#### `GET /api/assets/{asset_id}`
Returns complete 360-degree attack surface dossier for an asset.

- **Response (200 OK)** includes:
  - Base asset metadata & Geolocation/ASN
  - Full list of open ports with grabbed service banners
  - Detected technologies with versions
  - Complete SSL certificate evaluation
  - Security header breakdown with grade
  - Vulnerability list with CVSS, EPSS, and CISA KEV tags
  - SHAP Explainability waterfall features (`feature_name`, `impact_points`, `direction`)

---

### 2.4 Dashboard Aggregation Endpoint

#### `GET /api/dashboard/stats`
Returns aggregated high-level business metrics across all scans or for the latest scan.

- **Response (200 OK)**:
  ```json
  {
    "success": true,
    "data": {
      "total_scans": 12,
      "total_assets_monitored": 184,
      "overall_security_posture_score": 72.8,
      "severity_distribution": {
        "critical": 9,
        "high": 27,
        "medium": 64,
        "low": 52,
        "info": 32
      },
      "top_vulnerable_assets": [
        {"hostname": "dev-vpn.example.com", "risk_score": 96.2, "critical_issues": 3},
        {"hostname": "legacy-portal.example.com", "risk_score": 89.4, "critical_issues": 2}
      ],
      "exposed_critical_ports": {
        "3389_RDP": 2,
        "22_SSH": 14,
        "3306_MySQL": 1,
        "445_SMB": 0
      },
      "common_technologies": [
        {"name": "Nginx", "count": 45},
        {"name": "React", "count": 32},
        {"name": "Cloudflare", "count": 28}
      ]
    }
  }
  ```

---

### 2.5 Report Generation Endpoints

#### `POST /api/reports/generate`
- **Request Body**:
  ```json
  {
    "scan_id": "8f12a3c4-7b98-4e56-9a01-2c3d4e5f6a7b",
    "report_type": "executive",
    "provider": "gemini" 
  }
  ```
- **Response (200 OK)**:
  ```json
  {
    "success": true,
    "data": {
      "report_id": "rep_3910c",
      "scan_id": "8f12a3c4",
      "executive_summary": "AEGIS assessed example.com across 28 external assets...",
      "key_findings": [
        "Unauthenticated Remote Desktop (RDP) exposed on dev.example.com",
        "Expired wildcard TLS certificate on *.internal.example.com",
        "Subdomain takeover risk detected on shop.example.com (dangling GitHub Pages CNAME)"
      ],
      "remediation_priorities": [
        {"priority": 1, "title": "Firewall Port 3389", "target": "dev.example.com", "effort": "Immediate (15m)"},
        {"priority": 2, "title": "Claim or Delete Dangling CNAME", "target": "shop.example.com", "effort": "Immediate (10m)"}
      ]
    }
  }
  ```

#### `GET /api/reports/{report_id}/download`
- **Query Parameter**: `format=html` or `format=markdown` or `format=json`. Returns styled file stream for instant download.
