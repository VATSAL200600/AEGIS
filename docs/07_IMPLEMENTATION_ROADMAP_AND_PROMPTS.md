# AEGIS — Implementation Roadmap & AI Agent Prompts

**Document**: 07_IMPLEMENTATION_ROADMAP_AND_PROMPTS.md  
**Version**: 1.0  
**Target Audience**: Developers, Orchestrators, and Autonomous AI Coding Agents  

---

## 1. Roadmap & Implementation Phases

The construction of AEGIS is divided into **10 structured phases**. Each phase is self-contained, verifiable, and builds upon preceding phases.

```
┌──────────────────────────────────────────────────────────┐
│ Phase 1: Foundation (Config, DB Models, Schemas)         │
└────────────────────────────┬─────────────────────────────┘
                             ▼
┌──────────────────────────────────────────────────────────┐
│ Phase 2: Reconnaissance Engine Modules (7 Submodules)    │
└────────────────────────────┬─────────────────────────────┘
                             ▼
┌──────────────────────────────────────────────────────────┐
│ Phase 3: Threat Intelligence Clients (EPSS, KEV, Shodan) │
└────────────────────────────┬─────────────────────────────┘
                             ▼
┌──────────────────────────────────────────────────────────┐
│ Phase 4: AI/ML Engine (Synthetic Data, XGBoost & SHAP)   │
└────────────────────────────┬─────────────────────────────┘
                             ▼
┌──────────────────────────────────────────────────────────┐
│ Phase 5: Scan Orchestrator & Real-Time SSE Pipeline      │
└────────────────────────────┬─────────────────────────────┘
                             ▼
┌──────────────────────────────────────────────────────────┐
│ Phase 6: FastAPI REST API Routers & Endpoints            │
└────────────────────────────┬─────────────────────────────┘
                             ▼
┌──────────────────────────────────────────────────────────┐
│ Phase 7: Report Generation (LLM + Jinja2 Templates)      │
└────────────────────────────┬─────────────────────────────┘
                             ▼
┌──────────────────────────────────────────────────────────┐
│ Phase 8: Frontend UI (React + Vite, Cyber Theme, Charts) │
└────────────────────────────┬─────────────────────────────┘
                             ▼
┌──────────────────────────────────────────────────────────┐
│ Phase 9: Demo Mode & Offline Fixtures                    │
└────────────────────────────┬─────────────────────────────┘
                             ▼
┌──────────────────────────────────────────────────────────┐
│ Phase 10: Integration Testing & Verification             │
└──────────────────────────────────────────────────────────┘
```

---

## 2. Turnkey AI Prompts for Step-by-Step Implementation

When delegating tasks to an AI agent (or executing sequentially), provide these exact prompts. Each prompt includes full context references to the specifications in `docs/`.

---

### Prompt for Phase 1: Database & Foundation
```text
ROLE: Senior Python/FastAPI Backend Engineer.
TASK: Implement the foundational database models, Pydantic schemas, and settings for AEGIS according to docs/05_API_AND_DATABASE_SPEC.md.

FILES TO CREATE/UPDATE:
1. backend/app/config.py:
   - Use Pydantic Settings (pydantic-settings)
   - Configuration values: DATABASE_URL, GEMINI_API_KEY, SHODAN_API_KEY, ABUSEIPDB_API_KEY, DEMO_MODE, CORS_ORIGINS
   - Read from .env file with defaults
2. backend/app/database.py:
   - SQLAlchemy 2.0 engine and sessionmaker
   - Async or scoped sync session support for SQLite (sqlite:///./aegis.db)
   - Enable SQLite foreign key pragma on connect
   - Base declarative model class
3. backend/app/models.py:
   - Implement all tables specified in docs/05_API_AND_DATABASE_SPEC.md:
     - Scan (id, target_domain, scan_profile, status, progress_percent, total_assets, avg_risk_score, etc.)
     - Asset (id, scan_id, hostname, ip_address, is_apex, risk_score, risk_level, shap_explanation, etc.)
     - Port (id, asset_id, port_number, protocol, state, service_name, banner, is_critical)
     - Technology (id, asset_id, name, category, version, is_outdated)
     - Vulnerability (id, asset_id, cve_id, title, description, cvss_score, epss_score, is_cisa_kev)
     - SSLCert (id, asset_id, issuer, subject, valid_to, expires_in_days, is_expired, is_self_signed, tls_version)
     - SecurityHeader (id, asset_id, grade, score, hsts, csp, x_frame_options, cors_misconfigured, raw_headers)
     - DNSRecord (id, asset_id, record_type, value, is_dangling)
     - Report (id, scan_id, report_type, title, executive_summary, remediation_plan)
   - Correct ForeignKeys with CASCADE delete and bidirectional relationship definitions.
4. backend/app/schemas.py:
   - Complete Pydantic v2 schemas for ScanCreate, ScanResponse, AssetDetail, PortSchema, TechSchema, VulnerabilitySchema, ReportResponse.

VERIFICATION: Run a quick script to create all tables in SQLite and assert foreign keys are active.
```

---

### Prompt for Phase 2: Reconnaissance Engine Modules
```text
ROLE: Senior Cybersecurity & Network Protocol Python Engineer.
TASK: Implement the 7 reconnaissance submodules in backend/app/recon/ as detailed in docs/04_RECON_ENGINE_SPEC.md.

FILES TO IMPLEMENT:
1. backend/app/recon/subdomain_scanner.py:
   - Query crt.sh (JSON parsing with regex sanitation)
   - Query AlienVault OTX & HackerTarget APIs
   - Wildcard DNS detector (query 3 random UUID subdomains, match IP sets)
   - Async DNS brute-force with dnspython and semaphore (concurrency=20)
   - De-duplicate and return list of valid hostnames with resolved IPs.
2. backend/app/recon/port_scanner.py:
   - Pure async TCP socket scanner (asyncio.open_connection)
   - Scan top 100 ports with 1.5s timeout and concurrency throttler (semaphore=50)
   - Light banner grabbing (HEAD request for web ports, raw greeting for SSH/FTP/SMTP)
   - Flag critical ports (21, 22, 23, 445, 1433, 3306, 3389, 5432, 6379, 27017).
3. backend/app/recon/tech_detector.py:
   - Embedded signature rules (WordPress, Next.js, React, Vue, Angular, Laravel, Django, Nginx, Apache, Cloudflare)
   - HTTP header analyzer (Server, X-Powered-By, etc.)
   - HTML meta and script tag regex matching
   - MurmurHash3 favicon calculation using base64 76-char RFC format and mmh3
   - Match against embedded favicon hash dictionary.
4. backend/app/recon/ssl_analyzer.py:
   - Inspect SSL on port 443/8443 using ssl and cryptography.x509
   - Calculate remaining days to expiry, flag expired and self-signed certificates
   - Extract Subject Alternative Names (SANs)
   - Identify negotiated TLS version and cipher suite.
5. backend/app/recon/header_auditor.py:
   - Grade HTTP response headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
   - Implement 0-100 score to letter grade (A+, A, B, C, D, F)
   - CORS origin reflection detector with evil-attacker.com payload.
6. backend/app/recon/dns_analyzer.py:
   - SPF record mechanism parser (+all, ~all, -all)
   - DMARC record policy evaluator (none, quarantine, reject)
   - Common DKIM selector probing
   - DNS zone transfer (AXFR) test.
7. backend/app/recon/takeover_auditor.py:
   - Dangling CNAME checker against 25+ cloud fingerprints (AWS S3, GitHub Pages, Heroku, Azure, Shopify, etc.).

VERIFICATION: Write unit tests for each module with sample mock HTTP/DNS responses.
```

---

### Prompt for Phase 3: Threat Intelligence Clients
```text
ROLE: Security Automation Engineer.
TASK: Implement the threat intelligence integration clients in backend/app/intel/.

FILES TO IMPLEMENT:
1. backend/app/intel/epss_client.py:
   - Query FIRST.org EPSS API (https://api.first.org/data/v1/epss?cve={cve_id})
   - Extract epss probability score (0.0 to 1.0) and percentile
   - Local in-memory / SQLite caching with 24-hour expiration.
2. backend/app/intel/cisa_kev.py:
   - Automatic download and caching of CISA Known Exploited Vulnerabilities catalog
   - In-memory set lookup for O(1) matching against any detected CVE ID
   - Expose is_in_kev(cve_id: str) -> bool.
3. backend/app/intel/shodan_client.py:
   - Query Shodan InternetDB (https://internetdb.shodan.io/{ip}) (free, zero-API-key required)
   - Extract known open ports, vulnerabilities (CVE list), and CPEs.
   - If user supplied paid SHODAN_API_KEY in config, allow extended host lookup.

VERIFICATION: Test EPSS lookup on CVE-2021-44228 (Log4Shell) and assert epss > 0.9.
```

---

### Prompt for Phase 4: AI/ML Risk Scoring & SHAP Explainability
```text
ROLE: Machine Learning & AI Security Specialist.
TASK: Build the synthetic training data generator, train the XGBoost risk scoring model, and implement the SHAP explainability engine according to docs/03_AI_ML_SPEC.md.

FILES TO IMPLEMENT:
1. backend/train_model.py:
   - Generate 5,000 synthetic asset samples matching the 5 security profiles (critical, high, medium, low, info)
   - Engineer all 30 features defined in the feature vector table (ports, SSL days, missing headers, CVEs, EPSS, KEV, takeovers)
   - Calculate target risk_score (0 to 100) using weighted ground truth formula
   - Train XGBRegressor with hyperparams (n_estimators=150, max_depth=5, learning_rate=0.08)
   - Save trained model to backend/app/ai/risk_model.json
   - Fit and save TreeExplainer to backend/app/ai/explainer.pkl.
2. backend/app/ai/risk_engine.py:
   - Feature extraction pipeline converting Asset database entity + child records into numpy feature array
   - Model inference returning risk_score (0.0 to 100.0) and risk_level classification (critical, high, medium, low, info).
3. backend/app/ai/shap_explainer.py:
   - Calculate exact SHAP feature contributions for a given asset
   - Sort features by absolute contribution
   - Generate top 5 positive and negative contributing factors
   - Generate human-readable explanation strings (e.g. "Exposed RDP port 3389 added +28.5 risk points").

VERIFICATION: Run python train_model.py, confirm model achieves RMSE < 5.0 and R² > 0.95, and test single asset inference with SHAP output.
```

---

### Prompt for Phase 5: Scan Orchestrator & Live SSE Pipeline
```text
ROLE: Distributed Systems & Async Python Architect.
TASK: Implement the scan orchestrator pipeline in backend/app/recon/orchestrator.py and backend/app/api/scans.py.

REQUIREMENTS:
1. Orchestrator Workflow:
   - Accept scan_id and target_domain
   - Step 1: Subdomain discovery (crt.sh + OTX + brute force)
   - Step 2: Concurrently scan open ports for each discovered asset
   - Step 3: Run web inspection (headers, tech detector, SSL certs)
   - Step 4: Run DNS posture & takeover checks
   - Step 5: Threat intelligence enrichment (EPSS, KEV, Shodan)
   - Step 6: ML risk scoring & SHAP explanation generation
   - Step 7: Update scan summary stats (total_assets, avg_risk_score, severity counts)
2. Asynchronous Execution:
   - Run scans as background tasks (asyncio.create_task or BackgroundTasks)
   - Fault isolation: If an individual asset times out or fails, log the error and continue scanning remaining assets
3. Real-Time Streaming:
   - Implement an async event queue or callback mechanism per scan_id
   - Stream real-time progress events to SSE endpoint /api/scans/{scan_id}/stream:
     - scan_progress (percentage, current asset, phase)
     - asset_discovered (hostname, ip)
     - scan_completed / scan_failed.

VERIFICATION: Trigger a test scan and connect via curl -N http://localhost:8000/api/scans/{id}/stream to observe live event stream.
```

---

### Prompt for Phase 6: FastAPI REST API Routers
```text
ROLE: Backend API Developer.
TASK: Implement complete REST endpoints in backend/app/api/ according to docs/05_API_AND_DATABASE_SPEC.md.

FILES TO IMPLEMENT:
1. backend/app/api/scans.py:
   - POST /api/scans (initiate scan)
   - GET /api/scans (list scans with pagination)
   - GET /api/scans/{id} (get scan summary)
   - GET /api/scans/{id}/stream (SSE stream)
   - DELETE /api/scans/{id} (cancel/delete)
2. backend/app/api/assets.py:
   - GET /api/assets (query assets with filters: scan_id, risk_level, has_critical_ports, search)
   - GET /api/assets/{id} (full detail dossier including ports, techs, SSL, headers, vulnerabilities, SHAP explanations)
3. backend/app/api/dashboard.py:
   - GET /api/dashboard/stats (aggregate metrics across scans or latest scan)
4. backend/app/api/reports.py:
   - POST /api/reports/generate (generate report)
   - GET /api/reports/{id} (fetch report)
   - GET /api/reports/{id}/download (download as HTML, Markdown, or JSON)
5. backend/app/main.py:
   - FastAPI app initialization
   - CORS middleware configuration (allow localhost:5173 for Vite)
   - Exception handlers for standard error envelope (success: false, error: {...})
   - Include all routers with /api prefix.

VERIFICATION: Run uvicorn app.main:app and verify docs at http://localhost:8000/docs.
```

---

### Prompt for Phase 7: Report Generation Engine
```text
ROLE: Python Report Generation & LLM Integration Specialist.
TASK: Implement backend/app/reports/report_generator.py using Google Gemini API with fallback to Jinja2 template rendering.

SPECIFICATION:
1. Gemini LLM Generation:
   - If GEMINI_API_KEY is present, format full scan context (total assets, top critical targets, exposed ports, SHAP explanations) and send prompt to gemini-1.5-flash / gemini-2.0
   - Prompt instructions: Produce professional CISO executive briefing, financial exposure assessment, and prioritized technical remediation table.
2. Jinja2 Fallback Template:
   - If GEMINI_API_KEY is missing or API errors, render high-quality deterministic report using pre-built Jinja2 template (backend/app/reports/templates/executive_report.html)
   - Calculate posture metrics, compile critical findings, and generate remediation table.
3. Export Formats:
   - Generate styled HTML with dark cyber styling embedded
   - Generate clean GitHub-flavored Markdown.

VERIFICATION: Generate report for a scan session, test both Gemini API and fallback template.
```

---

### Prompt for Phase 8: Frontend React + Vite UI
```text
ROLE: Senior Frontend Engineer & UI/UX Specialist.
TASK: Implement the complete React + Vite frontend application in frontend/ according to docs/06_FRONTEND_UI_UX_SPEC.md.

REQUIREMENTS:
1. Visual Design & Theme:
   - Implement cyber dark theme in frontend/src/index.css using exact CSS variables from spec
   - Glassmorphism cards, glowing borders, modern sans-serif typography, responsive navigation
2. Core Pages to Implement:
   - DashboardPage: Metric stat cards (Assets, Avg Risk, Critical Ports), Severity distribution chart, Top Risky Assets list, Recent Scans table
   - ScansPage & ScanDetailPage: Scan launcher form (Target domain, profile selection), Live futuristic terminal with SSE auto-scrolling log stream and progress bar
   - AssetsPage: Filterable, searchable data table with severity badges, sortable columns, and quick filter pills
   - AssetDetailModal: Slide-over drawer with SHAP waterfall contribution chart, ports table, technologies, SSL cert validity, security headers grade, and CVEs
   - ReportsPage: Interactive report previewer with "Download PDF/HTML" and "Copy Markdown" buttons
3. API Client & State:
   - Implement frontend/src/services/api.js using fetch or axios
   - Implement SSE listener hook in frontend/src/services/sse.js.

VERIFICATION: Run npm run dev and test dashboard navigation, table filtering, and scan launching.
```

---

### Prompt for Phase 9: Demo Mode & Synthetic Test Data
```text
ROLE: Full-Stack Developer & QA Specialist.
TASK: Implement Demo Mode fixture support in backend/app/demo_fixture.py.

REQUIREMENTS:
1. When DEMO_MODE=true in .env:
   - Pre-populate database on startup with realistic enterprise scan data for "cyber-corp-demo.com"
   - Include 28 assets:
     - 3 Critical: dev-vpn.cyber-corp-demo.com (RDP 3389 exposed), legacy-api.cyber-corp-demo.com (CVE-2021-44228 Log4Shell, EPSS 0.97), shop.cyber-corp-demo.com (dangling GitHub Pages CNAME takeover)
     - 7 High: expired SSL certs, exposed MySQL 3306, missing HSTS and CSP
     - 12 Medium: outdated Nginx versions, missing Referrer-Policy
     - 6 Low/Info: standard static CDNs and apex domain
   - Pre-computed SHAP explanation features for each asset
   - Pre-generated executive report.
2. Safe presentation capability: Allows instant, flawless demonstration without active network packets or rate limit concerns.

VERIFICATION: Launch backend with DEMO_MODE=true, open frontend, and verify all metrics, tables, and modal drawers render instantly.
```

---

### Prompt for Phase 10: End-to-End Verification & Documentation
```text
ROLE: Lead QA & DevOps Engineer.
TASK: Create automated test suites, end-to-end integration tests, and developer onboarding documentation.

FILES TO IMPLEMENT:
1. backend/tests/test_recon.py (test each recon submodule with mocked network calls)
2. backend/tests/test_ml.py (test XGBoost model inference and SHAP explainability calculations)
3. backend/tests/test_api.py (test FastAPI endpoints using TestClient)
4. README.md in project root:
   - Hero banner and architecture diagram
   - Feature highlight matrix
   - Quick start guide (Backend setup, model training, frontend setup)
   - Configuration environment variables table (.env.example)
   - API endpoints summary table
   - Screenshots and demo instructions.

VERIFICATION: Run pytest in backend and verify all tests pass with 0 failures.
```
