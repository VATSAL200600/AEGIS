# AEGIS — Frontend UI/UX Design System & Component Specification

**Document**: 06_FRONTEND_UI_UX_SPEC.md  
**Version**: 1.0  
**Target Audience**: Frontend Engineers & AI Coding Agents  

---

## 1. Visual Design Philosophy & Aesthetics

AEGIS features a **high-tech cybersecurity SOC (Security Operations Center) aesthetic**:
- **Deep Obsidian Dark Mode**: Layered dark backgrounds (`#0a0d14`, `#101420`, `#171d2e`) with subtle neon and glowing accent highlights.
- **Glassmorphism**: Translucent backdrop-filter surfaces (`backdrop-filter: blur(16px); background: rgba(16, 20, 32, 0.75)`) with crisp 1px borders (`rgba(255, 255, 255, 0.08)`).
- **Vibrant Accent Neon Palette**:
  - Primary Cyan: `#00f0ff` (glow: `0 0 20px rgba(0, 240, 255, 0.35)`)
  - Attack Surface Emerald: `#10b981` (clean assets, secure states)
  - Critical Crimson: `#ff3366` (high risk, critical CVEs, exposed RDP)
  - Warning Amber: `#f59e0b` (medium issues, missing headers)
  - Electric Violet: `#8b5cf6` (AI intelligence, ML predictions, SHAP explainability)
- **Modern Typography**:
  - Primary UI Font: `'Outfit'`, `'Inter'`, system-ui, sans-serif
  - Monospace/Terminal: `'JetBrains Mono'`, `'Fira Code'`, monospace
- **Micro-animations**: Subtle glowing borders, pulse badges on active scanning, smooth accordion transitions, interactive hover cards.

---

## 2. Global Design System Tokens (`index.css`)

```css
:root {
  /* Surface Layers */
  --bg-primary: #07090e;
  --bg-secondary: #0d111a;
  --bg-surface: #131926;
  --bg-surface-elevated: #1a2234;
  --bg-glass: rgba(19, 25, 38, 0.75);
  
  /* Borders */
  --border-subtle: rgba(255, 255, 255, 0.06);
  --border-medium: rgba(255, 255, 255, 0.12);
  --border-focus: #00f0ff;
  
  /* Accents */
  --accent-cyan: #00f0ff;
  --accent-cyan-dim: rgba(0, 240, 255, 0.15);
  --accent-purple: #8b5cf6;
  --accent-purple-dim: rgba(139, 92, 246, 0.15);
  
  /* Severity Colors */
  --severity-critical: #ff3366;
  --severity-critical-dim: rgba(255, 51, 102, 0.15);
  --severity-high: #ff7700;
  --severity-high-dim: rgba(255, 119, 0, 0.15);
  --severity-medium: #f59e0b;
  --severity-medium-dim: rgba(245, 158, 11, 0.15);
  --severity-low: #3b82f6;
  --severity-low-dim: rgba(59, 130, 246, 0.15);
  --severity-info: #10b981;
  --severity-info-dim: rgba(16, 185, 129, 0.15);

  /* Typography */
  --text-main: #f1f5f9;
  --text-muted: #94a3b8;
  --text-dim: #64748b;
  
  /* Radii & Shadows */
  --radius-sm: 6px;
  --radius-md: 10px;
  --radius-lg: 16px;
  --shadow-card: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
  --glow-cyan: 0 0 25px rgba(0, 240, 255, 0.25);
  --glow-crimson: 0 0 25px rgba(255, 51, 102, 0.25);
}
```

---

## 3. Application Layout & Navigation Structure

```
┌─────────────────────────────────────────────────────────────────────────┐
│ [AEGIS LOGO]  Target: example.com  [ Quick Scan ]  [+ New Scan] (Nav)   │
├───────────┬─────────────────────────────────────────────────────────────┤
│  SIDEBAR  │ MAIN VIEWPORT                                               │
│           │                                                             │
│ 📊 Dash   │ ┌──────────────┐ ┌──────────────┐ ┌───────────────────────┐ │
│ 🌐 Assets │ │ 184 Total    │ │ 72.4 Avg Risk│ │ 9 Critical Exposure   │ │
│ 🔍 Scans  │ └──────────────┘ └──────────────┘ └───────────────────────┘ │
│ ⚡ Intel  │                                                             │
│ 📑 Reports│ ┌─────────────────────────────┐ ┌─────────────────────────┐ │
│ ⚙️ Config │ │ Risk Score Radar / Topology │ │ Severity Distribution   │ │
│           │ └─────────────────────────────┘ └─────────────────────────┘ │
│           │                                                             │
│           │ ┌─────────────────────────────────────────────────────────┐ │
│           │ │ Discovered Assets Table (Live filtering, search, badges)│ │
│           │ └─────────────────────────────────────────────────────────┘ │
└───────────┴─────────────────────────────────────────────────────────────┘
```

---

## 4. Key Page Specifications

### 4.1 Page 1: Dashboard (`/`)
- **Metric Banners**:
  - Total Monitored Assets (with count change indicator).
  - External Posture Index (0-100 meter with color gradient from Green -> Red).
  - Critical Exposed Ports (RDP 3389, SMB 445, Databases).
  - Takeover & DNS Vulnerabilities count.
- **Interactive Visualizations**:
  - **Attack Surface Heatmap**: Visual grouping of assets by domain level and risk severity.
  - **Severity Donut Chart**: Proportional split of Critical, High, Medium, Low, Info findings.
  - **Top 5 High-Risk Targets Card**: Instant remediation drill-down.
- **Recent Scans Table**: Quick view of latest scans, status, and duration.

### 4.2 Page 2: New Scan & Live Scan Terminal (`/scans/new` and `/scans/:id`)
- **Config Form**:
  - Target domain input with validation (rejects invalid hostnames or URLs with protocols).
  - Scan Profile Selector:
    - *Quick* (approx 1 min): Passive CT logs + Top 20 ports.
    - *Standard* (approx 3 min): Subdomains + Port scan top 100 + Headers + SSL + CVEs.
    - *Deep* (approx 6 min): Brute-force + Full banners + Subdomain takeover + EPSS/KEV.
  - Custom API Keys toggle (Shodan, VirusTotal, AbuseIPDB optional overrides).
- **Live Terminal & Progress View**:
  - Neon radial progress gauge (0 to 100%).
  - Phase status indicators (step-by-step pipeline ticks).
  - Real-time streaming log output styled like a futuristic cybersecurity terminal with auto-scroll.
  - Discovered asset ticker counter updating in real-time as SSE events arrive.

### 4.3 Page 3: Asset Inventory & Explorer (`/assets`)
- **Search & Filter Toolbar**:
  - Free text search (fuzzy search on subdomain, IP, service).
  - Severity pills toggle (`All`, `Critical`, `High`, `Medium`, `Low`, `Info`).
  - Tags filter (`Exposed Database`, `Expired SSL`, `Subdomain Takeover`, `Missing CSP`).
- **Asset Data Table**:
  - Columns: Hostname, IP Address, Open Ports (pill tags), Key Techs, Header Grade, Risk Score Badge, Actions.
  - Row click opens **Asset Detail Drawer**.

### 4.4 Page 4: Asset Detail Dossier (Modal / Slide-Over Drawer)
- **Header**: Hostname, IP, Apex domain, Geolocation, ASN, Risk Score badge with classification.
- **Tab 1: AI Risk Explanation (SHAP Waterfall)**:
  - Interactive horizontal waterfall bar chart showing exactly why the model assigned the risk score.
  - Example: `Base Score: 20` + `Exposed RDP Port (+35)` + `Expired SSL (+18)` + `Missing HSTS (+8)` = `Total Risk: 81 (Critical)`.
  - Natural-language explanation generated from SHAP attributes.
- **Tab 2: Network & Ports**:
  - Table of open ports, protocol, service detection, and grabbed banners.
- **Tab 3: Technologies**:
  - Detected CMS, web servers, frontend libraries with versions and outdated warnings.
- **Tab 4: SSL/TLS & Headers**:
  - Certificate validity timeline, cipher suite rating, SAN list.
  - Security header audit table with recommendations and grade.
- **Tab 5: Vulnerabilities & Intel**:
  - CVE cards showing CVSS v3 score, EPSS exploit probability, and CISA KEV badge.

### 4.5 Page 5: Executive & Technical Reports (`/reports/:id`)
- **Report Controls**:
  - Switch between Executive Summary (CISO/Board level) and Technical Remediation Plan (DevSecOps/Engineers).
  - "Export PDF", "Export HTML", and "Copy Markdown" buttons.
- **Rendered Report View**:
  - Executive Briefing with high-level risks and financial exposure metrics.
  - Asset Inventory Summary Table.
  - Actionable Remediation Checklist with priority ranks (1, 2, 3...) and estimated effort.

---

## 5. UI Component Hierarchy & Architecture

```
src/
├── components/
│   ├── layout/
│   │   ├── Navbar.jsx               # Top header with quick status and new scan button
│   │   ├── Sidebar.jsx              # Collapsible navigation menu
│   │   └── MainLayout.jsx           # App wrapper with responsive grid
│   ├── dashboard/
│   │   ├── StatCard.jsx             # Metric cards with neon border glow
│   │   ├── RiskGauge.jsx            # SVG circular gauge for overall posture
│   │   ├── SeverityChart.jsx        # Donut chart for vulnerability distribution
│   │   └── TopRisksList.jsx         # Most vulnerable assets quick list
│   ├── scan/
│   │   ├── ScanForm.jsx             # Domain input and options modal
│   │   ├── ScanTerminal.jsx         # Real-time SSE streaming log terminal
│   │   └── ScanPipelineSteps.jsx    # Visual step progression (1 to 6)
│   ├── assets/
│   │   ├── AssetTable.jsx           # High performance sortable data table
│   │   ├── AssetDetailModal.jsx     # Deep dive drawer
│   │   ├── ShapWaterfall.jsx        # SVG/Canvas horizontal contribution bars
│   │   └── RiskBadge.jsx            # Color-coded risk level badge
│   └── common/
│       ├── Button.jsx               # Glowing cyber styled buttons
│       ├── Input.jsx                # Glassmorphic inputs with focus effects
│       ├── Modal.jsx                # Backdrop blur dialog
│       └── Toast.jsx                # Notification popups
├── pages/
│   ├── DashboardPage.jsx
│   ├── ScansPage.jsx
│   ├── ScanDetailPage.jsx
│   ├── AssetsPage.jsx
│   └── ReportsPage.jsx
├── services/
│   ├── api.js                       # Axios/fetch wrapper with error interceptors
│   └── sse.js                       # Server-Sent Events subscription helper
└── utils/
    ├── formatters.js                # Port, date, and score formatters
    └── riskColors.js                # Severity-to-CSS mapping helpers
```
