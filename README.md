# 🛡️ AEGIS — AI-Powered Attack Surface Management Platform

<div align="center">

```
   █████╗ ███████╗ ██████╗ ██╗███████╗
  ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
  ███████║█████╗  ██║  ███╗██║███████╗
  ██╔══██║██╔══╝  ██║   ██║██║╚════██║
  ██║  ██║███████╗╚██████╔╝██║███████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
```

**Attack Surface Enumeration & Guided Intelligence System**  
*Open-Source, AI-Driven External Attack Surface Management (ASM) Platform*

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18+-61DAFB?style=flat&logo=react&logoColor=black)](https://reactjs.org)
[![XGBoost](https://img.shields.io/badge/XGBoost-2.1+-EB5424?style=flat)](https://xgboost.ai)
[![SHAP](https://img.shields.io/badge/Explainability-SHAP-blueviolet?style=flat)](https://shap.readthedocs.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

</div>

---

## 📖 Executive Summary

**AEGIS** is an enterprise-grade, open-source Attack Surface Management (ASM) system designed to solve the critical visibility and prioritization challenges facing modern organizations. Given an apex domain (e.g. `example.com`), AEGIS autonomously discovers all internet-facing assets, performs multi-vector reconnaissance, calculates AI-driven risk scores with explainable SHAP reasoning, and generates executive and technical intelligence reports.

Think of AEGIS as an open-source, highly transparent alternative to proprietary enterprise platforms like **CrowdStrike Falcon Surface** and **Palo Alto Cortex Xpanse** ($100K–$500K/year).

---

## 🏛️ System Architecture

```
                                    ┌────────────────────────────────────────────────────────┐
                                    │                FRONTEND (React + Vite)                 │
                                    │  • Dark Cyber Aesthetic  • Real-Time SSE Terminal      │
                                    │  • Attack Surface Graph  • SHAP Waterfall Chart        │
                                    └───────────────────────────┬────────────────────────────┘
                                                                │ HTTP / REST / SSE
                                                                ▼
┌────────────────────────────────────────────────────────────────────────────────────────────┐
│                                     BACKEND (Python FastAPI)                               │
│                                                                                            │
│   ┌───────────────────────┐    ┌────────────────────────┐    ┌─────────────────────────┐   │
│   │   Scan Orchestrator   │    │     AI Risk Engine     │    │    Report Generator     │   │
│   │   Async DAG Execution │    │ XGBoost + SHAP TreeExp │    │ Google Gemini + Jinja2  │   │
│   └───────────┬───────────┘    └───────────▲────────────┘    └─────────────────────────┘   │
│               │                            │                                               │
│   ┌───────────▼────────────────────────────┴───────────────────────────────────────────┐   │
│   │                                RECONNAISSANCE ENGINE                               │   │
│   │  • Subdomain Discovery (crt.sh, AlienVault OTX, HackerTarget, Wildcard DNS Filter) │   │
│   │  • Async Port Scanner (Top 100 ports, TCP connect, banner grabbing)               │   │
│   │  • Technology Fingerprinting (Wappalyzer signatures + MurmurHash3 favicon)         │   │
│   │  • SSL/TLS Inspector (cryptography X.509, cipher suites, expiration, SANs)         │   │
│   │  • Security Header Auditor (A-F grading, CSP, HSTS, CORS reflection test)          │   │
│   │  • DNS & Email Posture (SPF parser, DMARC validator, DKIM selectors, AXFR)        │   │
│   │  • Subdomain Takeover Auditor (25+ cloud fingerprints: S3, GitHub Pages, etc.)     │   │
│   └────────────────────────────────────────┬───────────────────────────────────────────┘   │
│                                            │                                               │
│   ┌────────────────────────────────────────▼───────────────────────────────────────────┐   │
│   │                               THREAT INTELLIGENCE                                  │   │
│   │  • FIRST.org EPSS API      • CISA Known Exploited Vulnerabilities (KEV) Cache      │   │
│   │  • Shodan InternetDB       • AbuseIPDB Reputation                                  │   │
│   └────────────────────────────────────────┬───────────────────────────────────────────┘   │
│                                            │                                               │
│   ┌────────────────────────────────────────▼───────────────────────────────────────────┐   │
│   │                        SQLITE DATABASE (SQLAlchemy 2.0)                            │   │
│   │   scans │ assets │ ports │ technologies │ vulnerabilities │ ssl_certs │ headers     │   │
│   └────────────────────────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 📚 Master Documentation Suite

The complete engineering and operational specifications are meticulously documented in [`docs/`](file:///d:/PROJECTS/HMMM/PROJ1/docs):

| Document | Title | Purpose |
|---|---|---|
| **[`01_PRD.md`](file:///d:/PROJECTS/HMMM/PROJ1/docs/01_PRD.md)** | Product Requirements Document | Business case, user personas, functional & non-functional requirements, and success metrics |
| **[`02_TECHNICAL_SPEC.md`](file:///d:/PROJECTS/HMMM/PROJ1/docs/02_TECHNICAL_SPEC.md)** | System Technical Specification | Component architecture, tech stack selections, database schema, and project layout |
| **[`03_AI_ML_SPEC.md`](file:///d:/PROJECTS/HMMM/PROJ1/docs/03_AI_ML_SPEC.md)** | AI/ML Implementation Guide | Synthetic data generation rules, 30-feature vector, XGBoost hyperparams, and SHAP pipeline |
| **[`04_RECON_ENGINE_SPEC.md`](file:///d:/PROJECTS/HMMM/PROJ1/docs/04_RECON_ENGINE_SPEC.md)** | Reconnaissance Engine Specification | In-depth algorithms for all 8 recon submodules, wildcard detection, mmh3 hashing, and takeover rules |
| **[`05_API_AND_DATABASE_SPEC.md`](file:///d:/PROJECTS/HMMM/PROJ1/docs/05_API_AND_DATABASE_SPEC.md)** | API & Database Specification | Complete SQLAlchemy 2.0 ERD, field definitions, REST endpoints, SSE stream contracts, and JSON envelopes |
| **[`06_FRONTEND_UI_UX_SPEC.md`](file:///d:/PROJECTS/HMMM/PROJ1/docs/06_FRONTEND_UI_UX_SPEC.md)** | Frontend UI/UX Design System | Cyber dark mode design tokens, glassmorphism rules, page layouts, component tree, and SHAP charts |
| **[`07_IMPLEMENTATION_ROADMAP_AND_PROMPTS.md`](file:///d:/PROJECTS/HMMM/PROJ1/docs/07_IMPLEMENTATION_ROADMAP_AND_PROMPTS.md)** | Roadmap & Turnkey AI Prompts | 10-phase execution plan with ready-to-run prompts for autonomous AI coding agents |

---

## ⚡ Key Highlights & Innovations

1. **Explainable AI Risk Scoring (SHAP)**:
   - Unlike opaque 1-100 scores from traditional scanners, AEGIS utilizes **SHAP (SHapley Additive exPlanations)** to break down every single score into human-comprehensible factor contributions (e.g. `+32.4 pts` due to exposed RDP, `+14.2 pts` due to expired SSL cert, `-10.0 pts` for strict HSTS).
2. **Native Asynchronous Recon Engine**:
   - Built directly on Python's `asyncio` and `httpx`, avoiding fragile external CLI wrappers and achieving sub-3-minute scan completion for typical mid-sized external attack surfaces.
3. **Subdomain Takeover Defense**:
   - Detects dangling CNAMEs referencing 25+ cloud providers (AWS S3, GitHub Pages, Heroku, Azure, Shopify, Fastly, etc.) before threat actors can claim them.
4. **Active Exploit Enrichment (EPSS & CISA KEV)**:
   - Integrates FIRST.org Exploit Prediction Scoring System (EPSS) and CISA's Known Exploited Vulnerabilities catalog to distinguish theoretical vulnerabilities from active, in-the-wild threats.
5. **Zero-Setup Demo Mode**:
   - Includes a deterministic, pre-loaded synthetic corporate attack surface (`cyber-corp-demo.com`) allowing instant live demos without performing active network scans.

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.11+
- Node.js 18+ & npm

### 1. Backend Setup
```bash
cd backend
python -m venv venv

# Windows
venv\Scripts\activate
# Linux / macOS
# source venv/bin/activate

pip install -r requirements.txt
cp ../.env.example .env    # Configure your API keys (optional: DEMO_MODE=true)

# Train the AI Risk Model and generate SHAP explainer
python train_model.py

# Launch the FastAPI backend server
uvicorn app.main:app --reload --port 8000
```
Backend API will be accessible at `http://localhost:8000`  
Interactive Swagger docs: `http://localhost:8000/docs`

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Frontend UI will be running at `http://localhost:5173`

---

## 🛡️ License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
