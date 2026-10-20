# 🔬 AEGIS — Exhaustive Algorithm & Research Report

> **Every algorithm, research paper, framework, and tool in the world — mapped to what AEGIS should implement**

---

## Table of Contents
1. [Asset Discovery Algorithms](#1-asset-discovery-algorithms)
2. [ML Models for Risk Scoring — Benchmarks](#2-ml-models-for-risk-scoring)
3. [Graph Neural Networks — Attack Path & Asset Correlation](#3-graph-neural-networks)
4. [Anomaly Detection Algorithms](#4-anomaly-detection-algorithms)
5. [Explainable AI (XAI) — SHAP & LIME](#5-explainable-ai)
6. [Vulnerability Prioritization — CVSS vs EPSS vs Bayesian](#6-vulnerability-prioritization)
7. [Technology Fingerprinting Algorithms](#7-technology-fingerprinting)
8. [Subdomain Takeover Detection](#8-subdomain-takeover-detection)
9. [NLP & LLM for Report Generation](#9-nlp--llm-for-report-generation)
10. [Open Source Tools & CTEM Framework](#10-open-source-tools--ctem-framework)
11. [Final Recommendation — What AEGIS Should Use](#11-final-recommendation)

---

## 1. Asset Discovery Algorithms

### 1.1 Certificate Transparency (CT) Log Mining

**Research Foundation**: CT logs are append-only Merkle Trees (RFC 6962) containing all publicly issued TLS certificates. SANs (Subject Alternative Names) reveal subdomains.

**Algorithm**:
```
INPUT: target_domain
OUTPUT: set of discovered subdomains

1. Query crt.sh API: SELECT name_value FROM certificate WHERE name_value LIKE '%.target_domain'
2. Parse JSON response → extract all SAN entries
3. Deduplicate and normalize:
   - Strip wildcard prefixes (*.)
   - Remove expired certificates (optional filter)
   - Lowercase all entries
4. Cross-validate via DNS resolution (asyncio bulk resolve)
5. Return validated subdomain set
```

**Accuracy**: Discovers **40-80%** of an organization's subdomains passively
**Key Paper**: *"Certificate Transparency: Logging All TLS Certificates"* — B. Laurie et al. (Google, RFC 6962)
**AEGIS Implementation**: ✅ **Core module** — first pass of all discovery

---

### 1.2 DNS Brute-Force with Wildcard Filtering

**Algorithm (with wildcard detection)**:
```
INPUT: target_domain, wordlist (100K+ entries)
OUTPUT: valid subdomains

1. WILDCARD DETECTION:
   a. Generate 5 random strings (e.g., "x7k2m9p4q1.target_domain")
   b. Resolve each via DNS
   c. If ANY resolves → wildcard_ip = resolved_ip
   d. Set wildcard_detected = True

2. ASYNC BRUTE-FORCE:
   a. For each word W in wordlist:
      - Construct candidate = W + "." + target_domain
      - Async DNS resolve (A record)
      - If resolved AND resolved_ip ≠ wildcard_ip:
        → Add to valid_subdomains

3. SMART RATE LIMITING:
   - Use semaphore (max 500 concurrent queries)
   - Rotate DNS resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9)
   - Exponential backoff on SERVFAIL
```

**Key Insight**: Without wildcard filtering, false positive rate can exceed 90% on wildcard domains.
**Tools**: MassDNS achieves 10,000+ queries/second using async I/O
**AEGIS Implementation**: ✅ **Core module** — second pass after CT logs

---

### 1.3 Permutation/Alteration Scanning

**Algorithm (Altdns-style)**:
```
INPUT: seed_subdomains (from CT + brute-force), modifier_list
OUTPUT: expanded subdomain set

1. TOKENIZE seeds:
   "staging-api-v1.target.com" → ["staging", "api", "v1"]

2. MUTATION RULES:
   For each seed:
     a. PREFIX mutations:  dev-{seed}, test-{seed}, stg-{seed}, int-{seed}
     b. SUFFIX mutations:  {seed}-dev, {seed}-staging, {seed}-uat, {seed}-old
     c. NUMERIC iteration: {seed}-1, {seed}-2, ..., {seed}-10
     d. WORD SWAP:         Replace each token with modifiers
     e. SEPARATOR SWAP:    Replace "-" with ".", "_", or remove

3. PERMUTATION MATRIX:
   New = Modifier × Separator × Original_Token
   Complexity: O(n × m) where n = seeds, m = modifiers

4. Async DNS resolution of all generated candidates
5. Filter via wildcard baseline
```

**Key Paper**: *"Altdns - Subdomain Discovery Through Alterations and Permutations"* — Shubham Shah (2017)
**AEGIS Implementation**: ✅ **Core module** — third pass, expands discovery by 15-30%

---

### 1.4 Graph-Based Recursive Enumeration (Amass-style)

**Algorithm**:
```
INPUT: target_domain
OUTPUT: infrastructure graph G(V, E)

1. Initialize graph G with root node = target_domain

2. For each discovered asset A:
   a. Resolve A → IP addresses
   b. Reverse DNS on each IP → find co-hosted domains
   c. WHOIS lookup on IP → find ASN and netblock owner
   d. Query CT logs for all certs on same IP
   e. For each new discovery D:
      - Add node D to graph G
      - Add edge (A → D) with relationship type
      - If D is a new subdomain → recurse (go to step 2)

3. RECURSION CONTROL:
   - Max depth = 3 levels
   - Deduplication via visited set
   - Rate limiting per data source

4. OUTPUT: Graph database with nodes = {Domain, Subdomain, IP, ASN, Organization}
           and edges = {resolves_to, belongs_to, sibling_of, shares_cert_with}
```

**Key Tool**: OWASP Amass — treats discovery as a graph problem using Neo4j backend
**Research**: *"OWASP Amass: In-depth Attack Surface Mapping and Asset Discovery"*
**AEGIS Implementation**: ✅ **Phase 2** — adds infrastructure relationship context

---

### 1.5 Passive DNS (pDNS) Historical Analysis

**What**: Query historical DNS resolution databases to find domains that *previously* resolved to target IPs, or IPs that *previously* hosted target domains.

**Data Sources**: SecurityTrails, Farsight DNSDB, VirusTotal pDNS
**Value**: Finds decommissioned-but-still-resolving assets, old staging servers, and historical infrastructure
**AEGIS Implementation**: ✅ **Phase 2** — supplementary discovery

---

## 2. ML Models for Risk Scoring

### Benchmark Comparison (from cybersecurity research papers)

| Model | Accuracy | F1-Score (Macro) | Training Speed | Inference Speed | Explainability | Best For |
|---|---|---|---|---|---|---|
| **LightGBM** | 98.3–99.9% | 0.95–0.98 | 🟢 Blazing fast | 🟢 Fast | SHAP (TreeSHAP) | Large-scale event logs |
| **XGBoost** | 98.0–99.8% | 0.97–0.98 | 🟢 Fast | 🟢 Fast | SHAP (TreeSHAP) | Robust with regularization |
| **Random Forest** | 97.5–99.5% | 0.96–0.98 | 🟡 Moderate | 🟢 Fast | Feature importance | Reliable out-of-box |
| **Neural Network (MLP)** | 90.0–96.5% | 0.85–0.94 | 🔴 Slow (GPU) | 🟡 Moderate | SHAP/LIME (expensive) | Complex non-linear patterns |
| **Isolation Forest** | N/A (unsupervised) | N/A | 🟢 Fast | 🟢 Very fast | Path-based | Anomaly/outlier detection |
| **Autoencoder** | N/A (unsupervised) | N/A | 🔴 Slow | 🟡 Moderate | Reconstruction error | Temporal anomaly detection |

> [!IMPORTANT]
> **Research consensus**: For tabular cybersecurity data (network flows, asset metadata), **gradient boosted trees (XGBoost/LightGBM) consistently outperform neural networks** in both accuracy and speed. Neural networks only win on raw packet/byte-level data.

### Recommended Risk Scoring Architecture for AEGIS

```mermaid
flowchart LR
    A["Raw Asset Data"] --> B["Feature Engineering"]
    B --> C{"Primary Model"}
    C --> D["XGBoost Classifier"]
    D --> E["Risk Score 0-100"]
    E --> F["SHAP Explainer"]
    F --> G["Risk Factors"]

    B --> H{"Anomaly Detector"}
    H --> I["Isolation Forest"]
    I --> J["Anomaly Flag"]

    E --> K["Score Fusion"]
    J --> K
    K --> L["Final Risk Assessment"]
```

**Feature Vector for Asset Risk Scoring**:
```python
features = {
    # Port & Service Features
    "num_open_ports": int,           # Total open ports
    "num_critical_ports": int,       # Ports 22,23,445,3389,1433,3306,5432
    "has_rdp_exposed": bool,         # RDP (3389) open
    "has_ssh_exposed": bool,         # SSH (22) open
    "has_db_exposed": bool,          # Database ports open

    # SSL/TLS Features
    "ssl_days_until_expiry": int,    # Negative = expired
    "ssl_uses_weak_cipher": bool,    # RC4, DES, NULL
    "ssl_protocol_version": float,   # TLS 1.0=1.0, 1.2=1.2, 1.3=1.3
    "ssl_key_size": int,             # RSA key bits
    "ssl_is_self_signed": bool,

    # Security Header Features
    "num_missing_headers": int,      # Out of CSP,HSTS,X-Frame,etc
    "has_csp": bool,
    "has_hsts": bool,
    "cors_misconfigured": bool,

    # Vulnerability Features
    "num_known_cves": int,           # CVEs for detected tech
    "max_cvss_score": float,         # Highest CVSS
    "max_epss_score": float,         # Highest EPSS probability
    "has_cisa_kev": bool,            # On CISA Known Exploited list
    "num_critical_cves": int,        # CVSS >= 9.0

    # Technology Features
    "tech_is_eol": bool,             # End-of-life software
    "tech_version_age_days": int,    # How old is the version
    "cms_detected": bool,            # WordPress/Drupal/etc
    "has_admin_panel": bool,         # /admin, /wp-admin found
    "has_exposed_api_docs": bool,    # Swagger/GraphQL open

    # DNS/Email Features
    "has_spf": bool,
    "has_dkim": bool,
    "has_dmarc": bool,
    "is_subdomain_takeover_risk": bool,
    "has_dangling_cname": bool,

    # Infrastructure Features
    "is_cloud_hosted": bool,
    "cloud_provider": categorical,   # AWS/Azure/GCP/Other
    "has_waf": bool,
    "has_cdn": bool,

    # Threat Intel Features
    "virustotal_malicious_count": int,
    "abuseipdb_confidence_score": int,
    "shodan_vulns_count": int,
}
```

**Key Papers**:
- *"LightGBM: A Highly Efficient Gradient Boosting Decision Tree"* — Ke et al. (Microsoft, NeurIPS 2017)
- *"XGBoost: A Scalable Tree Boosting System"* — Chen & Guestrin (KDD 2016)
- *"Network Intrusion Detection Using ML: A Comparative Study"* — Multiple surveys on CIC-IDS2017/UNSW-NB15

**AEGIS Implementation**: ✅ **XGBoost as primary model** with SHAP explainability

---

## 3. Graph Neural Networks

### Attack Path & Asset Correlation

**Concept**: Model the organization's infrastructure as a heterogeneous graph where:
- **Nodes** = Assets (hosts, domains, IPs, services)
- **Edges** = Relationships (resolves_to, runs_service, has_vulnerability, communicates_with)

**GNN Variants Used in Research**:

| GNN Type | What It Does | Cybersecurity Application | Key Paper |
|---|---|---|---|
| **GCN** (Graph Convolutional Network) | Aggregates neighbor features via spectral convolutions | Lateral movement detection, IDS | Kipf & Welling, ICLR 2017 |
| **GAT** (Graph Attention Network) | Weighted neighbor aggregation via attention | Prioritize high-risk neighboring assets | Veličković et al., ICLR 2018 |
| **GraphSAGE** | Inductive learning on large graphs via sampling | Scalable attack surface analysis | Hamilton et al., NeurIPS 2017 |
| **GIN** (Graph Isomorphism Network) | Maximum discriminative power among GNNs | Multi-stage attack detection | Xu et al., ICLR 2019 |
| **Node2Vec** | Graph embedding via random walks | Asset similarity and clustering | Grover & Leskovec, KDD 2016 |

**Algorithm Pipeline**:
```
1. GRAPH CONSTRUCTION:
   V = {domain_nodes, ip_nodes, service_nodes, vuln_nodes}
   E = {resolves_to, hosts, has_vuln, shares_cert}

2. FEATURE ENCODING:
   - Node features: [risk_score, num_ports, num_cves, is_internet_facing, ...]
   - Edge features: [relationship_type, confidence, timestamp]

3. GNN MESSAGE PASSING (k layers):
   For each layer l = 1 to k:
     h_v^(l) = σ(W^(l) · AGGREGATE({h_u^(l-1) : u ∈ N(v)}))
   Where N(v) = neighbors of node v

4. PREDICTION TASKS:
   a. Node Classification: Is this asset compromised? (Risk level)
   b. Link Prediction: Will attacker pivot from A to B?
   c. Sub-graph Detection: Identify attack chains
```

**Research Datasets**: SWaT, WADI, HAI (ICS), ToN-IoT, UNSW-NB15
**Frameworks**: PyTorch Geometric (PyG), Deep Graph Library (DGL), NetworkX

> [!TIP]
> **For AEGIS**: Full GNN is overkill for Phase 1. Start with **NetworkX graph** for infrastructure correlation (simpler, no ML needed). Add GNN in Phase 3 if pursuing academic publication.

**AEGIS Implementation**: 
- ✅ **Phase 1**: NetworkX graph for asset relationship visualization
- ⚠️ **Phase 3 (Advanced)**: GAT/GraphSAGE for attack path prediction

---

## 4. Anomaly Detection Algorithms

### For Detecting Abnormal Assets / Sudden Changes

| Algorithm | Type | How It Works | Accuracy (F1) | Speed | Best For |
|---|---|---|---|---|---|
| **Isolation Forest** | Unsupervised, Tree | Isolates anomalies via random splits; fewer splits = more anomalous | Stable | 🟢 Very fast | Global statistical outliers |
| **Autoencoder** | Unsupervised, DNN | Learns to reconstruct normal data; high reconstruction error = anomaly | High | 🔴 Slow train | Complex temporal patterns |
| **LSTM-Autoencoder** | Unsupervised, RNN | Captures temporal sequences in reconstruction | Very high | 🔴 Slow | Time-series anomaly (scan history) |
| **DBSCAN** | Unsupervised, Clustering | Density-based spatial clustering; outliers = noise points | Moderate | 🟢 Fast | Grouping similar assets, finding outliers |
| **One-Class SVM** | Unsupervised, SVM | Learns boundary of "normal" in feature space | Moderate | 🟡 Moderate | Small datasets |
| **Local Outlier Factor (LOF)** | Unsupervised, Density | Compares local density of a point to its neighbors | Moderate | 🟢 Fast | Local anomaly detection |

### Hybrid Architecture (State-of-the-Art)

```mermaid
flowchart LR
    A["Asset Features"] --> B["Isolation Forest"]
    A --> C["LSTM-Autoencoder"]
    B --> D["Anomaly Score 1"]
    C --> E["Anomaly Score 2"]
    D --> F["Score Fusion<br/>(Weighted Average)"]
    E --> F
    F --> G{"Threshold"}
    G -->|Above| H["🚨 Alert: Anomalous Asset"]
    G -->|Below| I["✅ Normal"]
```

**Research Result**: Hybrid pipelines (Isolation Forest + Autoencoder) achieve **>99% F1-score** with dramatically reduced false positives vs either alone.

**AEGIS Implementation**: ✅ **Isolation Forest** for Phase 1 (fast, simple). Hybrid in Phase 3.

---

## 5. Explainable AI (XAI)

### SHAP vs LIME for Cybersecurity Risk Scoring

| Dimension | SHAP | LIME |
|---|---|---|
| **Math Foundation** | Shapley values (game theory) | Local surrogate linear model |
| **Consistency** | ✅ Mathematically guaranteed | ⚠️ Can be unstable across runs |
| **Global Explanations** | ✅ Yes (summary plots) | ❌ Local only |
| **Local Explanations** | ✅ Yes (force plots) | ✅ Yes (feature weights) |
| **Speed** | 🟡 Moderate (TreeSHAP is fast) | 🟢 Fast per prediction |
| **Best For** | Comprehensive audit trails | Quick single-prediction explanations |

### SHAP Implementation for AEGIS Risk Scoring

```python
import shap
import xgboost as xgb

# Train risk model
model = xgb.XGBClassifier()
model.fit(X_train, y_train)

# SHAP Explanations
explainer = shap.TreeExplainer(model)  # TreeSHAP = O(T*L*D) not O(2^F)
shap_values = explainer.shap_values(X_test)

# Per-asset explanation
# "This asset scored 87/100 because:
#   +23 points: RDP port (3389) exposed to internet
#   +19 points: 3 critical CVEs with EPSS > 0.8
#   +15 points: SSL certificate expired 45 days ago
#   +12 points: No CSP or HSTS headers
#   -8 points:  Behind Cloudflare WAF (mitigating factor)"
```

**Key Paper**: *"A Unified Approach to Interpreting Model Predictions"* — Lundberg & Lee (NeurIPS 2017)
**Critical Insight**: SHAP is **non-negotiable** in cybersecurity. Analysts won't trust a black-box score. SHAP provides the "why" that makes the score actionable.

**AEGIS Implementation**: ✅ **Must have** — TreeSHAP with XGBoost (fast, exact)

---

## 6. Vulnerability Prioritization

### The Modern Prioritization Stack

```mermaid
flowchart TD
    A["CVE Discovered"] --> B{"On CISA KEV?"}
    B -->|Yes| C["🔴 CRITICAL — Actively exploited in wild"]
    B -->|No| D{"EPSS Score"}
    D -->|≥ 0.088| E{"CVSS Score"}
    D -->|< 0.088| F["🟢 LOW PRIORITY"]
    E -->|≥ 9.0| G["🔴 CRITICAL"]
    E -->|≥ 7.0| H["🟠 HIGH"]
    E -->|≥ 4.0| I["🟡 MEDIUM"]
    E -->|< 4.0| J["🟢 LOW"]

    C --> K["Asset Context"]
    G --> K
    H --> K
    K -->|Internet-facing| L["⬆️ Escalate"]
    K -->|Internal-only| M["→ Standard priority"]
```

### CVSS vs EPSS vs CISA KEV

| System | What It Measures | Type | Update Frequency | Limitation |
|---|---|---|---|---|
| **CVSS** | Theoretical severity (what COULD happen) | Static score (0-10) | Once per CVE | Doesn't predict actual exploitation |
| **EPSS** | Probability of exploitation within 30 days | Dynamic (0.0-1.0) | Daily | May miss zero-days before data exists |
| **CISA KEV** | Confirmed active exploitation in the wild | Binary (on list or not) | Weekly | Small catalog (~1,100 CVEs) |

### Bayesian Network for Composite Risk (Advanced)

**Algorithm (Bayesian Attack Graph)**:
```
1. CONSTRUCT DAG:
   Nodes = {vulnerability states, asset states, privilege levels}
   Edges = {exploitation paths with conditional probabilities}

2. ASSIGN CPTs (Conditional Probability Tables):
   P(Node_compromised | Parent_nodes_compromised) using:
   - CVSS exploitability sub-score
   - EPSS probability
   - Network accessibility
   - Patch availability

3. INFERENCE (Variable Elimination or MCMC):
   Query: P(Crown_Jewel_Asset_Compromised | Current_Exposure_State)
   
4. MONTE CARLO SIMULATION (for uncertainty):
   Run 10,000 iterations sampling from probability distributions
   Output: Expected loss distribution, Value-at-Risk

Frameworks: pgmpy (Python), PyMC, bnlearn
```

**Key Papers**:
- *"EPSS: Exploit Prediction Scoring System"* — FIRST.org (Jay Jacobs et al.)
- *"Bayesian Network-Based Cyber Security Risk Assessment"* — Multiple papers on attack graph + BN fusion
- *"Prioritizing Vulnerability Remediation with CVSS and EPSS"* — arXiv 2024

> [!IMPORTANT]
> **Key Research Finding**: Using EPSS ≥ 0.088 as a filter **reduces remediation workload by 95%** while still catching the vast majority of actually-exploited vulnerabilities. This threshold was empirically derived.

**AEGIS Implementation**: 
- ✅ **Phase 1**: CVSS + EPSS + CISA KEV decision tree (simple, effective)
- ⚠️ **Phase 3**: Bayesian network for probabilistic risk modeling

---

## 7. Technology Fingerprinting

### Multi-Layer Detection Algorithm

```mermaid
flowchart TD
    A["HTTP Request to Target"] --> B["Layer 1: Header Analysis"]
    B --> C["Layer 2: Cookie Analysis"]
    C --> D["Layer 3: HTML/JS Body Analysis"]
    D --> E["Layer 4: Favicon Hash"]
    E --> F["Layer 5: Error Page Fingerprint"]
    F --> G["Layer 6: Default File Probing"]
    G --> H["Technology Profile"]
    
    B -->|"Server: nginx/1.21"| H
    C -->|"PHPSESSID → PHP"| H
    D -->|"wp-content → WordPress"| H
    E -->|"MMH3: -1234567 → Grafana"| H
    F -->|"404 page style → IIS"| H
    G -->|"/robots.txt patterns"| H
```

### Favicon Hashing Algorithm (MurmurHash3)

```python
import mmh3
import base64
import requests

def favicon_hash(url):
    """Calculate Shodan-compatible favicon hash"""
    response = requests.get(f"{url}/favicon.ico", timeout=5)
    favicon_b64 = base64.encodebytes(response.content).decode()
    hash_value = mmh3.hash(favicon_b64)  # MurmurHash3 → 32-bit signed int
    return hash_value

# Cross-reference with Shodan: http.favicon.hash:{hash_value}
# Known hashes: Grafana=-1854810269, Jenkins=81586312, Spring=116323821
```

### Wappalyzer Detection Model

Declarative JSON fingerprint specification matching simultaneously across:
1. **HTTP Headers** → regex on `Server`, `X-Powered-By`, `X-Generator`
2. **Cookies** → name matching (`JSESSIONID`=Java, `PHPSESSID`=PHP, `connect.sid`=Express)
3. **HTML/DOM** → meta tags, class names, script paths
4. **Script Sources** → external JS file paths (`/wp-includes/`, `/sites/default/`)
5. **Implied Technologies** → if WordPress detected → imply PHP, MySQL

**AEGIS Implementation**: ✅ Custom Wappalyzer-style engine + favicon hashing

---

## 8. Subdomain Takeover Detection

### Detection Algorithm

```
INPUT: list of discovered subdomains with CNAME records
OUTPUT: list of vulnerable subdomains

FINGERPRINT_DB = {
    "github.io": {"cname": "*.github.io", "response": "There isn't a GitHub Pages site here"},
    "herokuapp.com": {"cname": "*.herokuapp.com", "response": "No such app"},
    "s3.amazonaws.com": {"cname": "*.s3.amazonaws.com", "response": "NoSuchBucket"},
    "azurewebsites.net": {"cname": "*.azurewebsites.net", "response": "404 Web Site not found"},
    "cloudfront.net": {"cname": "*.cloudfront.net", "response": "Bad request"},
    "shopify.com": {"cname": "shops.shopify.com", "response": "Sorry, this shop is currently unavailable"},
    ... (50+ cloud services)
}

ALGORITHM:
1. For each subdomain S with CNAME record C:
   a. Resolve CNAME chain recursively (handle multi-hop chains)
   b. Check if terminal CNAME matches any FINGERPRINT_DB pattern
   c. If match found:
      - HTTP probe the subdomain
      - Check response body against fingerprint error string
      - Check for NXDOMAIN on CNAME target
      - If NXDOMAIN or fingerprint matches → VULNERABLE
   d. WILDCARD CHECK: Verify not a false positive from wildcard DNS
   e. If confirmed → Add to vulnerable list with severity = CRITICAL
```

**Key Paper**: *"HostingChecker: Detecting and Preventing Subdomain Takeovers"* — USENIX Security 2024
**Key Resource**: `can-i-take-over-xyz` GitHub repo — community-maintained fingerprint database

**AEGIS Implementation**: ✅ **Must have** — subdomain takeover is a **critical severity** finding

---

## 9. NLP & LLM for Report Generation

### Architecture: RAG-based Security Report Generator

```mermaid
flowchart LR
    A["Scan Results<br/>(Structured JSON)"] --> B["Prompt Template Engine"]
    C["CVE/CWE Database<br/>(RAG Vector Store)"] --> B
    D["MITRE ATT&CK<br/>Mapping"] --> B
    B --> E["LLM<br/>(Gemini/GPT)"]
    E --> F["Executive Summary"]
    E --> G["Technical Report"]
    E --> H["Remediation Guide"]
```

### Multi-Agent Report Generation Pipeline

| Agent | Role | Input | Output |
|---|---|---|---|
| **Analyzer Agent** | Interprets raw scan data, maps to CWEs/MITRE | Scan JSON | Structured findings |
| **Writer Agent** | Generates natural language report sections | Structured findings | Report markdown |
| **Remediation Agent** | Generates fix instructions per finding | Finding + tech context | Step-by-step fixes |
| **Reviewer Agent** | Checks for hallucinations, validates CVE references | Draft report | Validated final report |

### Prompt Engineering for Security Reports

```
SYSTEM: You are a senior cybersecurity analyst generating an executive 
security report. Use formal, precise language. Reference specific CVE 
IDs, CVSS scores, and EPSS probabilities. Structure findings by severity.

CONTEXT: {scan_results_json}

TEMPLATE:
## Executive Summary
[2-3 sentence overview of organization's external attack surface health]

## Critical Findings ({count})
For each critical finding:
- Asset: {hostname}
- Risk: {risk_description}
- Evidence: {technical_evidence}
- Business Impact: {business_impact}
- Remediation: {specific_steps}
- Timeline: {recommended_fix_timeline}

## Risk Score Trend
[Compare with previous scan if available]

## Recommendations (Priority Ordered)
1. [Highest impact remediation]
...
```

**Key Architecture Decision**: RAG (Retrieval-Augmented Generation) is critical to prevent hallucinations. Store CVE descriptions, CWE details, and remediation best practices in a vector database. Retrieve relevant context before LLM generation.

**Key Papers**:
- *"Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks"* — Lewis et al. (Facebook AI, NeurIPS 2020)
- *"FaultLine: Automated LLM-Based Vulnerability Report Generation"* — arXiv 2024

**AEGIS Implementation**: ✅ **Structured prompting with RAG** using Gemini/GPT API

---

## 10. Open Source Tools & CTEM Framework

### Tool Comparison Matrix

| Tool | Language | Primary Function | Speed | Graph Support | Extensibility |
|---|---|---|---|---|---|
| **OWASP Amass** | Go | Deep asset mapping + graph DB | 🟡 Moderate | ✅ Neo4j | Go modules, YAML configs |
| **Subfinder** | Go | Passive subdomain enumeration | 🟢 Blazing | ❌ | YAML provider config |
| **Nuclei** | Go | Template-based vuln scanning | 🟢 Fast | ❌ | Community YAML templates |
| **Httpx** | Go | HTTP probing + tech fingerprinting | 🟢 Blazing | ❌ | JSON output piping |
| **Naabu** | Go | Port scanning | 🟢 Fast | ❌ | stdin/stdout |
| **Reconftw** | Bash | Full recon orchestration | 🟡 Slow | ❌ | Config toggles |
| **SpiderFoot** | Python | OSINT automation platform | 🟡 Moderate | ✅ | Module-based |

### How AEGIS Differs from All of These

| Capability | Existing Tools | AEGIS |
|---|---|---|
| Asset Discovery | ✅ Many tools do this well | ✅ Combines best approaches |
| Unified Platform | ❌ Requires chaining 5-10 tools | ✅ Single platform |
| AI Risk Scoring | ❌ None have ML-based scoring | ✅ XGBoost + SHAP |
| Explainable Findings | ❌ Raw data output only | ✅ "WHY is this risky?" |
| LLM Reports | ❌ None generate natural language reports | ✅ Executive + Technical |
| EPSS Prioritization | ❌ None integrate EPSS | ✅ CVSS + EPSS + CISA KEV |
| Interactive Dashboard | ⚠️ SpiderFoot has basic UI | ✅ Premium React dashboard |
| CTEM Alignment | ❌ Tools, not frameworks | ✅ Full Gartner CTEM cycle |

### Gartner CTEM Framework Alignment

```mermaid
flowchart LR
    A["1. SCOPING<br/>Define target domain<br/>& asset boundaries"] --> B["2. DISCOVERY<br/>CT logs, DNS brute-force,<br/>port scan, tech fingerprint"]
    B --> C["3. PRIORITIZATION<br/>AI risk scoring,<br/>EPSS + CISA KEV,<br/>SHAP explanations"]
    C --> D["4. VALIDATION<br/>Subdomain takeover check,<br/>SSL/header audit,<br/>CVE verification"]
    D --> E["5. MOBILIZATION<br/>LLM-generated reports,<br/>remediation guides,<br/>dashboard alerts"]
    E -->|"Continuous Loop"| A
```

---

## 11. Final Recommendation — What AEGIS Should Use

### Algorithm Selection Summary

| Component | Selected Algorithm | Why This One |
|---|---|---|
| **Subdomain Discovery** | CT Log Mining + Async DNS Brute-force + Altdns Permutation | Combined approach gives 95%+ coverage |
| **Risk Scoring Model** | **XGBoost** | Best accuracy/speed tradeoff for tabular data; TreeSHAP support |
| **Explainability** | **SHAP (TreeSHAP)** | Mathematically guaranteed, fast with tree models, audit-ready |
| **Anomaly Detection** | **Isolation Forest** | Fast, unsupervised, great for identifying unusual assets |
| **Vulnerability Priority** | **CVSS + EPSS + CISA KEV Decision Tree** | Research-backed 95% workload reduction |
| **Asset Correlation** | **NetworkX Graph** | Simple, Python-native, visualization-ready |
| **Tech Fingerprinting** | **Custom Wappalyzer-style engine + MurmurHash3 favicon** | Multi-layer detection for maximum accuracy |
| **Subdomain Takeover** | **CNAME chain resolution + cloud fingerprint DB** | Critical finding, well-understood algorithm |
| **Report Generation** | **LLM (Gemini) + RAG** | Prevents hallucinations, generates actionable reports |
| **SSL Grading** | **Qualys SSL Labs methodology** | Industry standard, well-documented rubric |

### Research Paper Reference List

| # | Paper | Authors | Venue/Year | Relevance |
|---|---|---|---|---|
| 1 | *XGBoost: A Scalable Tree Boosting System* | Chen & Guestrin | KDD 2016 | Risk scoring model |
| 2 | *LightGBM: Highly Efficient GBDT* | Ke et al. (Microsoft) | NeurIPS 2017 | Alternative risk model |
| 3 | *A Unified Approach to Interpreting Model Predictions (SHAP)* | Lundberg & Lee | NeurIPS 2017 | Explainability |
| 4 | *EPSS: Exploit Prediction Scoring System* | Jacobs et al. (FIRST) | 2021-ongoing | Vulnerability prioritization |
| 5 | *Semi-Supervised Classification with GCN* | Kipf & Welling | ICLR 2017 | Graph-based asset analysis |
| 6 | *Graph Attention Networks* | Veličković et al. | ICLR 2018 | Attack path prediction |
| 7 | *Inductive Representation Learning (GraphSAGE)* | Hamilton et al. | NeurIPS 2017 | Scalable graph ML |
| 8 | *Node2Vec: Scalable Feature Learning for Networks* | Grover & Leskovec | KDD 2016 | Asset embedding |
| 9 | *Isolation Forest* | Liu, Ting & Zhou | ICDM 2008 | Anomaly detection |
| 10 | *RAG for Knowledge-Intensive NLP* | Lewis et al. (Meta AI) | NeurIPS 2020 | Report generation |
| 11 | *HostingChecker: Subdomain Takeover Detection* | Chen et al. | USENIX Security 2024 | Takeover detection |
| 12 | *Certificate Transparency (RFC 6962)* | Laurie et al. (Google) | IETF 2013 | CT log mining |
| 13 | *Bayesian Attack Graphs for Risk Assessment* | Poolsappasit et al. | Colorado State Univ | Probabilistic risk |
| 14 | *FaultLine: LLM-Based Vulnerability Reporting* | Multiple | arXiv 2024 | Automated reports |
| 15 | *Altdns: Subdomain Permutation Discovery* | Shubham Shah | 2017 | Permutation scanning |
| 16 | *FAIR-BN: Bayesian Network for Cyber Risk* | Multiple | ResearchGate 2023-24 | Monte Carlo risk simulation |
| 17 | *Gartner CTEM Framework* | Gartner | 2022-ongoing | Strategic framework alignment |
| 18 | *CVSS v3.1 Specification* | FIRST.org | 2019 | Severity scoring |
| 19 | *MITRE ATT&CK Framework* | MITRE Corp | Ongoing | Threat classification |
| 20 | *SSL Labs Grading Methodology* | Qualys | Ongoing | SSL assessment rubric |

---

> [!TIP]
> **Interview Power Move**: When asked *"What research did you base this on?"*, you can cite specific papers (XGBoost KDD 2016, SHAP NeurIPS 2017, EPSS by FIRST.org) and explain WHY you chose each algorithm over alternatives. This demonstrates research depth that most candidates lack.
