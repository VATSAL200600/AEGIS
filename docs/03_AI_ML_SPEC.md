# AEGIS — AI/ML Implementation Guide

**Purpose**: This document specifies exactly how to implement the AI/ML components so any developer or AI can build them without ambiguity.

---

## 1. Synthetic Training Data Generation

Since we don't have labeled real-world ASM data, we generate synthetic training data based on security best practices and CVSS scoring logic.

### 1.1 Generation Rules

Generate **5,000 samples** using the following probability distributions:

```python
"""
Synthetic Data Generation Logic
Each row = one asset with features + label (risk_score 0-100)
"""

import numpy as np
import pandas as pd

def generate_training_data(n_samples=5000):
    np.random.seed(42)
    data = []
    
    for _ in range(n_samples):
        # Randomly assign a risk profile
        profile = np.random.choice(
            ["critical", "high", "medium", "low", "info"],
            p=[0.10, 0.20, 0.30, 0.25, 0.15]
        )
        
        if profile == "critical":
            # Critical assets: lots of issues
            num_open_ports = np.random.randint(5, 20)
            num_critical_ports = np.random.randint(2, 8)
            has_rdp = np.random.choice([0, 1], p=[0.3, 0.7])
            has_ssh = np.random.choice([0, 1], p=[0.2, 0.8])
            has_db = np.random.choice([0, 1], p=[0.3, 0.7])
            ssl_days = np.random.randint(-365, -1)  # Expired
            ssl_expired = 1
            ssl_self_signed = np.random.choice([0, 1], p=[0.4, 0.6])
            ssl_weak_cipher = np.random.choice([0, 1], p=[0.3, 0.7])
            ssl_weak_proto = np.random.choice([0, 1], p=[0.3, 0.7])
            ssl_key_score = np.random.uniform(0.0, 0.4)
            num_missing_headers = np.random.randint(5, 8)
            has_csp = 0
            has_hsts = 0
            cors_misconfig = np.random.choice([0, 1], p=[0.4, 0.6])
            num_cves = np.random.randint(3, 15)
            max_cvss = np.random.uniform(8.0, 10.0)
            max_epss = np.random.uniform(0.5, 1.0)
            has_kev = np.random.choice([0, 1], p=[0.3, 0.7])
            num_critical_cves = np.random.randint(1, 5)
            num_tech = np.random.randint(3, 8)
            has_outdated = 1
            has_cms = np.random.choice([0, 1], p=[0.5, 0.5])
            has_api_docs = np.random.choice([0, 1], p=[0.4, 0.6])
            has_spf = np.random.choice([0, 1], p=[0.6, 0.4])
            has_dkim = np.random.choice([0, 1], p=[0.7, 0.3])
            has_dmarc = np.random.choice([0, 1], p=[0.7, 0.3])
            has_dangling = np.random.choice([0, 1], p=[0.6, 0.4])
            is_cloud = np.random.choice([0, 1])
            has_waf = np.random.choice([0, 1], p=[0.7, 0.3])
            has_cdn = np.random.choice([0, 1], p=[0.7, 0.3])
            vt_malicious = np.random.randint(2, 10)
            abuse_score = np.random.randint(40, 100)
            shodan_vulns = np.random.randint(2, 10)
            risk_score = np.random.uniform(80, 100)
            
        elif profile == "high":
            num_open_ports = np.random.randint(3, 12)
            num_critical_ports = np.random.randint(1, 4)
            has_rdp = np.random.choice([0, 1], p=[0.6, 0.4])
            has_ssh = np.random.choice([0, 1], p=[0.4, 0.6])
            has_db = np.random.choice([0, 1], p=[0.6, 0.4])
            ssl_days = np.random.randint(-30, 60)
            ssl_expired = 1 if ssl_days < 0 else 0
            ssl_self_signed = np.random.choice([0, 1], p=[0.7, 0.3])
            ssl_weak_cipher = np.random.choice([0, 1], p=[0.5, 0.5])
            ssl_weak_proto = np.random.choice([0, 1], p=[0.5, 0.5])
            ssl_key_score = np.random.uniform(0.3, 0.7)
            num_missing_headers = np.random.randint(3, 6)
            has_csp = np.random.choice([0, 1], p=[0.6, 0.4])
            has_hsts = np.random.choice([0, 1], p=[0.5, 0.5])
            cors_misconfig = np.random.choice([0, 1], p=[0.6, 0.4])
            num_cves = np.random.randint(1, 8)
            max_cvss = np.random.uniform(6.0, 9.0)
            max_epss = np.random.uniform(0.2, 0.7)
            has_kev = np.random.choice([0, 1], p=[0.7, 0.3])
            num_critical_cves = np.random.randint(0, 2)
            num_tech = np.random.randint(2, 6)
            has_outdated = np.random.choice([0, 1], p=[0.4, 0.6])
            has_cms = np.random.choice([0, 1])
            has_api_docs = np.random.choice([0, 1], p=[0.6, 0.4])
            has_spf = np.random.choice([0, 1])
            has_dkim = np.random.choice([0, 1], p=[0.5, 0.5])
            has_dmarc = np.random.choice([0, 1], p=[0.5, 0.5])
            has_dangling = np.random.choice([0, 1], p=[0.8, 0.2])
            is_cloud = np.random.choice([0, 1])
            has_waf = np.random.choice([0, 1], p=[0.5, 0.5])
            has_cdn = np.random.choice([0, 1], p=[0.5, 0.5])
            vt_malicious = np.random.randint(0, 5)
            abuse_score = np.random.randint(10, 60)
            shodan_vulns = np.random.randint(0, 5)
            risk_score = np.random.uniform(60, 80)
            
        elif profile == "medium":
            num_open_ports = np.random.randint(1, 6)
            num_critical_ports = np.random.randint(0, 2)
            has_rdp = 0
            has_ssh = np.random.choice([0, 1], p=[0.6, 0.4])
            has_db = np.random.choice([0, 1], p=[0.8, 0.2])
            ssl_days = np.random.randint(30, 180)
            ssl_expired = 0
            ssl_self_signed = np.random.choice([0, 1], p=[0.85, 0.15])
            ssl_weak_cipher = np.random.choice([0, 1], p=[0.7, 0.3])
            ssl_weak_proto = np.random.choice([0, 1], p=[0.7, 0.3])
            ssl_key_score = np.random.uniform(0.5, 0.9)
            num_missing_headers = np.random.randint(2, 5)
            has_csp = np.random.choice([0, 1])
            has_hsts = np.random.choice([0, 1])
            cors_misconfig = np.random.choice([0, 1], p=[0.8, 0.2])
            num_cves = np.random.randint(0, 4)
            max_cvss = np.random.uniform(3.0, 7.0)
            max_epss = np.random.uniform(0.01, 0.3)
            has_kev = 0
            num_critical_cves = 0
            num_tech = np.random.randint(1, 5)
            has_outdated = np.random.choice([0, 1], p=[0.6, 0.4])
            has_cms = np.random.choice([0, 1], p=[0.6, 0.4])
            has_api_docs = np.random.choice([0, 1], p=[0.8, 0.2])
            has_spf = np.random.choice([0, 1], p=[0.4, 0.6])
            has_dkim = np.random.choice([0, 1])
            has_dmarc = np.random.choice([0, 1])
            has_dangling = 0
            is_cloud = np.random.choice([0, 1])
            has_waf = np.random.choice([0, 1])
            has_cdn = np.random.choice([0, 1])
            vt_malicious = np.random.randint(0, 2)
            abuse_score = np.random.randint(0, 30)
            shodan_vulns = np.random.randint(0, 3)
            risk_score = np.random.uniform(40, 60)
            
        elif profile == "low":
            num_open_ports = np.random.randint(1, 3)
            num_critical_ports = 0
            has_rdp = 0
            has_ssh = np.random.choice([0, 1], p=[0.8, 0.2])
            has_db = 0
            ssl_days = np.random.randint(90, 365)
            ssl_expired = 0
            ssl_self_signed = 0
            ssl_weak_cipher = 0
            ssl_weak_proto = np.random.choice([0, 1], p=[0.8, 0.2])
            ssl_key_score = np.random.uniform(0.7, 1.0)
            num_missing_headers = np.random.randint(1, 3)
            has_csp = np.random.choice([0, 1], p=[0.4, 0.6])
            has_hsts = np.random.choice([0, 1], p=[0.3, 0.7])
            cors_misconfig = 0
            num_cves = np.random.randint(0, 2)
            max_cvss = np.random.uniform(0, 5.0)
            max_epss = np.random.uniform(0.0, 0.1)
            has_kev = 0
            num_critical_cves = 0
            num_tech = np.random.randint(1, 3)
            has_outdated = 0
            has_cms = np.random.choice([0, 1], p=[0.7, 0.3])
            has_api_docs = 0
            has_spf = 1
            has_dkim = np.random.choice([0, 1], p=[0.3, 0.7])
            has_dmarc = np.random.choice([0, 1], p=[0.3, 0.7])
            has_dangling = 0
            is_cloud = np.random.choice([0, 1])
            has_waf = np.random.choice([0, 1], p=[0.4, 0.6])
            has_cdn = np.random.choice([0, 1], p=[0.4, 0.6])
            vt_malicious = 0
            abuse_score = np.random.randint(0, 10)
            shodan_vulns = 0
            risk_score = np.random.uniform(20, 40)
            
        else:  # info
            num_open_ports = np.random.randint(1, 2)
            num_critical_ports = 0
            has_rdp = 0
            has_ssh = 0
            has_db = 0
            ssl_days = np.random.randint(180, 730)
            ssl_expired = 0
            ssl_self_signed = 0
            ssl_weak_cipher = 0
            ssl_weak_proto = 0
            ssl_key_score = np.random.uniform(0.9, 1.0)
            num_missing_headers = np.random.randint(0, 2)
            has_csp = 1
            has_hsts = 1
            cors_misconfig = 0
            num_cves = 0
            max_cvss = 0.0
            max_epss = 0.0
            has_kev = 0
            num_critical_cves = 0
            num_tech = np.random.randint(1, 3)
            has_outdated = 0
            has_cms = 0
            has_api_docs = 0
            has_spf = 1
            has_dkim = 1
            has_dmarc = 1
            has_dangling = 0
            is_cloud = np.random.choice([0, 1])
            has_waf = 1
            has_cdn = 1
            vt_malicious = 0
            abuse_score = 0
            shodan_vulns = 0
            risk_score = np.random.uniform(0, 20)
        
        # Add gaussian noise to risk score (±3 points) and clamp
        risk_score = np.clip(risk_score + np.random.normal(0, 3), 0, 100)
        
        data.append({
            "num_open_ports": num_open_ports,
            "num_critical_ports": num_critical_ports,
            "has_rdp_exposed": has_rdp,
            "has_ssh_exposed": has_ssh,
            "has_db_exposed": has_db,
            "ssl_days_until_expiry": ssl_days,
            "ssl_is_expired": ssl_expired,
            "ssl_is_self_signed": ssl_self_signed,
            "ssl_has_weak_cipher": ssl_weak_cipher,
            "ssl_has_weak_protocol": ssl_weak_proto,
            "ssl_key_size_score": round(ssl_key_score, 3),
            "num_missing_headers": num_missing_headers,
            "has_csp": has_csp,
            "has_hsts": has_hsts,
            "cors_misconfigured": cors_misconfig,
            "num_cves": num_cves,
            "max_cvss_score": round(max_cvss, 1),
            "max_epss_score": round(max_epss, 3),
            "has_cisa_kev": has_kev,
            "num_critical_cves": num_critical_cves,
            "num_technologies": num_tech,
            "has_outdated_tech": has_outdated,
            "has_cms": has_cms,
            "has_exposed_api_docs": has_api_docs,
            "has_spf": has_spf,
            "has_dkim": has_dkim,
            "has_dmarc": has_dmarc,
            "has_dangling_cname": has_dangling,
            "is_cloud_hosted": is_cloud,
            "has_waf_detected": has_waf,
            "has_cdn_detected": has_cdn,
            "vt_malicious_count": vt_malicious,
            "abuseipdb_score": abuse_score,
            "shodan_vuln_count": shodan_vulns,
            "risk_score": round(risk_score, 1),
        })
    
    return pd.DataFrame(data)
```

### 1.2 Feature Names (Ordered)

These MUST be used in this exact order for model training and inference:

```python
FEATURE_NAMES = [
    "num_open_ports",
    "num_critical_ports",
    "has_rdp_exposed",
    "has_ssh_exposed",
    "has_db_exposed",
    "ssl_days_until_expiry",
    "ssl_is_expired",
    "ssl_is_self_signed",
    "ssl_has_weak_cipher",
    "ssl_has_weak_protocol",
    "ssl_key_size_score",
    "num_missing_headers",
    "has_csp",
    "has_hsts",
    "cors_misconfigured",
    "num_cves",
    "max_cvss_score",
    "max_epss_score",
    "has_cisa_kev",
    "num_critical_cves",
    "num_technologies",
    "has_outdated_tech",
    "has_cms",
    "has_exposed_api_docs",
    "has_spf",
    "has_dkim",
    "has_dmarc",
    "has_dangling_cname",
    "is_cloud_hosted",
    "has_waf_detected",
    "has_cdn_detected",
    "vt_malicious_count",
    "abuseipdb_score",
    "shodan_vuln_count",
]
```

---

## 2. Model Training Script (`train_model.py`)

```python
"""
train_model.py — Generate synthetic data, train XGBoost, save model

Usage:
    cd backend
    python train_model.py

Output:
    app/ai/risk_model.pkl — serialized XGBoost model
"""

# 1. Generate synthetic data (function above)
# 2. Split into X (features) and y (risk_score)
# 3. Bin risk_score into 5 classes for classification:
#    0 = info (0-19), 1 = low (20-39), 2 = medium (40-59),
#    3 = high (60-79), 4 = critical (80-100)
# 4. Train XGBoost classifier:
#    model = xgb.XGBRegressor(
#        n_estimators=200,
#        max_depth=6,
#        learning_rate=0.1,
#        subsample=0.8,
#        colsample_bytree=0.8,
#        reg_alpha=0.1,
#        reg_lambda=1.0,
#        random_state=42,
#    )
#    model.fit(X_train, y_train)
# 5. Evaluate on test set (print MAE, R², feature importance)
# 6. Save with pickle: pickle.dump(model, open("app/ai/risk_model.pkl", "wb"))
```

**XGBoost Hyperparameters**:
- `n_estimators`: 200 (number of boosting rounds)
- `max_depth`: 6 (tree depth — prevents overfitting)
- `learning_rate`: 0.1 (step size shrinkage)
- `subsample`: 0.8 (row sampling per tree)
- `colsample_bytree`: 0.8 (column sampling per tree)
- `reg_alpha`: 0.1 (L1 regularization)
- `reg_lambda`: 1.0 (L2 regularization)
- **Task**: Regression (predict continuous score 0-100)
- **Objective**: `reg:squarederror`
- **Evaluation metric**: MAE (Mean Absolute Error), R²

---

## 3. Risk Scorer Module (`risk_scorer.py`)

### 3.1 Loading the Model
```python
import pickle
import numpy as np
import shap
import xgboost as xgb

class RiskScorer:
    def __init__(self, model_path: str):
        with open(model_path, "rb") as f:
            self.model = pickle.load(f)
        self.explainer = shap.TreeExplainer(self.model)
    
    def predict(self, features: dict) -> tuple[float, str, list]:
        """
        Args:
            features: dict of feature_name → value (all 34 features)
        
        Returns:
            (risk_score, risk_level, risk_factors)
            risk_score: float 0-100
            risk_level: str "critical"/"high"/"medium"/"low"/"info"
            risk_factors: list of {"factor": str, "impact": str, "direction": str}
        """
        # 1. Convert to numpy array in correct feature order
        X = np.array([[features[f] for f in FEATURE_NAMES]])
        
        # 2. Predict risk score
        score = float(self.model.predict(X)[0])
        score = np.clip(score, 0, 100)
        
        # 3. Determine risk level
        if score >= 80: level = "critical"
        elif score >= 60: level = "high"
        elif score >= 40: level = "medium"
        elif score >= 20: level = "low"
        else: level = "info"
        
        # 4. SHAP explanations
        shap_values = self.explainer.shap_values(X)[0]
        
        # 5. Build risk factors (sorted by absolute impact)
        factors = []
        indices = np.argsort(np.abs(shap_values))[::-1]
        for idx in indices[:10]:  # Top 10 factors
            feature = FEATURE_NAMES[idx]
            value = shap_values[idx]
            if abs(value) < 0.5:
                continue  # Skip negligible factors
            factors.append({
                "factor": FEATURE_DESCRIPTIONS.get(feature, feature),
                "impact": f"+{value:.0f}" if value > 0 else f"{value:.0f}",
                "direction": "up" if value > 0 else "down",
            })
        
        return score, level, factors
```

### 3.2 Feature Description Mapping

```python
FEATURE_DESCRIPTIONS = {
    "num_open_ports": "Multiple open ports exposed to internet",
    "num_critical_ports": "Critical service ports exposed (SSH, RDP, DB)",
    "has_rdp_exposed": "RDP port (3389) directly accessible from internet",
    "has_ssh_exposed": "SSH port (22) accessible from internet",
    "has_db_exposed": "Database port directly accessible from internet",
    "ssl_days_until_expiry": "SSL certificate approaching/past expiry",
    "ssl_is_expired": "SSL certificate has expired",
    "ssl_is_self_signed": "Using self-signed SSL certificate (not trusted)",
    "ssl_has_weak_cipher": "Weak cipher suites enabled (RC4, DES, NULL)",
    "ssl_has_weak_protocol": "Deprecated TLS versions supported (1.0/1.1)",
    "ssl_key_size_score": "Cryptographic key strength assessment",
    "num_missing_headers": "Multiple security headers missing from HTTP response",
    "has_csp": "Content-Security-Policy header",
    "has_hsts": "HTTP Strict Transport Security header",
    "cors_misconfigured": "CORS policy allows any origin (Access-Control-Allow-Origin: *)",
    "num_cves": "Known CVE vulnerabilities in detected software",
    "max_cvss_score": "Highest vulnerability severity score (CVSS)",
    "max_epss_score": "High probability of active exploitation (EPSS)",
    "has_cisa_kev": "Vulnerability is actively exploited in the wild (CISA KEV)",
    "num_critical_cves": "Critical severity vulnerabilities (CVSS ≥ 9.0)",
    "num_technologies": "Number of detected technology components",
    "has_outdated_tech": "Running end-of-life or outdated software versions",
    "has_cms": "Content Management System detected (WordPress, Drupal, etc.)",
    "has_exposed_api_docs": "API documentation publicly accessible (Swagger/GraphQL)",
    "has_spf": "SPF email authentication record",
    "has_dkim": "DKIM email signing record",
    "has_dmarc": "DMARC email authentication policy",
    "has_dangling_cname": "Dangling DNS CNAME record (subdomain takeover risk)",
    "is_cloud_hosted": "Hosted on cloud infrastructure",
    "has_waf_detected": "Web Application Firewall detected (mitigating factor)",
    "has_cdn_detected": "Content Delivery Network detected (mitigating factor)",
    "vt_malicious_count": "Flagged as malicious by VirusTotal engines",
    "abuseipdb_score": "IP abuse confidence score from AbuseIPDB",
    "shodan_vuln_count": "Vulnerabilities reported by Shodan",
}
```

---

## 4. Feature Engineering Module (`feature_engineer.py`)

### 4.1 Extract Features from Asset Data

```python
def extract_features(asset, ports, technologies, vulnerabilities, 
                     ssl_cert, security_headers, dns_records, threat_intel) -> dict:
    """
    Extract the 34-feature vector from collected asset data.
    
    All inputs are ORM model instances or lists of ORM instances.
    Returns dict ready for RiskScorer.predict()
    """
    # --- Port features ---
    CRITICAL_PORTS = {21, 22, 23, 445, 1433, 3306, 3389, 5432, 5900, 27017}
    open_ports = [p for p in ports if p.state == "open"]
    critical_ports = [p for p in open_ports if p.port_number in CRITICAL_PORTS]
    
    features = {
        "num_open_ports": len(open_ports),
        "num_critical_ports": len(critical_ports),
        "has_rdp_exposed": int(any(p.port_number == 3389 for p in open_ports)),
        "has_ssh_exposed": int(any(p.port_number == 22 for p in open_ports)),
        "has_db_exposed": int(any(p.port_number in {3306,5432,1433,27017} for p in open_ports)),
    }
    
    # --- SSL features ---
    if ssl_cert:
        key_score = 1.0
        if ssl_cert.key_size:
            if ssl_cert.key_type == "RSA":
                key_score = min(ssl_cert.key_size / 4096, 1.0)
            else:  # EC
                key_score = min(ssl_cert.key_size / 384, 1.0)
        features.update({
            "ssl_days_until_expiry": ssl_cert.days_until_expiry or 365,
            "ssl_is_expired": int(ssl_cert.is_expired),
            "ssl_is_self_signed": int(ssl_cert.is_self_signed),
            "ssl_has_weak_cipher": int(ssl_cert.has_weak_cipher),
            "ssl_has_weak_protocol": int(ssl_cert.has_weak_protocol),
            "ssl_key_size_score": round(key_score, 3),
        })
    else:
        features.update({
            "ssl_days_until_expiry": 0,
            "ssl_is_expired": 0,
            "ssl_is_self_signed": 0,
            "ssl_has_weak_cipher": 0,
            "ssl_has_weak_protocol": 0,
            "ssl_key_size_score": 0.0,
        })
    
    # --- Header features ---
    present_headers = {h.header_name.lower() for h in security_headers if h.is_present}
    missing = [h for h in security_headers if not h.is_present]
    features.update({
        "num_missing_headers": len(missing),
        "has_csp": int("content-security-policy" in present_headers),
        "has_hsts": int("strict-transport-security" in present_headers),
        "cors_misconfigured": int(any(
            h.header_name.lower() == "access-control-allow-origin" 
            and h.header_value == "*" 
            for h in security_headers if h.is_present
        )),
    })
    
    # --- Vulnerability features ---
    features.update({
        "num_cves": len(vulnerabilities),
        "max_cvss_score": max((v.cvss_score or 0 for v in vulnerabilities), default=0.0),
        "max_epss_score": max((v.epss_score or 0 for v in vulnerabilities), default=0.0),
        "has_cisa_kev": int(any(v.is_on_cisa_kev for v in vulnerabilities)),
        "num_critical_cves": len([v for v in vulnerabilities if (v.cvss_score or 0) >= 9.0]),
    })
    
    # --- Technology features ---
    OUTDATED_KEYWORDS = ["end-of-life", "eol", "deprecated", "unsupported"]
    features.update({
        "num_technologies": len(technologies),
        "has_outdated_tech": int(any(
            t.version and any(k in (t.version or "").lower() for k in OUTDATED_KEYWORDS)
            for t in technologies
        )),
        "has_cms": int(any(t.category == "cms" for t in technologies)),
        "has_exposed_api_docs": int(any(
            t.name.lower() in {"swagger", "openapi", "graphql"} for t in technologies
        )),
    })
    
    # --- DNS features ---
    record_types_present = {r.record_type for r in dns_records}
    txt_records = " ".join(r.record_value for r in dns_records if r.record_type == "TXT")
    features.update({
        "has_spf": int("v=spf1" in txt_records.lower()),
        "has_dkim": int(any(r.record_type == "TXT" and "dkim" in r.record_value.lower() 
                           for r in dns_records)),
        "has_dmarc": int(any(r.record_type == "TXT" and "v=dmarc1" in r.record_value.lower() 
                            for r in dns_records)),
        "has_dangling_cname": int(any(r.is_misconfigured and r.record_type == "CNAME" 
                                      for r in dns_records)),
    })
    
    # --- Infrastructure features ---
    CLOUD_INDICATORS = {"amazonaws.com", "azure", "cloudfront", "googleusercontent", 
                        "cloudflare", "fastly", "akamai", "digitalocean"}
    ip = asset.ip_address or ""
    hostname = asset.hostname or ""
    is_cloud = any(c in hostname.lower() or c in ip for c in CLOUD_INDICATORS)
    
    waf_detected = any(t.name.lower() in {"cloudflare", "aws waf", "akamai", "imperva",
                                            "f5", "modsecurity"} for t in technologies)
    cdn_detected = any(t.name.lower() in {"cloudflare", "cloudfront", "akamai", "fastly",
                                            "azure cdn"} for t in technologies)
    features.update({
        "is_cloud_hosted": int(is_cloud),
        "has_waf_detected": int(waf_detected),
        "has_cdn_detected": int(cdn_detected),
    })
    
    # --- Threat intel features ---
    vt_data = [t for t in threat_intel if t.source == "virustotal"]
    abuse_data = [t for t in threat_intel if t.source == "abuseipdb"]
    shodan_data = [t for t in threat_intel if t.source == "shodan"]
    
    features.update({
        "vt_malicious_count": max(
            (t.data.get("malicious", 0) for t in vt_data), default=0
        ),
        "abuseipdb_score": max(
            (t.data.get("abuseConfidenceScore", 0) for t in abuse_data), default=0
        ),
        "shodan_vuln_count": max(
            (len(t.data.get("vulns", [])) for t in shodan_data), default=0
        ),
    })
    
    return features
```

---

## 5. Report Generation Module (`report_generator.py`)

### 5.1 Template-Based Generation (No API Key Required)

Use Jinja2 templates for guaranteed report generation without LLM dependency.

**Executive Report Template** (`templates/executive_report.md.j2`):
```jinja2
# 🛡️ AEGIS Security Report — {{ scan.target_domain }}

**Generated**: {{ now }}  
**Scan Type**: {{ scan.scan_type | title }}  
**Overall Risk Score**: {{ scan.overall_risk_score | round(1) }}/100 ({{ risk_level | upper }})

---

## Executive Summary

AEGIS performed a {{ scan.scan_type }} security assessment of **{{ scan.target_domain }}** 
and discovered **{{ scan.total_assets }} assets** across the organization's external attack surface.

| Severity | Count |
|---|---|
| 🔴 Critical | {{ scan.critical_findings }} |
| 🟠 High | {{ scan.high_findings }} |
| 🟡 Medium | {{ scan.medium_findings }} |
| 🔵 Low | {{ scan.low_findings }} |

{% if critical_assets %}
## ⚠️ Critical Findings

{% for asset in critical_assets %}
### {{ loop.index }}. {{ asset.hostname }} (Risk: {{ asset.risk_score | round(1) }}/100)

**IP**: {{ asset.ip_address or "N/A" }}  
**Risk Factors**:
{% for factor in asset.risk_factors %}
- {{ factor.impact }} — {{ factor.factor }}
{% endfor %}

{% endfor %}
{% endif %}

## Top Recommendations

{% for rec in recommendations %}
{{ loop.index }}. **{{ rec.title }}** ({{ rec.severity | upper }})
   {{ rec.description }}

{% endfor %}

---

*This report was generated by AEGIS — AI-Powered Attack Surface Management Platform*
```

### 5.2 LLM-Enhanced Generation (With API Key)

If `GEMINI_API_KEY` or equivalent is set, enhance the template output with:

**Prompt Structure**:
```
SYSTEM: You are a senior cybersecurity analyst writing a professional security report.
Write in formal, precise language. Reference specific CVE IDs and scores.
Do NOT hallucinate — only use the data provided below.

SCAN DATA:
{json.dumps(scan_data, indent=2)}

TASK: Generate a {report_type} security report with the following sections:
1. Executive Summary (3-5 sentences)
2. Critical Findings with business impact
3. Risk Analysis
4. Prioritized Remediation Recommendations
5. Conclusion

Format as Markdown. Be specific and actionable.
```

### 5.3 Fallback Logic
```
if LLM_API_KEY exists:
    try:
        report = generate_with_llm(scan_data, report_type)
    except (APIError, Timeout, RateLimit):
        report = generate_with_template(scan_data, report_type)
else:
    report = generate_with_template(scan_data, report_type)
```

---

## 6. Embedded Data

### 6.1 Subdomain Wordlist (Top 500)
Embed directly in `wordlists.py` as a Python list. Include:
```
www, mail, ftp, smtp, pop, imap, webmail, admin, blog, dev, staging,
test, api, app, cdn, cloud, cms, cpanel, dashboard, demo, docs, git,
gitlab, grafana, jenkins, jira, kibana, login, monitor, mysql, ns1,
ns2, office, panel, portal, proxy, rdp, remote, sentry, shop, sso,
status, store, support, vpn, wiki, ...
```

Full 500-word list should be sourced from SecLists or similar.

### 6.2 Favicon Hash Database
Embed in `tech_detector.py` as a Python dict:
```python
FAVICON_HASHES = {
    81586312: {"name": "Jenkins", "category": "ci-cd"},
    -1854810269: {"name": "Grafana", "category": "monitoring"},
    116323821: {"name": "Spring Boot", "category": "framework"},
    -1293291880: {"name": "Apache Tomcat", "category": "web-server"},
    -1184861099: {"name": "Kibana", "category": "monitoring"},
    442749392: {"name": "Jira", "category": "project-management"},
    # ... add 50+ known hashes
}
```

### 6.3 Subdomain Takeover Fingerprints
Embed in `dns_analyzer.py` as defined in PRD section F-RECON-10.

### 6.4 Service Port Mapping
```python
PORT_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios", 143: "imap", 443: "https", 445: "smb",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1723: "pptp",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 8888: "http-alt",
    9090: "http-alt", 9200: "elasticsearch", 27017: "mongodb",
}
```
