"""AEGIS — Model Training CLI Script

Generates calibrated synthetic dataset, trains the XGBoost Risk Regression Model,
fits the TreeSHAP explainer, evaluates validation metrics, and serializes artifacts.

Usage:
    python train_model.py
"""
import sys
import time
from pathlib import Path

# Add backend directory to path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from app.ai.risk_engine import RiskEngine
from app.config import settings


def main():
    print("=" * 65)
    print(" [AEGIS] AI RISK ENGINE MODEL TRAINING PIPELINE")
    print("=" * 65)

    start_time = time.time()
    engine = RiskEngine(auto_init=False)

    print("\n[+] Generating 5,000 synthetic security profiles across 30 features...")
    print("    - Profiles: Critical (10%), High (20%), Medium (30%), Low (25%), Info (15%)")
    print("    - Ground Truth: Calibrated against CVSS v3.1, EPSS, CISA KEV & CIS benchmarks")

    metrics = engine.train_and_save(n_samples=5000)

    elapsed = time.time() - start_time

    print("\n" + "=" * 65)
    print(" [*] MODEL PERFORMANCE & VALIDATION METRICS (80/20 Holdout)")
    print("=" * 65)
    print(f" * R2 Score (Coefficient of Determination) : {metrics['r2']:.4f}  (Target: > 0.95)")
    print(f" * Root Mean Squared Error (RMSE)          : {metrics['rmse']:.2f} pts (Target: < 5.0)")
    print(f" * Mean Absolute Error (MAE)               : {metrics['mae']:.2f} pts")
    print(f" * Training & Serialization Time           : {elapsed:.2f}s")
    print("-" * 65)
    print(f" * Saved XGBoost Model Artifact            : {settings.RISK_MODEL_PATH}")
    print(f" * Saved TreeSHAP Explainer Artifact       : {settings.EXPLAINER_PATH}")
    print("=" * 65)

    # Sanity inference test
    test_asset = {
        "hostname": "dev-vpn.example.com",
        "ports": [
            {"port_number": 3389, "is_critical": True},
            {"port_number": 80, "is_critical": False}
        ],
        "ssl_cert": {"is_expired": True, "expires_in_days": -14},
        "vulnerabilities": [
            {"cve_id": "CVE-2021-44228", "cvss_score": 10.0, "epss_score": 0.97, "is_cisa_kev": True, "severity": "critical"}
        ],
        "security_headers": {"grade": "F", "score": 15, "hsts": False, "csp": False, "cors_misconfigured": True}
    }

    res = engine.score_asset(test_asset)
    print("\n[OK] Sanity Check Verification on Sample Critical Asset:")
    print(f"    - Predicted Risk Score : {res['risk_score']} / 100 ({res['risk_level'].upper()})")
    print(f"    - SHAP Summary         : {res['shap_explanation']['summary']}")
    print(f"    - Top 3 Risk Drivers   :")
    for d in res['shap_explanation']['top_drivers'][:3]:
        print(f"      * {d['label']}: +{d['impact']} pts ({d['description']})")

    print("\n[OK] Phase 4 Model Training Pipeline Completed Successfully!\n")


if __name__ == "__main__":
    main()
