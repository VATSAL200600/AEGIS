"""AEGIS AI/ML Engine — SHAP Explainability Engine

Computes exact Shapley Additive exPlanations (SHAP) for asset risk scores,
deconstructing predictions into positive risk drivers and mitigating factors.
"""
import logging
from typing import Dict, Any, List, Optional
import numpy as np
import shap
from app.ai.features import FEATURE_NAMES, FEATURE_METADATA

logger = logging.getLogger("aegis.ai.shap")


class SHAPExplainer:
    """Explains XGBoost risk predictions using TreeSHAP."""

    def __init__(self, explainer: Optional[shap.TreeExplainer] = None):
        self.explainer = explainer

    def explain_asset(self, feature_vector: np.ndarray, predicted_score: float) -> Dict[str, Any]:
        """
        Calculates SHAP feature contributions for a single 1D feature array (shape: 30,).
        Returns structured explanation dictionary with drivers, mitigations, and natural language text.
        """
        if self.explainer is None:
            return {
                "base_value": 45.0,
                "top_drivers": [],
                "top_mitigations": [],
                "summary": f"Risk score assessed at {predicted_score:.1f}/100 based on standard heuristics."
            }

        # Shape to (1, 30) for SHAP
        X = feature_vector.reshape(1, -1)
        shap_values = self.explainer.shap_values(X)

        # Handle 1D or 2D array output
        vals = shap_values[0] if len(shap_values.shape) > 1 else shap_values

        base_val = float(self.explainer.expected_value) if hasattr(self.explainer, "expected_value") else 40.0
        if isinstance(base_val, (list, np.ndarray)):
            base_val = float(base_val[0])

        contributions: List[Dict[str, Any]] = []

        for i, name in enumerate(FEATURE_NAMES):
            val = float(feature_vector[i])
            impact = float(vals[i])
            meta = FEATURE_METADATA.get(name, {"label": name, "high_risk_desc": name, "low_risk_desc": name})

            # Format human explanation
            if impact > 0:
                try:
                    desc = meta["high_risk_desc"].format(val=val)
                except Exception:
                    desc = meta["high_risk_desc"]
            else:
                try:
                    desc = meta["low_risk_desc"].format(val=val)
                except Exception:
                    desc = meta["low_risk_desc"]

            contributions.append({
                "feature": name,
                "label": meta["label"],
                "value": val,
                "impact": round(impact, 2),
                "direction": "increase" if impact > 0 else "decrease",
                "description": desc
            })

        # Sort by absolute impact
        contributions.sort(key=lambda x: abs(x["impact"]), reverse=True)

        top_drivers = [c for c in contributions if c["impact"] > 0.5][:5]
        top_mitigations = [c for c in contributions if c["impact"] < -0.5][:5]

        # Natural language summary
        summary_sentences = []
        if top_drivers:
            driver_phrases = [f"{d['label']} (+{d['impact']:.1f} pts)" for d in top_drivers[:3]]
            summary_sentences.append(f"Primary risk drivers: {', '.join(driver_phrases)}.")

        if top_mitigations:
            mit_phrases = [f"{m['label']} ({m['impact']:.1f} pts)" for m in top_mitigations[:2]]
            summary_sentences.append(f"Mitigating factors: {', '.join(mit_phrases)}.")

        if not summary_sentences:
            summary_sentences.append("Asset exhibits nominal external risk indicators.")

        return {
            "base_value": round(base_val, 2),
            "predicted_score": round(predicted_score, 2),
            "top_drivers": top_drivers,
            "top_mitigations": top_mitigations,
            "all_contributions": contributions,
            "summary": " ".join(summary_sentences)
        }
