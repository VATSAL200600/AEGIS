"""AEGIS AI/ML Engine — Risk Engine Coordinator

Loads the trained XGBoost model and SHAP explainer, performs inference,
classifies risk tiers, and generates full explainability dossiers.
"""
import logging
import pickle
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
import numpy as np
import xgboost as xgb
import shap

from app.config import settings
from app.ai.features import FEATURE_NAMES
from app.ai.feature_extractor import FeatureExtractor
from app.ai.shap_explainer import SHAPExplainer

logger = logging.getLogger("aegis.ai.engine")


class RiskEngine:
    """Production ML Risk Engine powered by XGBoost and SHAP."""

    def __init__(
        self,
        model_path: Optional[str] = None,
        explainer_path: Optional[str] = None,
        auto_init: bool = True
    ):
        self.model_path = Path(model_path or settings.RISK_MODEL_PATH)
        self.explainer_path = Path(explainer_path or settings.EXPLAINER_PATH)
        self.model: Optional[xgb.XGBRegressor] = None
        self.explainer: Optional[SHAPExplainer] = None

        if auto_init:
            self.load_or_train()

    def classify_risk_level(self, score: float) -> str:
        """Map a 0-100 continuous score to standard severity tiers."""
        if score >= 80.0:
            return "critical"
        if score >= 60.0:
            return "high"
        if score >= 40.0:
            return "medium"
        if score >= 20.0:
            return "low"
        return "info"

    def load_or_train(self):
        """Loads serialized model and explainer, or triggers training if absent."""
        if self.model_path.exists() and self.explainer_path.exists():
            try:
                # Load XGBoost Regressor
                model = xgb.XGBRegressor()
                model.load_model(str(self.model_path))
                self.model = model

                # Load SHAP Explainer
                with open(self.explainer_path, "rb") as f:
                    tree_explainer = pickle.load(f)
                    self.explainer = SHAPExplainer(tree_explainer)

                logger.info("Loaded pre-trained XGBoost risk model and SHAP explainer from disk")
                return
            except Exception as e:
                logger.warning(f"Failed to load existing model files: {e}. Re-training model...")

        # If model does not exist or failed to load, train on the fly
        self.train_and_save()

    def train_and_save(self, n_samples: int = 5000) -> Dict[str, float]:
        """Trains model on synthetic data and persists artifacts to disk."""
        from app.ai.data_generator import generate_training_data
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import mean_squared_error, r2_score, mean_absolute_error

        logger.info(f"Generating {n_samples} calibrated synthetic samples for risk model training...")
        X, y = generate_training_data(n_samples=n_samples)

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        model = xgb.XGBRegressor(
            n_estimators=150,
            max_depth=5,
            learning_rate=0.08,
            subsample=0.85,
            colsample_bytree=0.85,
            random_state=42,
            n_jobs=-1
        )

        model.fit(X_train, y_train)

        # Evaluate performance
        y_pred = model.predict(X_test)
        rmse = float(np.sqrt(mean_squared_error(y_test, y_pred)))
        mae = float(mean_absolute_error(y_test, y_pred))
        r2 = float(r2_score(y_test, y_pred))

        logger.info(f"Model Training Results: RMSE={rmse:.2f}, MAE={mae:.2f}, R2={r2:.4f}")

        # Create output directories if needed
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        self.explainer_path.parent.mkdir(parents=True, exist_ok=True)

        # Save XGBoost model
        model.save_model(str(self.model_path))

        # Create and save TreeSHAP explainer
        tree_explainer = shap.TreeExplainer(model)
        with open(self.explainer_path, "wb") as f:
            pickle.dump(tree_explainer, f)

        self.model = model
        self.explainer = SHAPExplainer(tree_explainer)

        return {"rmse": rmse, "mae": mae, "r2": r2}

    def predict(self, feature_vector: np.ndarray) -> Tuple[float, str]:
        """
        Runs model inference on a 30-feature vector.
        Returns (risk_score, risk_level).
        """
        if self.model is None:
            self.load_or_train()

        X = feature_vector.reshape(1, -1)
        pred = float(self.model.predict(X)[0])
        score = float(np.clip(pred, 0.0, 100.0))
        level = self.classify_risk_level(score)
        return round(score, 1), level

    def score_asset(self, asset_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        End-to-end asset scoring:
        1. Extract 30 features
        2. Predict risk score and severity level
        3. Compute SHAP explainability breakdown
        """
        feat_vector = FeatureExtractor.extract_from_dict(asset_dict)
        feat_dict = FeatureExtractor.extract_feature_dict(asset_dict)

        score, level = self.predict(feat_vector)

        shap_report = {}
        if self.explainer:
            shap_report = self.explainer.explain_asset(feat_vector, score)

        return {
            "risk_score": score,
            "risk_level": level,
            "features": feat_dict,
            "shap_explanation": shap_report
        }


# Global singleton instance
risk_engine = RiskEngine(auto_init=False)
