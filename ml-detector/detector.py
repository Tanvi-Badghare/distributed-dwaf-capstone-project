"""
ML HTTP Detector
Loads trained models and classifies HTTP requests using
Random Forest + Isolation Forest ensemble.
"""

import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, List

from feature_extractor import extract_features_from_row


MODELS_DIR = Path(__file__).parent / "models"


class HTTPDetector:
    """
    ML-based HTTP anomaly detector.
    """

    def __init__(self):

        self._check_models()

        self.scaler = joblib.load(MODELS_DIR / "scaler.pkl")
        self.rf     = joblib.load(MODELS_DIR / "random_forest.pkl")
        self.iso    = joblib.load(MODELS_DIR / "isolation_forest.pkl")

        print("✅ ML models loaded successfully")

    def _check_models(self):
        required = [
            "scaler.pkl",
            "random_forest.pkl",
            "isolation_forest.pkl"
        ]

        for m in required:
            path = MODELS_DIR / m
            if not path.exists():
                raise FileNotFoundError(
                    f"Missing model file: {path}. Run training/train.py first."
                )

    # ─────────────────────────────────────────
    # Single request prediction
    # ─────────────────────────────────────────

    def predict(self, request: Dict) -> Dict:
        """
        Classify a single HTTP request.

        Expected request fields:
            method, url, content_type, cookie,
            length, content, user_agent
        """

        row = pd.Series(request)

        features = extract_features_from_row(row)

        X = np.array(features).reshape(1, -1)

        X_scaled = self.scaler.transform(X)

        # Random Forest
        rf_pred  = int(self.rf.predict(X_scaled)[0])
        rf_prob  = float(self.rf.predict_proba(X_scaled)[0][1])

        # Isolation Forest
        iso_pred = self.iso.predict(X_scaled)[0]
        iso_flag = 1 if iso_pred == -1 else 0

        # Ensemble threat score
        threat_score = 0.8 * rf_prob + 0.2 * iso_flag

        classification = (
            "malicious" if threat_score >= 0.5 else "benign"
        )

        return {
            "classification": classification,
            "threat_score": round(threat_score, 4),
            "rf_probability": round(rf_prob, 4),
            "iso_flag": iso_flag,
            "features": [round(f, 6) for f in features]
        }

    # ─────────────────────────────────────────
    # Batch prediction
    # ─────────────────────────────────────────

    def predict_batch(self, requests: List[Dict]) -> List[Dict]:
        """
        Predict multiple HTTP requests.
        """

        results = []

        for req in requests:
            results.append(self.predict(req))

        return results

    # ─────────────────────────────────────────
    # Debug info
    # ─────────────────────────────────────────

    def info(self) -> Dict:
        """
        Return detector metadata.
        """

        return {
            "model": "RandomForest + IsolationForest",
            "ensemble_weights": {"rf": 0.8, "iso": 0.2},
            "feature_count": 41,
        }
