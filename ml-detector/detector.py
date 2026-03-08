"""
HTTP Detector — loads hybrid RF + TF-IDF models and classifies requests.
"""

import joblib
import numpy as np
from pathlib import Path
from scipy.sparse import hstack, csr_matrix

from feature_extractor import extract_features_from_row, FEATURE_NAMES

import pandas as pd

MODELS_DIR = Path(__file__).parent / "models"


def _build_payload_text(request: dict) -> str:
    url  = str(request.get("url",     "") or "")
    body = str(request.get("content", "") or "")
    for sfx in [" HTTP/1.1", " HTTP/1.0", " HTTP/2"]:
        url = url.replace(sfx, "")
    text = (url + " " + body) \
        .replace("&", " ").replace("=", " ").replace("+", " ") \
        .replace("?", " ").replace("/", " ") \
        .replace("%27", " SQLI_QUOTE ") \
        .replace("%3B", " SQLI_SEMI ").replace("%3b", " SQLI_SEMI ") \
        .replace("%2F", " ENC_SLASH ").replace("%2f", " ENC_SLASH ") \
        .replace("%3C", " XSS_LT ").replace("%3c", " XSS_LT ") \
        .replace("%3E", " XSS_GT ").replace("%3e", " XSS_GT ") \
        .replace("%00", " NULL_BYTE ") \
        .replace("--",  " SQLI_COMMENT ") \
        .replace("/*",  " SQLI_COMMENT ")
    return text.lower()


class HTTPDetector:

    def __init__(self):
        self.scaler    = joblib.load(MODELS_DIR / "scaler.pkl")
        self.tfidf     = joblib.load(MODELS_DIR / "tfidf.pkl")
        self.rf        = joblib.load(MODELS_DIR / "random_forest.pkl")
        self.iso       = joblib.load(MODELS_DIR / "isolation_forest.pkl")
        self.threshold = float(joblib.load(MODELS_DIR / "threshold.pkl"))

    def predict(self, request: dict) -> dict:
        # Hand-crafted features
        row      = pd.Series(request)
        hc_feat  = np.array(extract_features_from_row(row)).reshape(1, -1)
        hc_scaled = self.scaler.transform(hc_feat)

        # TF-IDF features
        text      = _build_payload_text(request)
        tfidf_vec = self.tfidf.transform([text])

        # Combined
        X_combined = hstack([csr_matrix(hc_scaled), tfidf_vec])

        # RF prediction
        rf_proba       = float(self.rf.predict_proba(X_combined)[0, 1])
        classification = "malicious" if rf_proba >= self.threshold else "benign"

        # Isolation Forest (on hand-crafted only)
        iso_flag = int(self.iso.predict(hc_scaled)[0] == -1)

        # Ensemble threat score
        threat_score = round(0.85 * rf_proba + 0.15 * iso_flag, 4)

        return {
            "classification":  classification,
            "threat_score":    threat_score,
            "rf_confidence":   round(rf_proba, 4),
            "iso_flag":        iso_flag,
            "features":        hc_feat[0].tolist(),
            "latency_ms":      0.0,
        }