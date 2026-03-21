"""
tests/unit/test_ml_detector.py
Unit tests for detector.py — requires trained models in ml-detector/models/
Run: pytest tests/unit/test_ml_detector.py -v
"""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ml-detector"))

# Skip all tests if models not trained yet
models_dir = Path(__file__).parent.parent.parent / "ml-detector" / "models"
models_exist = all([
    (models_dir / "random_forest.pkl").exists(),
    (models_dir / "scaler.pkl").exists(),
    (models_dir / "tfidf.pkl").exists(),
    (models_dir / "threshold.pkl").exists(),
])

pytestmark = pytest.mark.skipif(
    not models_exist,
    reason="Models not trained yet — run: python training/train.py"
)

from detector import HTTPDetector


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def detector():
    return HTTPDetector()


def normal_request():
    return {
        "method":       "GET",
        "url":          "/tienda1/publico/anadir.jsp?id=3&nombre=Vino+Rioja&precio=100&cantidad=55",
        "user_agent":   "Mozilla/5.0",
        "content_type": "",
        "cookie":       "JSESSIONID=ABC123",
        "length":       0,
        "content":      "",
        "host":         "localhost:8080",
    }


def sqli_request():
    return {
        "method":       "GET",
        "url":          "/anadir.jsp?id=2&cantidad=%27%3B+DROP+TABLE+usuarios%3B+SELECT+*+FROM+datos",
        "user_agent":   "Mozilla/5.0",
        "content_type": "",
        "cookie":       "JSESSIONID=XYZ789",
        "length":       0,
        "content":      "",
        "host":         "localhost:8080",
    }


def xss_request():
    return {
        "method":       "GET",
        "url":          "/search?q=<script>alert('xss')</script>",
        "user_agent":   "Mozilla/5.0",
        "content_type": "",
        "cookie":       "",
        "length":       0,
        "content":      "",
        "host":         "localhost:8080",
    }


# ── Detector initialisation ───────────────────────────────────────────────────

def test_detector_loads(detector):
    assert detector is not None
    assert detector.rf is not None
    assert detector.scaler is not None
    assert detector.tfidf is not None
    assert 0.0 < detector.threshold < 1.0


# ── Response structure ────────────────────────────────────────────────────────

def test_predict_returns_required_fields(detector):
    result = detector.predict(normal_request())
    assert "classification" in result
    assert "threat_score"   in result
    assert "rf_confidence"  in result
    assert "iso_flag"       in result
    assert "features"       in result
    assert "latency_ms"     in result


def test_classification_is_valid_string(detector):
    result = detector.predict(normal_request())
    assert result["classification"] in ("malicious", "benign")


def test_threat_score_in_range(detector):
    result = detector.predict(normal_request())
    assert 0.0 <= result["threat_score"] <= 1.0


def test_rf_confidence_in_range(detector):
    result = detector.predict(normal_request())
    assert 0.0 <= result["rf_confidence"] <= 1.0


def test_iso_flag_is_binary(detector):
    result = detector.predict(normal_request())
    assert result["iso_flag"] in (0, 1)


def test_features_length(detector):
    result = detector.predict(normal_request())
    assert len(result["features"]) == 41


# ── Classification correctness ────────────────────────────────────────────────

def test_sqli_detected_as_malicious(detector):
    result = detector.predict(sqli_request())
    assert result["classification"] == "malicious", \
        f"SQLi should be malicious, got {result['classification']} (score={result['threat_score']:.3f})"


def test_sqli_high_threat_score(detector):
    result = detector.predict(sqli_request())
    assert result["threat_score"] >= 0.5, \
        f"SQLi threat score too low: {result['threat_score']:.3f}"


def test_normal_low_threat_score(detector):
    result = detector.predict(normal_request())
    assert result["threat_score"] < 0.7, \
        f"Normal request threat score too high: {result['threat_score']:.3f}"


def test_xss_detected(detector):
    result = detector.predict(xss_request())
    # XSS should have elevated threat score
    assert result["threat_score"] > 0.3, \
        f"XSS threat score too low: {result['threat_score']:.3f}"


# ── Edge cases ────────────────────────────────────────────────────────────────

def test_empty_content(detector):
    req = normal_request()
    req["content"] = ""
    result = detector.predict(req)
    assert result["classification"] in ("malicious", "benign")


def test_post_sqli_body(detector):
    req = {
        "method":       "POST",
        "url":          "/anadir.jsp",
        "user_agent":   "Mozilla/5.0",
        "content_type": "application/x-www-form-urlencoded",
        "cookie":       "JSESSIONID=ABC",
        "length":       146,
        "content":      "id=2&cantidad=%27%3B+DROP+TABLE+usuarios%3B+SELECT+*+FROM+datos",
        "host":         "localhost:8080",
    }
    result = detector.predict(req)
    assert result["classification"] == "malicious"


def test_missing_optional_fields(detector):
    req = {"method": "GET", "url": "/index.jsp"}
    result = detector.predict(req)
    assert result["classification"] in ("malicious", "benign")