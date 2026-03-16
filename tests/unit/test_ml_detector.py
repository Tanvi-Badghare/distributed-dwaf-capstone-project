"""
tests/unit/test_ml_detector.py
Unit tests for the ML detector inference pipeline.

Run:
pytest tests/unit/test_ml_detector.py -v
"""

import sys
from pathlib import Path
import numpy as np
import pandas as pd
import pytest

# Add ml-detector module to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ml-detector"))

from feature_extractor import extract_features_df
from model_loader import load_model


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def model():
    """Load the trained ML model once for all tests."""
    return load_model()


@pytest.fixture
def sample_dataframe():
    """Create small sample HTTP dataset."""
    return pd.DataFrame([
        {
            "method": "GET",
            "url": "/index.jsp",
            "content": "",
            "cookie": "",
            "content_type": "",
            "lenght": 0
        },
        {
            "method": "GET",
            "url": "/search?q=%27+OR+1%3D1",
            "content": "",
            "cookie": "",
            "content_type": "",
            "lenght": 0
        },
        {
            "method": "POST",
            "url": "/login",
            "content": "user=admin&pass=test",
            "cookie": "",
            "content_type": "application/x-www-form-urlencoded",
            "lenght": 24
        }
    ])


# ── Feature extraction pipeline ─────────────────────────────────────────────

def test_feature_extraction_pipeline(sample_dataframe):
    X = extract_features_df(sample_dataframe)

    assert isinstance(X, np.ndarray)
    assert X.shape[0] == len(sample_dataframe)
    assert X.shape[1] == 41


# ── Model loading ───────────────────────────────────────────────────────────

def test_model_loaded(model):
    assert model is not None


# ── Prediction output ───────────────────────────────────────────────────────

def test_prediction_shape(model, sample_dataframe):
    X = extract_features_df(sample_dataframe)
    preds = model.predict(X)

    assert len(preds) == len(sample_dataframe)


def test_prediction_values(model, sample_dataframe):
    X = extract_features_df(sample_dataframe)
    preds = model.predict(X)

    for p in preds:
        assert p in [0, 1]


# ── Probability outputs ─────────────────────────────────────────────────────

def test_prediction_probabilities(model, sample_dataframe):
    X = extract_features_df(sample_dataframe)

    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X)

        for row in probs:
            for p in row:
                assert 0.0 <= p <= 1.0


# ── Attack vs normal detection sanity ───────────────────────────────────────

def test_attack_has_higher_probability(model):
    df = pd.DataFrame([
        {"method":"GET","url":"/index.jsp","content":"","cookie":"","content_type":"","lenght":0},
        {"method":"GET","url":"/search?q=%27+OR+1%3D1--","content":"","cookie":"","content_type":"","lenght":0}
    ])

    X = extract_features_df(df)

    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X)

        normal_prob = probs[0][1]
        attack_prob = probs[1][1]

        assert attack_prob >= normal_prob


# ── Edge cases ──────────────────────────────────────────────────────────────

def test_empty_dataframe(model):
    df = pd.DataFrame(columns=[
        "method","url","content","cookie","content_type","lenght"
    ])

    X = extract_features_df(df)

    assert X.shape[0] == 0


def test_invalid_input_handling(model):
    df = pd.DataFrame([
        {"method":None,"url":None,"content":None,"cookie":None,"content_type":None,"lenght":None}
    ])

    X = extract_features_df(df)

    preds = model.predict(X)

    assert len(preds) == 1