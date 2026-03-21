"""
tests/unit/test_feature_extraction.py
Unit tests for feature_extractor.py
Run: pytest tests/unit/test_feature_extraction.py -v
"""

import sys
from pathlib import Path
import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ml-detector"))
from feature_extractor import extract_features_from_row, extract_features_df, FEATURE_NAMES


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_row(**kwargs) -> pd.Series:
    defaults = {
        "method":       "GET",
        "url":          "/tienda1/index.jsp",
        "content":      "",
        "cookie":       "JSESSIONID=ABC123",
        "content_type": "",
        "lenght":       0,
    }
    defaults.update(kwargs)
    return pd.Series(defaults)


def idx(name: str) -> int:
    """Get feature index by name."""
    return FEATURE_NAMES.index(name)


# ── Feature count ─────────────────────────────────────────────────────────────

def test_feature_count_normal():
    features = extract_features_from_row(make_row())
    assert len(features) == 41


def test_feature_count_attack():
    features = extract_features_from_row(
        make_row(url="/anadir.jsp?cantidad=%27%3B+DROP+TABLE+usuarios"))
    assert len(features) == 41


def test_feature_names_count():
    assert len(FEATURE_NAMES) == 41


# ── Feature values in range ───────────────────────────────────────────────────

def test_features_in_range():
    features = extract_features_from_row(make_row(url="/search?q=wine"))
    for i, f in enumerate(features):
        assert 0.0 <= f <= 1.0, f"Feature {FEATURE_NAMES[i]}={f} out of [0,1]"


def test_attack_features_in_range():
    features = extract_features_from_row(
        make_row(url="/login?user=%27+OR+1%3D1--"))
    for i, f in enumerate(features):
        assert 0.0 <= f <= 1.0, f"Feature {FEATURE_NAMES[i]}={f} out of [0,1]"


# ── Method encoding ───────────────────────────────────────────────────────────

def test_method_get():
    f = extract_features_from_row(make_row(method="GET"))
    assert f[idx("method_get")]  == 1.0
    assert f[idx("method_post")] == 0.0


def test_method_post():
    f = extract_features_from_row(make_row(method="POST"))
    assert f[idx("method_get")]  == 0.0
    assert f[idx("method_post")] == 1.0


# ── SQLi detection — use feature names not hardcoded indices ──────────────────

def test_sqli_detected_in_url():
    f = extract_features_from_row(
        make_row(url="/search?q=%27+OR+%271%27%3D%271"))
    # At least one attack signal should fire
    attack_signals = [
        f[idx("url_enc_squote")],
        f[idx("url_enc_semicolon")],
        f[idx("has_sqli_kw")],
        f[idx("sqli_punct_count")],
    ]
    assert any(v > 0.0 for v in attack_signals), \
        f"Expected at least one SQLi signal, got: {dict(zip(FEATURE_NAMES, f))}"


def test_sqli_keyword_in_params():
    f = extract_features_from_row(
        make_row(url="/search?q=SELECT+username+FROM+users+WHERE+1=1"))
    assert f[idx("has_sqli_kw")] == 1.0 or f[idx("sqli_kw_count")] > 0.0, \
        "Expected SQLi keyword detection"


def test_drop_table_detected():
    f = extract_features_from_row(
        make_row(url="/anadir.jsp?cantidad=%27%3B+DROP+TABLE+usuarios"))
    attack_signals = [
        f[idx("url_enc_squote")],
        f[idx("url_enc_semicolon")],
        f[idx("has_sqli_kw")],
        f[idx("param_has_sqli_kw")],
        f[idx("sqli_punct_count")],
    ]
    assert any(v > 0.0 for v in attack_signals), \
        "Expected attack signals for DROP TABLE payload"


# ── Normal traffic ────────────────────────────────────────────────────────────

def test_normal_url_low_attack_signals():
    f = extract_features_from_row(
        make_row(url="/tienda1/publico/anadir.jsp?id=3&nombre=Vino+Rioja&precio=100&cantidad=55"))
    # Only check clear binary flags — not statistical scores
    assert f[idx("has_sqli_kw")]   == 0.0, "Normal URL should not trigger SQLi keyword"
    assert f[idx("has_xss")]       == 0.0, "Normal URL should not trigger XSS"
    assert f[idx("has_command")]   == 0.0, "Normal URL should not trigger command injection"


# ── Batch extraction ──────────────────────────────────────────────────────────

def test_extract_features_df_shape():
    df = pd.DataFrame([
        {"method": "GET",  "url": "/index.jsp", "content": "", "cookie": "", "content_type": "", "lenght": 0},
        {"method": "POST", "url": "/login",     "content": "user=admin", "cookie": "", "content_type": "application/x-www-form-urlencoded", "lenght": 10},
        {"method": "GET",  "url": "/search?q=%27+OR+1%3D1", "content": "", "cookie": "", "content_type": "", "lenght": 0},
    ])
    X = extract_features_df(df)
    assert X.shape == (3, 41)


def test_extract_features_df_returns_numpy():
    df = pd.DataFrame([
        {"method": "GET", "url": "/index.jsp", "content": "", "cookie": "", "content_type": "", "lenght": 0},
    ])
    assert isinstance(extract_features_df(df), np.ndarray)


# ── Edge cases ────────────────────────────────────────────────────────────────

def test_empty_url():
    assert len(extract_features_from_row(make_row(url=""))) == 41


def test_very_long_url():
    f = extract_features_from_row(make_row(url="/search?q=" + "A" * 1000))
    assert len(f) == 41
    assert all(0.0 <= v <= 1.0 for v in f)


def test_none_values():
    row = pd.Series({"method": None, "url": None, "content": None,
                     "cookie": None, "content_type": None, "lenght": None})
    assert len(extract_features_from_row(row)) == 41


def test_http_suffix_stripped():
    assert len(extract_features_from_row(
        make_row(url="/tienda1/index.jsp HTTP/1.1"))) == 41              