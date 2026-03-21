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


# ── Fixtures ──────────────────────────────────────────────────────────────────

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


# ── Feature count ─────────────────────────────────────────────────────────────

def test_feature_count_normal():
    row = make_row()
    features = extract_features_from_row(row)
    assert len(features) == 41, f"Expected 41 features, got {len(features)}"


def test_feature_count_attack():
    row = make_row(url="/anadir.jsp?id=2&cantidad=%27%3B+DROP+TABLE+usuarios")
    features = extract_features_from_row(row)
    assert len(features) == 41


def test_feature_names_count():
    assert len(FEATURE_NAMES) == 41


# ── Feature values in range ───────────────────────────────────────────────────

def test_features_in_range():
    row = make_row(url="/search?q=wine&category=food")
    features = extract_features_from_row(row)
    for i, f in enumerate(features):
        assert 0.0 <= f <= 1.0, f"Feature {FEATURE_NAMES[i]} = {f} out of [0,1]"


def test_attack_features_in_range():
    row = make_row(url="/login?user=%27+OR+1%3D1--&pwd=x")
    features = extract_features_from_row(row)
    for i, f in enumerate(features):
        assert 0.0 <= f <= 1.0, f"Feature {FEATURE_NAMES[i]} = {f} out of [0,1]"


# ── Method encoding ───────────────────────────────────────────────────────────

def test_method_get():
    row = make_row(method="GET")
    f = extract_features_from_row(row)
    assert f[0] == 1.0  # method_get
    assert f[1] == 0.0  # method_post

def test_method_post():
    row = make_row(method="POST")
    f = extract_features_from_row(row)
    assert f[0] == 0.0  # method_get
    assert f[1] == 1.0  # method_post


# ── SQLi detection ────────────────────────────────────────────────────────────

def test_sqli_detected_in_url():
    row = make_row(url="/search?q=%27+OR+%271%27%3D%271")
    f = extract_features_from_row(row)
    # enc_quotes_in_url (index 10) should be > 0
    assert f[10] > 0.0, "Expected encoded quote detection"

def test_sqli_keyword_in_params():
    row = make_row(url="/search?q=SELECT+*+FROM+users")
    f = extract_features_from_row(row)
    # has_sqli_kw (index 20) should be 1
    assert f[20] == 1.0, "Expected SQLi keyword flag"

def test_drop_table_detected():
    row = make_row(url="/anadir.jsp?cantidad=%27%3B+DROP+TABLE+usuarios")
    f = extract_features_from_row(row)
    assert f[10] > 0.0 or f[11] > 0.0 or f[20] == 1.0, \
        "Expected attack signals for DROP TABLE payload"


# ── Normal traffic produces low attack scores ─────────────────────────────────

def test_normal_url_low_attack_signals():
    row = make_row(url="/tienda1/publico/anadir.jsp?id=3&nombre=Vino+Rioja&precio=100&cantidad=55")
    f = extract_features_from_row(row)
    # Binary attack flags: has_sqli_kw(20), has_xss(22), has_traversal(23), has_command(24)
    # Note: some statistical features may be non-zero for normal URLs
    assert f[20] == 0.0, "Normal URL should not trigger SQLi keyword flag"
    assert f[22] == 0.0, "Normal URL should not trigger XSS flag"
    assert f[23] == 0.0, "Normal URL should not trigger traversal flag"
    assert f[24] == 0.0, "Normal URL should not trigger command flag"


# ── Batch extraction ──────────────────────────────────────────────────────────

def test_extract_features_df_shape():
    df = pd.DataFrame([
        {"method": "GET",  "url": "/index.jsp",          "content": "", "cookie": "", "content_type": "", "lenght": 0},
        {"method": "POST", "url": "/login",               "content": "user=admin&pass=x", "cookie": "", "content_type": "application/x-www-form-urlencoded", "lenght": 20},
        {"method": "GET",  "url": "/search?q=%27+OR+1%3D1", "content": "", "cookie": "", "content_type": "", "lenght": 0},
    ])
    X = extract_features_df(df)
    assert X.shape == (3, 41), f"Expected (3, 41), got {X.shape}"


def test_extract_features_df_returns_numpy():
    df = pd.DataFrame([
        {"method": "GET", "url": "/index.jsp", "content": "", "cookie": "", "content_type": "", "lenght": 0},
    ])
    X = extract_features_df(df)
    assert isinstance(X, np.ndarray)


# ── Edge cases ────────────────────────────────────────────────────────────────

def test_empty_url():
    row = make_row(url="")
    features = extract_features_from_row(row)
    assert len(features) == 41

def test_very_long_url():
    long_url = "/search?q=" + "A" * 1000
    row = make_row(url=long_url)
    features = extract_features_from_row(row)
    assert len(features) == 41
    for f in features:
        assert 0.0 <= f <= 1.0

def test_none_values():
    row = pd.Series({"method": None, "url": None, "content": None,
                     "cookie": None, "content_type": None, "lenght": None})
    features = extract_features_from_row(row)
    assert len(features) == 41

def test_http_suffix_stripped():
    row = make_row(url="/tienda1/index.jsp HTTP/1.1")
    features = extract_features_from_row(row)
    assert len(features) == 41