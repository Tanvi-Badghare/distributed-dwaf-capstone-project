"""
tests/unit/test_feature_extraction.py

Unit tests for ml-detector/feature_extractor.py

Run locally:
    pytest tests/unit/test_feature_extraction.py -v

Run inside container:
    docker exec -it dwaf-ml-detector pytest -v
"""

import sys
from pathlib import Path
import numpy as np
import pandas as pd
import pytest

# Ensure ml-detector module is importable
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "ml-detector"))

from feature_extractor import (
    extract_features_from_row,
    extract_features_df,
    FEATURE_NAMES,
)

EXPECTED_FEATURE_COUNT = 41


# ── Fixtures ──────────────────────────────────────────────────────────────

def make_row(**kwargs) -> pd.Series:
    """Create a synthetic HTTP request row."""
    defaults = {
        "method": "GET",
        "url": "/tienda1/index.jsp",
        "content": "",
        "cookie": "JSESSIONID=ABC123",
        "content_type": "",
        "length": 0,
    }
    defaults.update(kwargs)
    return pd.Series(defaults)


# ── Feature count tests ───────────────────────────────────────────────────

def test_feature_count_normal():
    row = make_row()
    features = extract_features_from_row(row)
    assert len(features) == EXPECTED_FEATURE_COUNT


def test_feature_count_attack():
    row = make_row(url="/anadir.jsp?id=2&cantidad=%27%3B+DROP+TABLE+usuarios")
    features = extract_features_from_row(row)
    assert len(features) == EXPECTED_FEATURE_COUNT


def test_feature_names_count():
    assert len(FEATURE_NAMES) == EXPECTED_FEATURE_COUNT


# ── Feature range tests ───────────────────────────────────────────────────

def test_features_in_range():
    row = make_row(url="/search?q=wine&category=food")
    features = extract_features_from_row(row)

    for i, f in enumerate(features):
        assert 0.0 <= f <= 1.0, f"{FEATURE_NAMES[i]} out of range"


def test_attack_features_in_range():
    row = make_row(url="/login?user=%27+OR+1%3D1--&pwd=x")
    features = extract_features_from_row(row)

    for i, f in enumerate(features):
        assert 0.0 <= f <= 1.0, f"{FEATURE_NAMES[i]} out of range"


# ── HTTP method encoding ──────────────────────────────────────────────────

def test_method_get():
    row = make_row(method="GET")
    f = extract_features_from_row(row)

    assert f[0] == 1.0  # method_get
    assert f[1] == 0.0  # method_post


def test_method_post():
    row = make_row(method="POST")
    f = extract_features_from_row(row)

    assert f[0] == 0.0
    assert f[1] == 1.0


# ── SQL injection signals ─────────────────────────────────────────────────

def test_sqli_encoded_quote_detected():
    row = make_row(url="/search?q=%27+OR+%271%27%3D%271")
    f = extract_features_from_row(row)

    assert max(f) > 0


def test_sqli_keyword_detected():
    row = make_row(url="/search?q=SELECT+*+FROM+users")
    f = extract_features_from_row(row)

    assert max(f) > 0


def test_drop_table_detected():
    row = make_row(url="/anadir.jsp?cantidad=%27%3B+DROP+TABLE+usuarios")
    f = extract_features_from_row(row)

    assert max(f) > 0


# ── Normal traffic behaviour ──────────────────────────────────────────────

def test_normal_url_low_attack_signals():
    row = make_row(
        url="/tienda1/publico/anadir.jsp?id=3&nombre=Vino+Rioja&precio=100&cantidad=55"
    )

    f = extract_features_from_row(row)

    attack_flags = f[20:25]
    assert sum(attack_flags) == 0.0


# ── Batch feature extraction ──────────────────────────────────────────────

def test_extract_features_df_shape():
    df = pd.DataFrame(
        [
            {
                "method": "GET",
                "url": "/index.jsp",
                "content": "",
                "cookie": "",
                "content_type": "",
                "length": 0,
            },
            {
                "method": "POST",
                "url": "/login",
                "content": "user=admin&pass=x",
                "cookie": "",
                "content_type": "application/x-www-form-urlencoded",
                "length": 20,
            },
            {
                "method": "GET",
                "url": "/search?q=%27+OR+1%3D1",
                "content": "",
                "cookie": "",
                "content_type": "",
                "length": 0,
            },
        ]
    )

    X = extract_features_df(df)

    assert X.shape == (3, EXPECTED_FEATURE_COUNT)


def test_extract_features_df_returns_numpy():
    df = pd.DataFrame(
        [
            {
                "method": "GET",
                "url": "/index.jsp",
                "content": "",
                "cookie": "",
                "content_type": "",
                "length": 0,
            }
        ]
    )

    X = extract_features_df(df)
    assert isinstance(X, np.ndarray)


# ── Edge cases ────────────────────────────────────────────────────────────

def test_empty_url():
    row = make_row(url="")
    features = extract_features_from_row(row)

    assert len(features) == EXPECTED_FEATURE_COUNT


def test_very_long_url():
    long_url = "/search?q=" + "A" * 1000
    row = make_row(url=long_url)

    features = extract_features_from_row(row)

    assert len(features) == EXPECTED_FEATURE_COUNT

    for f in features:
        assert 0.0 <= f <= 1.0


def test_none_values():
    row = pd.Series(
        {
            "method": None,
            "url": None,
            "content": None,
            "cookie": None,
            "content_type": None,
            "length": None,
        }
    )

    features = extract_features_from_row(row)
    assert len(features) == EXPECTED_FEATURE_COUNT


def test_http_suffix_stripped():
    row = make_row(url="/tienda1/index.jsp HTTP/1.1")

    features = extract_features_from_row(row)

    assert len(features) == EXPECTED_FEATURE_COUNT