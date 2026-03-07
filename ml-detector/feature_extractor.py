"""
Feature Extractor for CSIC 2010 CSV Dataset
Extracts 41 numerical features from HTTP request fields.
"""

import re
import math
import numpy as np
import pandas as pd
from typing import List
from urllib.parse import urlparse, parse_qs, unquote


# ── Attack patterns ─────────────────────────────────────────

SQLI = re.compile(
    r"\bOR\b|\bAND\b|--|;|UNION|SELECT|INSERT|DROP|DELETE|UPDATE|"
    r"EXEC|CAST|CONVERT|CHAR|VARCHAR|ALTER|CREATE|FROM|WHERE",
    re.IGNORECASE
)

XSS = re.compile(
    r"<script|</script|javascript:|onerror=|onload=|onclick=|"
    r"<img|<iframe|alert\(|document\.cookie",
    re.IGNORECASE
)

TRAVERSAL = re.compile(
    r"\.\./|\.\.\\|%2e%2e|/etc/passwd|/windows/system32|boot\.ini",
    re.IGNORECASE
)

COMMAND = re.compile(
    r";|\||&&|\$\(|`|cmd=|exec=|system\(|/bin/sh|/bin/bash|cat\s+/etc",
    re.IGNORECASE
)

SPECIAL = re.compile(r"[<>\"'%;()&+\-=\[\]{}|\\^~`!@#$*/]")


# ── Utility functions ───────────────────────────────────────

def _entropy(s: str) -> float:
    """Compute Shannon entropy."""
    if not s or len(s) < 2:
        return 0.0

    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1

    n = len(s)

    return -sum((f/n) * math.log2(f/n) for f in freq.values())


# ── Row Feature Extraction ──────────────────────────────────

def extract_features_from_row(row: pd.Series) -> List[float]:
    """
    Extract 41 normalized features from a dataset row.
    """

    method       = str(row.get("method", "GET")).upper().strip()
    url          = str(row.get("url", "/")).strip()
    content_type = str(row.get("content_type", "")).lower()
    cookie       = str(row.get("cookie", ""))
    body         = str(row.get("content", ""))
    user_agent   = str(row.get("user_agent", ""))
    host         = str(row.get("host", ""))

    try:
        content_length = int(float(str(row.get("length", 0))))
    except (ValueError, TypeError):
        content_length = 0

    url_dec  = unquote(url)
    body_dec = unquote(body)
    full     = url_dec + " " + body_dec

    parsed = urlparse(url_dec)
    path   = parsed.path or "/"
    query  = parsed.query or ""
    params = parse_qs(query)

    # ── HTTP Method ──
    f01 = float(method == "GET")
    f02 = float(method == "POST")
    f03 = float(method == "PUT")
    f04 = float(method == "DELETE")
    f05 = float(method == "HEAD")

    # ── URL Structure ──
    f06 = min(len(url), 1000) / 1000
    f07 = min(len(path), 500) / 500
    f08 = min(len(query), 500) / 500
    f09 = min(path.count("/"), 20) / 20
    f10 = min(len(params), 20) / 20
    f11 = _entropy(url_dec) / 8
    f12 = min(url.count("%"), 50) / 50
    f13 = min(url.count("="), 20) / 20
    f14 = min(url.count("&"), 20) / 20
    f15 = float(".." in url)

    # ── Body Analysis ──
    f16 = min(len(body), 5000) / 5000
    f17 = _entropy(body_dec) / 8
    f18 = min(body.count("%"), 50) / 50
    f19 = min(body.count("="), 30) / 30
    f20 = min(body.count("&"), 30) / 30
    f21 = float(bool(body.strip()))
    f22 = min(body.count("+"), 30) / 30
    f23 = min(body.count("'"), 20) / 20

    # ── Headers ──
    f24 = min(content_length, 10000) / 10000
    f25 = float("json" in content_type)
    f26 = float("form" in content_type)
    f27 = float("xml" in content_type)
    f28 = min(len(user_agent), 300) / 300
    f29 = float(bool(cookie.strip()))
    f30 = float("jsessionid" in cookie.lower())

    # ── Attack Signatures ──
    f31 = min(len(SQLI.findall(full)), 10) / 10
    f32 = min(len(XSS.findall(full)), 10) / 10
    f33 = min(len(TRAVERSAL.findall(full)), 10) / 10
    f34 = min(len(COMMAND.findall(full)), 10) / 10
    f35 = min(len(SPECIAL.findall(full)), 50) / 50
    f36 = float(bool(SQLI.search(full)))
    f37 = float(bool(XSS.search(full)))

    # ── Statistical ──
    max_param_len = max(
        (len(v) for vals in params.values() for v in vals),
        default=0
    )

    f38 = min(max_param_len, 500) / 500
    f39 = sum(c.isdigit() for c in url_dec) / max(len(url_dec), 1)
    f40 = sum(c.isalpha() for c in url_dec) / max(len(url_dec), 1)
    f41 = _entropy(full) / 8

    features = [
        f01,f02,f03,f04,f05,
        f06,f07,f08,f09,f10,
        f11,f12,f13,f14,f15,
        f16,f17,f18,f19,f20,
        f21,f22,f23,f24,f25,
        f26,f27,f28,f29,f30,
        f31,f32,f33,f34,f35,
        f36,f37,f38,f39,f40,
        f41
    ]

    assert len(features) == 41

    return features


# ── DataFrame Feature Extraction ───────────────────────────

def extract_features_df(df: pd.DataFrame) -> np.ndarray:
    """
    Convert a dataset DataFrame into (N, 41) feature matrix.
    """

    df = df.copy()

    df.columns = [
        c.strip().lower().replace("-", "_").replace(" ", "_")
        for c in df.columns
    ]

    features = [extract_features_from_row(row) for _, row in df.iterrows()]

    return np.asarray(features, dtype=np.float32)


FEATURE_COUNT = 41
