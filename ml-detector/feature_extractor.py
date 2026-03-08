"""
Feature Extractor for CSIC 2010 CSV Dataset — v4
Key insight: Normal traffic contains Spanish ISO-8859-1 chars (%F3=ñ, %E9=é).
Attack signals are SPECIFIC: %27('), %3B(;), %2F(/), %3C(<), %3E(>), SQL keywords.
"""

import re
import math
import numpy as np
import pandas as pd
from typing import List
from urllib.parse import urlparse, parse_qs, unquote


# ── Attack-SPECIFIC encoded characters (NOT Spanish chars) ────────────────────
# Spanish chars: %F3 %E9 %F1 %FA %E1 %ED %F3 %FC — these are NORMAL
# Attack chars: %27(') %22(") %3B(;) %2F(/) %3C(<) %3E(>) %60(`) %00(null)
ENC_SQUOTE    = re.compile(r"%27",          re.IGNORECASE)  # '
ENC_DQUOTE    = re.compile(r"%22",          re.IGNORECASE)  # "
ENC_SEMICOLON = re.compile(r"%3[Bb]",       re.IGNORECASE)  # ;
ENC_SLASH     = re.compile(r"%2[Ff]",       re.IGNORECASE)  # /
ENC_LT        = re.compile(r"%3[Cc]",       re.IGNORECASE)  # <
ENC_GT        = re.compile(r"%3[Ee]",       re.IGNORECASE)  # >
ENC_BACKTICK  = re.compile(r"%60",          re.IGNORECASE)  # `
ENC_SPACE     = re.compile(r"%20",          re.IGNORECASE)  # space (not +)
NULL_BYTE     = re.compile(r"%00|\\x00",    re.IGNORECASE)
DOUBLE_ENC    = re.compile(r"%25[2-3][0-9a-fA-F]", re.IGNORECASE)  # double-encoded punctuation only

# SQL keywords in decoded values
SQLI_KW = re.compile(
    r"\b(union|select|insert|update|delete|drop|alter|create|exec|"
    r"execute|from|where|having|group\s+by|order\s+by|sleep|benchmark|"
    r"waitfor|load_file|outfile|information_schema|xp_cmdshell|"
    r"char\s*\(|ascii\s*\(|substring\s*\(|mid\s*\(|concat\s*\()\b",
    re.IGNORECASE
)
# SQL punctuation in decoded values
SQLI_PUNCT = re.compile(r"'|\"|\`;|;--|--\s|/\*|\*/|#\s", re.IGNORECASE)

XSS_PAT = re.compile(
    r"(<script|javascript:|vbscript:|on\w+\s*=|"
    r"alert\s*\(|document\.cookie|eval\s*\(|"
    r"<iframe|<img\s|<svg|expression\s*\()",
    re.IGNORECASE
)
TRAVERSAL_PAT = re.compile(
    r"(\.\./|/etc/passwd|/proc/self|boot\.ini)", re.IGNORECASE
)
CMD_PAT = re.compile(
    r"(/bin/(sh|bash)|system\s*\(|shell_exec\s*\(|`[^`]+`)",
    re.IGNORECASE
)
TILDE = re.compile(r"~$")


def _s(val) -> str:
    s = str(val) if val is not None else ""
    return "" if s == "nan" else s


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f/n) * math.log2(f/n) for f in freq.values())


def _strip_http(url: str) -> str:
    for sfx in [" HTTP/1.1", " HTTP/1.0", " HTTP/2.0", " HTTP/2"]:
        if url.endswith(sfx):
            return url[:-len(sfx)]
    return url


def _decode(s: str) -> str:
    try:
        return unquote(unquote(s))
    except Exception:
        return s


def extract_features_from_row(row: pd.Series) -> List[float]:

    method = _s(row.get("method", "GET")).upper().strip()
    url    = _strip_http(_s(row.get("url", "/")))
    body   = _s(row.get("content", ""))
    cookie = _s(row.get("cookie",  ""))
    ct     = _s(row.get("content_type", "")).lower()

    try:
        clen = int(float(_s(row.get("lenght", 0)) or 0))
    except (ValueError, TypeError):
        clen = 0

    url_dec  = _decode(url)
    body_dec = _decode(body)

    parsed       = urlparse(url_dec)
    query        = parsed.query or ""
    query_raw    = url.split("?", 1)[1] if "?" in url else ""
    query_params = parse_qs(query, keep_blank_values=True)

    # Decoded URL param values
    url_vals = [_decode(v) for vals in query_params.values() for v in vals]

    # Decoded body param values
    body_params = {}
    for part in body.split("&"):
        if "=" in part:
            k, _, v = part.partition("=")
            body_params[k] = _decode(v)
    body_vals = list(body_params.values())

    all_vals     = url_vals + body_vals
    all_vals_str = " ".join(all_vals)

    # ── Method (1–5) ──────────────────────────────────────────────────────────
    f01 = 1.0 if method == "GET"    else 0.0
    f02 = 1.0 if method == "POST"   else 0.0
    f03 = 1.0 if method == "PUT"    else 0.0
    f04 = 1.0 if method == "DELETE" else 0.0
    f05 = 1.0 if method not in ("GET","POST","PUT","DELETE","HEAD") else 0.0

    # ── Attack-specific encoded chars IN RAW URL (6–12) ───────────────────────
    # These are specific to attacks, NOT Spanish chars
    f06 = min(len(ENC_SQUOTE.findall(query_raw)),    10) / 10.0   # %27
    f07 = min(len(ENC_SEMICOLON.findall(query_raw)), 10) / 10.0   # %3B
    f08 = min(len(ENC_SLASH.findall(query_raw)),     10) / 10.0   # %2F
    f09 = min(len(ENC_LT.findall(query_raw)),        10) / 10.0   # %3C
    f10 = min(len(ENC_GT.findall(query_raw)),        10) / 10.0   # %3E
    f11 = min(len(ENC_DQUOTE.findall(query_raw)),    10) / 10.0   # %22
    f12 = min(len(DOUBLE_ENC.findall(query_raw)),    10) / 10.0   # %25xx

    # ── Same in body raw (13–17) ──────────────────────────────────────────────
    f13 = min(len(ENC_SQUOTE.findall(body)),    10) / 10.0
    f14 = min(len(ENC_SEMICOLON.findall(body)), 10) / 10.0
    f15 = min(len(ENC_SLASH.findall(body)),     10) / 10.0
    f16 = min(len(ENC_LT.findall(body)),        10) / 10.0
    f17 = 1.0 if NULL_BYTE.search(url + body) else 0.0

    # ── SQL keywords in decoded param values (18–20) ──────────────────────────
    f18 = min(len(SQLI_KW.findall(all_vals_str)),    10) / 10.0
    f19 = 1.0 if SQLI_KW.search(all_vals_str)        else 0.0
    f20 = min(len(SQLI_PUNCT.findall(all_vals_str)), 10) / 10.0

    # ── XSS / Traversal / Command in decoded values (21–23) ──────────────────
    f21 = 1.0 if XSS_PAT.search(all_vals_str)       else 0.0
    f22 = 1.0 if TRAVERSAL_PAT.search(all_vals_str) else 0.0
    f23 = 1.0 if CMD_PAT.search(all_vals_str)        else 0.0

    # ── Param value statistics (24–29) ───────────────────────────────────────
    max_val_len = max((len(v) for v in all_vals), default=0)
    max_val_ent = max((_entropy(v) for v in all_vals), default=0.0)

    f24 = min(max_val_len, 500) / 500.0
    f25 = max_val_ent / 8.0
    f26 = min(len(all_vals), 20) / 20.0
    # Ratio of attack-specific encoded chars to total encoded chars in query
    all_enc     = len(re.findall(r"%[0-9a-fA-F]{2}", query_raw))
    attack_enc  = (len(ENC_SQUOTE.findall(query_raw)) +
                   len(ENC_SEMICOLON.findall(query_raw)) +
                   len(ENC_SLASH.findall(query_raw)) +
                   len(ENC_LT.findall(query_raw)) +
                   len(ENC_GT.findall(query_raw)))
    f27 = attack_enc / max(all_enc, 1)
    f28 = 1.0 if any(SQLI_KW.search(v)   for v in all_vals) else 0.0
    f29 = 1.0 if any(SQLI_PUNCT.search(v) for v in all_vals) else 0.0

    # ── URL structure (30–34) ─────────────────────────────────────────────────
    f30 = min(len(url),   2000) / 2000.0
    f31 = min(len(query_raw), 1000) / 1000.0
    f32 = min(len(query_params), 20) / 20.0
    f33 = _entropy(url_dec) / 8.0
    f34 = 1.0 if TILDE.search(url_dec.rstrip()) else 0.0

    # ── Body features (35–38) ─────────────────────────────────────────────────
    f35 = min(len(body), 2000) / 2000.0
    f36 = _entropy(body_dec) / 8.0
    f37 = 1.0 if SQLI_KW.search(body_dec)    else 0.0
    f38 = 1.0 if SQLI_PUNCT.search(body_dec) else 0.0

    # ── Header / misc (39–41) ─────────────────────────────────────────────────
    f39 = min(clen, 10000) / 10000.0
    f40 = 1.0 if "application/x-www-form-urlencoded" in ct else 0.0
    f41 = _entropy(all_vals_str) / 8.0

    features = [
        f01,f02,f03,f04,f05,
        f06,f07,f08,f09,f10,
        f11,f12,f13,f14,f15,
        f16,f17,f18,f19,f20,
        f21,f22,f23,f24,f25,
        f26,f27,f28,f29,f30,
        f31,f32,f33,f34,f35,
        f36,f37,f38,f39,f40,
        f41,
    ]
    assert len(features) == 41, f"Expected 41, got {len(features)}"
    return features


def extract_features_df(df: pd.DataFrame) -> np.ndarray:
    df = df.copy()
    df.columns = [c.strip().lower().replace("-","_").replace(" ","_")
                  for c in df.columns]
    return np.array([extract_features_from_row(row)
                     for _, row in df.iterrows()])


FEATURE_NAMES = [
    "method_get","method_post","method_put","method_delete","method_other",
    "url_enc_squote","url_enc_semicolon","url_enc_slash","url_enc_lt","url_enc_gt",
    "url_enc_dquote","url_double_enc","body_enc_squote","body_enc_semicolon","body_enc_slash",
    "body_enc_lt","has_null_byte","sqli_kw_count","has_sqli_kw","sqli_punct_count",
    "has_xss","has_traversal","has_command","max_param_val_len","max_param_entropy",
    "num_param_vals","attack_enc_ratio","param_has_sqli_kw","param_has_sqli_punct","url_length",
    "query_length","num_query_params","url_entropy","url_ends_tilde","body_length",
    "body_entropy","body_has_sqli_kw","body_has_sqli_punct","content_length","content_type_form",
    "all_vals_entropy",
]