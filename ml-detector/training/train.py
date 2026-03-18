"""
Training script for CSIC 2010 — Hybrid RF + TF-IDF
Usage:
    python training/train.py --csv training/csic2010/csic_2010.csv
"""

from dataset import load_csic_csv
from feature_extractor import extract_features_df, FEATURE_NAMES
import sys
import argparse
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from scipy.sparse import hstack, csr_matrix

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix,
    accuracy_score, f1_score, roc_auc_score
)

sys.path.insert(0, str(Path(__file__).parent.parent))

MODELS_DIR = Path(__file__).parent.parent / "models"
MODELS_DIR.mkdir(exist_ok=True)


# ── Text payload builder ────────────────────────────────────────────────

def build_payload_text(df: pd.DataFrame) -> list:
    """
    Concatenate URL + body into a single text string per row.
    TF-IDF will tokenize on URL path segments, param names/values, body tokens.
    """
    texts = []
    for _, row in df.iterrows():
        url = str(row.get("url", "") or "")
        body = str(row.get("content", "") or "")
        # Strip HTTP version suffix
        for sfx in [" HTTP/1.1", " HTTP/1.0", " HTTP/2"]:
            url = url.replace(sfx, "")
        # Normalise separators so TF-IDF tokenises on attack tokens
        text = (url + " " + body) \
            .replace("&", " ") \
            .replace("=", " ") \
            .replace("+", " ") \
            .replace("?", " ") \
            .replace("/", " ") \
            .replace("%27", " SQLI_QUOTE ")   \
            .replace("%3B", " SQLI_SEMI ")    \
            .replace("%3b", " SQLI_SEMI ")    \
            .replace("%2F", " ENC_SLASH ")    \
            .replace("%2f", " ENC_SLASH ")    \
            .replace("%3C", " XSS_LT ")       \
            .replace("%3c", " XSS_LT ")       \
            .replace("%3E", " XSS_GT ")       \
            .replace("%3e", " XSS_GT ")       \
            .replace("%00", " NULL_BYTE ")     \
            .replace("--", " SQLI_COMMENT ") \
            .replace("/*", " SQLI_COMMENT ")
        texts.append(text.lower())
    return texts


# ── Metrics helper ──────────────────────────────────────────────────────

def _metrics(y_true, y_pred, y_prob=None, label=""):
    acc = accuracy_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    print(f"  {label}")
    print(
        f"    Acc={
            acc:.4f}  F1={
            f1:.4f}  FNR={
                fnr:.4f}  FPR={
                    fpr:.4f}",
        end="")
    if y_prob is not None:
        print(f"  AUC={roc_auc_score(y_true, y_prob):.4f}", end="")
    print()
    print(f"    Accuracy ≥ 0.97  : {'✅' if acc >= 0.97 else '❌'} ({acc:.4f})")
    print(f"    F1       ≥ 0.96  : {'✅' if f1 >= 0.96 else '❌'} ({f1:.4f})")
    print(f"    FNR      ≤ 0.015 : {'✅' if fnr <= 0.015 else '❌'} ({fnr:.4f})")
    print(f"    FPR      ≤ 0.025 : {'✅' if fpr <= 0.025 else '❌'} ({fpr:.4f})")
    print(classification_report(y_true, y_pred,
          target_names=["normal", "anomalous"], zero_division=0))
    return acc, f1, fnr, fpr


def find_best_threshold(y_true, y_prob):
    best_t, best_f1, best_met = 0.5, 0.0, False
    for t in np.arange(0.05, 0.95, 0.001):
        pred = (y_prob >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 1.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 1.0
        f1 = f1_score(y_true, pred, zero_division=0)
        acc = accuracy_score(y_true, pred)
        # Prioritise FNR — catching attacks matters more than false alarms
        meets = fnr <= 0.015 and fpr <= 0.05 and acc >= 0.96
        if meets and f1 > best_f1:
            best_f1, best_t, best_met = f1, t, True
        elif not best_met and f1 > best_f1:
            best_f1, best_t = f1, t
    return best_t, best_met


# ── Main training ───────────────────────────────────────────────────────

def train(df: pd.DataFrame):

    # ── Split first (fit TF-IDF only on train) ──────────────────────────────
    y = df["label"].values
    idx = np.arange(len(df))
    idx_tr, idx_tmp, y_tr, y_tmp = train_test_split(
        idx, y, test_size=0.30, random_state=42, stratify=y)
    idx_val, idx_te, y_val, y_te = train_test_split(
        idx_tmp, y_tmp, test_size=0.50, random_state=42, stratify=y_tmp)

    df_tr = df.iloc[idx_tr].reset_index(drop=True)
    df_val = df.iloc[idx_val].reset_index(drop=True)
    df_te = df.iloc[idx_te].reset_index(drop=True)

    print(f"Train={len(df_tr)}, Val={len(df_val)}, Test={len(df_te)}")

    # ── Hand-crafted features (41) ──────────────────────────────────────────
    print("\n── Extracting hand-crafted features ────────────────────")
    X_hc_tr = extract_features_df(df_tr)
    X_hc_val = extract_features_df(df_val)
    X_hc_te = extract_features_df(df_te)
    print(f"  Hand-crafted shape: {X_hc_tr.shape}")

    scaler = StandardScaler()
    X_hc_tr_s = scaler.fit_transform(X_hc_tr)
    X_hc_val_s = scaler.transform(X_hc_val)
    X_hc_te_s = scaler.transform(X_hc_te)

    # ── TF-IDF features ─────────────────────────────────────────────────────
    print("\n── Building TF-IDF features ─────────────────────────────")
    texts_tr = build_payload_text(df_tr)
    texts_val = build_payload_text(df_val)
    texts_te = build_payload_text(df_te)

    tfidf = TfidfVectorizer(
        analyzer="word",
        token_pattern=r"[a-z0-9_%]+",
        ngram_range=(1, 3),              # trigrams catch "drop table usuarios"
        max_features=5000,
        min_df=2,
        sublinear_tf=True,
    )
    X_tfidf_tr = tfidf.fit_transform(texts_tr)
    X_tfidf_val = tfidf.transform(texts_val)
    X_tfidf_te = tfidf.transform(texts_te)
    print(f"  TF-IDF shape: {X_tfidf_tr.shape}")

    # ── Combine: hand-crafted (dense) + TF-IDF (sparse) ──────────────────────
    X_tr = hstack([csr_matrix(X_hc_tr_s), X_tfidf_tr])
    X_val = hstack([csr_matrix(X_hc_val_s), X_tfidf_val])
    X_te = hstack([csr_matrix(X_hc_te_s), X_tfidf_te])
    print(f"  Combined shape: {X_tr.shape}")

    # ── Random Forest ───────────────────────────────────────────────────────
    print("\n── Random Forest (hybrid) ───────────────────────────────")
    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=1,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_tr, y_tr)

    val_proba = rf.predict_proba(X_val)[:, 1]
    te_proba = rf.predict_proba(X_te)[:, 1]

    best_t, met = find_best_threshold(y_val, val_proba)
    print(f"\n  Optimal threshold: {best_t:.3f} (targets met: {met})")

    print("\n  Validation:")
    _metrics(y_val, (val_proba >= best_t).astype(int), val_proba, "")
    print("  Test:")
    _metrics(y_te, (te_proba >= best_t).astype(int), te_proba, "")

    # ── Isolation Forest (on hand-crafted only — sparse not ideal) ──────────
    print("\n── Isolation Forest ─────────────────────────────────────")
    iso = IsolationForest(
        n_estimators=200,
        contamination=(y == 1).sum() / len(y),
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_hc_tr_s)
    iso_val = (iso.predict(X_hc_val_s) == -1).astype(int)
    iso_te = (iso.predict(X_hc_te_s) == -1).astype(int)
    print("  Validation:")
    _metrics(y_val, iso_val, label="")
    print("  Test:")
    _metrics(y_te, iso_te, label="")

    # ── Save everything ─────────────────────────────────────────────────────
    joblib.dump(scaler, MODELS_DIR / "scaler.pkl")
    joblib.dump(tfidf, MODELS_DIR / "tfidf.pkl")
    joblib.dump(rf, MODELS_DIR / "random_forest.pkl")
    joblib.dump(iso, MODELS_DIR / "isolation_forest.pkl")
    joblib.dump(float(best_t), MODELS_DIR / "threshold.pkl")

    print(f"\n✅ Models saved to {MODELS_DIR}")
    print(f"✅ Threshold {best_t:.3f} saved")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    args = ap.parse_args()
    df = load_csic_csv(args.csv)
    train(df)
