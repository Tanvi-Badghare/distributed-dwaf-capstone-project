"""
Evaluation script for CSIC 2010 hybrid RF + TF-IDF detector.

Usage:
    python training/evaluate.py --csv training/csic2010/csic2010.csv
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

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    f1_score,
    roc_auc_score
)
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).parent.parent))


MODELS_DIR = Path(__file__).parent.parent / "models"


# ─────────────────────────────────────────────
# Targets
# ─────────────────────────────────────────────

TARGETS = {
    "accuracy": (0.97, "≥"),
    "f1": (0.96, "≥"),
    "fnr": (0.015, "≤"),
    "fpr": (0.025, "≤"),
}


# ─────────────────────────────────────────────
# Payload builder
# ─────────────────────────────────────────────

def build_payload_text(df: pd.DataFrame):
    texts = []

    for url, body in zip(df.get("url", ""), df.get("content", "")):

        url = str(url or "")
        body = str(body or "")

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
            .replace("--", " SQLI_COMMENT ") \
            .replace("/*", " SQLI_COMMENT ")

        texts.append(text.lower())

    return texts


# ─────────────────────────────────────────────
# Metrics printer
# ─────────────────────────────────────────────

def _print_metrics(y_true, y_pred, y_prob, label: str):

    acc = accuracy_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    try:
        auc = roc_auc_score(y_true, y_prob)
    except ValueError:
        auc = 0.0

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print(f"\n{'─' * 55}")
    print(f"  {label}")
    print(f"{'─' * 55}")

    print(
        f"  Accuracy  : {
            acc:.4f}  {
            '✅' if acc >= TARGETS['accuracy'][0] else '❌'}")
    print(f"  F1        : {f1:.4f}  {'✅' if f1 >= TARGETS['f1'][0] else '❌'}")
    print(
        f"  FNR       : {
            fnr:.4f}  {
            '✅' if fnr <= TARGETS['fnr'][0] else '❌'}")
    print(
        f"  FPR       : {
            fpr:.4f}  {
            '✅' if fpr <= TARGETS['fpr'][0] else '❌'}")
    print(f"  ROC-AUC   : {auc:.4f}")

    print(f"\n  TP={tp}  TN={tn}  FP={fp}  FN={fn}\n")

    print(
        classification_report(
            y_true,
            y_pred,
            target_names=["normal", "anomalous"],
            zero_division=0
        )
    )

    met = [
        acc >= TARGETS["accuracy"][0],
        f1 >= TARGETS["f1"][0],
        fnr <= TARGETS["fnr"][0],
        fpr <= TARGETS["fpr"][0],
    ]

    print(f"Targets met: {sum(met)}/4\n")

    return acc, f1, fnr, fpr, auc


# ─────────────────────────────────────────────
# Evaluation
# ─────────────────────────────────────────────

def evaluate(df: pd.DataFrame):

    y = df["label"].values
    idx = np.arange(len(df))

    idx_tr, idx_tmp, _, y_tmp = train_test_split(
        idx, y, test_size=0.30, random_state=42, stratify=y
    )

    idx_val, idx_te, y_val, y_te = train_test_split(
        idx_tmp, y_tmp, test_size=0.50, random_state=42, stratify=y_tmp
    )

    df_tr = df.iloc[idx_tr].reset_index(drop=True)
    df_val = df.iloc[idx_val].reset_index(drop=True)
    df_te = df.iloc[idx_te].reset_index(drop=True)

    print(f"Split — Train={len(df_tr)}, Val={len(df_val)}, Test={len(df_te)}")

    # ── Load models
    print("\nLoading models...")

    scaler = joblib.load(MODELS_DIR / "scaler.pkl")
    tfidf = joblib.load(MODELS_DIR / "tfidf.pkl")
    rf = joblib.load(MODELS_DIR / "random_forest.pkl")
    iso = joblib.load(MODELS_DIR / "isolation_forest.pkl")
    threshold = float(joblib.load(MODELS_DIR / "threshold.pkl"))

    print(f"RF threshold: {threshold:.3f}")

    # ── Feature extraction
    print("\nExtracting features...")

    X_hc_val = extract_features_df(df_val)
    X_hc_te = extract_features_df(df_te)

    X_hc_val_s = scaler.transform(X_hc_val)
    X_hc_te_s = scaler.transform(X_hc_te)

    X_tfidf_val = tfidf.transform(build_payload_text(df_val))
    X_tfidf_te = tfidf.transform(build_payload_text(df_te))

    X_val = hstack([csr_matrix(X_hc_val_s), X_tfidf_val])
    X_te = hstack([csr_matrix(X_hc_te_s), X_tfidf_te])

    # ── Random Forest
    print("\n" + "═" * 55)
    print("  RANDOM FOREST")
    print("═" * 55)

    val_proba = rf.predict_proba(X_val)[:, 1]
    te_proba = rf.predict_proba(X_te)[:, 1]

    val_pred = (val_proba >= threshold).astype(int)
    te_pred = (te_proba >= threshold).astype(int)

    _print_metrics(y_val, val_pred, val_proba, "Validation")
    _print_metrics(y_te, te_pred, te_proba, "Test")

    # ── Isolation Forest
    print("\n" + "═" * 55)
    print("  ISOLATION FOREST")
    print("═" * 55)

    iso_val_pred = (iso.predict(X_hc_val_s) == -1).astype(int)
    iso_te_pred = (iso.predict(X_hc_te_s) == -1).astype(int)

    iso_val_score = -iso.score_samples(X_hc_val_s)
    iso_te_score = -iso.score_samples(X_hc_te_s)

    iso_val_norm = iso_val_score / max(iso_val_score.max(), 1e-9)
    iso_te_norm = iso_te_score / max(iso_te_score.max(), 1e-9)

    _print_metrics(y_val, iso_val_pred, iso_val_norm, "Validation")
    _print_metrics(y_te, iso_te_pred, iso_te_norm, "Test")

    # ── Ensemble
    print("\n" + "═" * 55)
    print("  ENSEMBLE (0.85 RF + 0.15 ISO)")
    print("═" * 55)

    ens_val = 0.85 * val_proba + 0.15 * iso_val_norm
    ens_te = 0.85 * te_proba + 0.15 * iso_te_norm

    ens_val_pred = (ens_val >= threshold).astype(int)
    ens_te_pred = (ens_te >= threshold).astype(int)

    _print_metrics(y_val, ens_val_pred, ens_val, "Validation")
    _print_metrics(y_te, ens_te_pred, ens_te, "Test")

    # ── Feature importance
    print("\n" + "═" * 55)
    print("  TOP 20 FEATURE IMPORTANCES")
    print("═" * 55)

    hc_count = len(FEATURE_NAMES)
    hc_importances = rf.feature_importances_[:hc_count]

    top20 = pd.Series(hc_importances, index=FEATURE_NAMES).nlargest(20)

    for name, score in top20.items():
        bar = "█" * int(score * 300)
        print(f"{name:<35} {score:.4f}  {bar}")


# ─────────────────────────────────────────────

if __name__ == "__main__":

    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="Path to CSIC CSV")
    args = ap.parse_args()

    required = [
        "scaler.pkl",
        "tfidf.pkl",
        "random_forest.pkl",
        "isolation_forest.pkl",
        "threshold.pkl"
    ]

    missing = [m for m in required if not (MODELS_DIR / m).exists()]

    if missing:
        print(f"Missing models: {missing}")
        print(f"Run training first:")
        print(f"python training/train.py --csv {args.csv}")
        sys.exit(1)

    df = load_csic_csv(args.csv)

    evaluate(df)
