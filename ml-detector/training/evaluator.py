"""
Evaluation script for CSIC 2010 trained models.

Usage:
    python training/evaluate.py --csv training/csic2010/csic2010.csv
"""

import sys
import argparse
import joblib
import numpy as np
import pandas as pd
from pathlib import Path

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    f1_score,
    roc_auc_score,
    precision_score,
    recall_score
)

from sklearn.model_selection import train_test_split


# ── Project root import ─────────────────────────

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))

from feature_extractor import extract_features_df
from training.dataset import load_csic_csv


MODELS_DIR = ROOT / "models"


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def print_section(title: str):
    print("\n" + "="*55)
    print(f"  {title}")
    print("="*55)


def full_metrics(y_true, y_pred, y_prob=None, name="Model"):

    print(f"\n── {name} ─────────────────────────────")

    acc  = accuracy_score(y_true, y_pred)
    f1   = f1_score(y_true, y_pred, zero_division=0)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec  = recall_score(y_true, y_pred, zero_division=0)

    tn, fp, fn, tp = confusion_matrix(
        y_true, y_pred, labels=[0,1]
    ).ravel()

    fnr = fn/(fn+tp) if (fn+tp)>0 else 0
    fpr = fp/(fp+tn) if (fp+tn)>0 else 0

    print(f"  Accuracy  : {acc:.4f}")
    print(f"  F1 Score  : {f1:.4f}")
    print(f"  Precision : {prec:.4f}")
    print(f"  Recall    : {rec:.4f}")
    print(f"  FNR       : {fnr:.4f}")
    print(f"  FPR       : {fpr:.4f}")

    if y_prob is not None:
        auc = roc_auc_score(y_true, y_prob)
        print(f"  ROC-AUC   : {auc:.4f}")

    print("\nConfusion Matrix")
    print(confusion_matrix(y_true, y_pred))

    print("\nClassification Report")
    print(
        classification_report(
            y_true,
            y_pred,
            target_names=["normal","anomalous"],
            zero_division=0
        )
    )

    return {
        "accuracy": acc,
        "f1": f1,
        "precision": prec,
        "recall": rec,
        "fnr": fnr,
        "fpr": fpr
    }


# ─────────────────────────────────────────────
# Main evaluation
# ─────────────────────────────────────────────

def evaluate(csv_path: str):

    print_section("Loading Models")

    scaler = joblib.load(MODELS_DIR / "scaler.pkl")
    rf     = joblib.load(MODELS_DIR / "random_forest.pkl")
    iso    = joblib.load(MODELS_DIR / "isolation_forest.pkl")

    print("Models loaded successfully")

    # ── Dataset ─────────────────────────────

    print_section("Loading Dataset")

    df = load_csic_csv(csv_path)

    print(f"Rows: {len(df)}")

    # ── Feature extraction ──────────────────

    print_section("Extracting Features")

    X = extract_features_df(df)
    y = df["label"].values

    print(f"Feature matrix shape: {X.shape}")

    # ── Same split as training ─────────────

    _, X_tmp, _, y_tmp = train_test_split(
        X, y,
        test_size=0.30,
        random_state=42,
        stratify=y
    )

    X_val, X_te, y_val, y_te = train_test_split(
        X_tmp, y_tmp,
        test_size=0.50,
        random_state=42,
        stratify=y_tmp
    )

    X_val_s = scaler.transform(X_val)
    X_te_s  = scaler.transform(X_te)

    # ── Random Forest ──────────────────────

    print_section("Random Forest Evaluation")

    rf_val_pred  = rf.predict(X_val_s)
    rf_val_prob  = rf.predict_proba(X_val_s)[:,1]

    rf_te_pred   = rf.predict(X_te_s)
    rf_te_prob   = rf.predict_proba(X_te_s)[:,1]

    full_metrics(y_val, rf_val_pred, rf_val_prob, "RF Validation")
    full_metrics(y_te,  rf_te_pred,  rf_te_prob,  "RF Test")

    # ── Isolation Forest ───────────────────

    print_section("Isolation Forest Evaluation")

    iso_val_score = (iso.predict(X_val_s) == -1).astype(float)
    iso_te_score  = (iso.predict(X_te_s)  == -1).astype(float)

    full_metrics(y_val, iso_val_score.astype(int), name="ISO Validation")
    full_metrics(y_te,  iso_te_score.astype(int),  name="ISO Test")

    # ── Ensemble ───────────────────────────

    print_section("Ensemble Evaluation")

    ens_val_score = 0.8 * rf_val_prob + 0.2 * iso_val_score
    ens_te_score  = 0.8 * rf_te_prob  + 0.2 * iso_te_score

    ens_val_pred = (ens_val_score >= 0.5).astype(int)
    ens_te_pred  = (ens_te_score  >= 0.5).astype(int)

    full_metrics(y_val, ens_val_pred, ens_val_score, "Ensemble Validation")
    full_metrics(y_te,  ens_te_pred,  ens_te_score,  "Ensemble Test")

    print_section("Evaluation Complete")


# ─────────────────────────────────────────────

if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--csv",
        required=True,
        help="Path to CSIC 2010 CSV dataset"
    )

    args = parser.parse_args()

    if not (MODELS_DIR / "random_forest.pkl").exists():
        print("❌ Models not found. Run training/train.py first.")
        sys.exit(1)

    evaluate(args.csv)
