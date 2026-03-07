"""
Training script for CSIC 2010 HTTP Anomaly Detection

Usage:
    python training/train.py --csv training/csic2010/csic2010.csv
"""

import sys
import argparse
import joblib
import numpy as np
import pandas as pd
from pathlib import Path

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    f1_score,
    roc_auc_score
)

# ── Import project modules ─────────────────────────────────

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))

from feature_extractor import extract_features_df
from training.dataset import load_csic_csv

MODELS_DIR = ROOT / "models"
MODELS_DIR.mkdir(exist_ok=True)


# ── Training Pipeline ─────────────────────────────────────

def train(df: pd.DataFrame):

    print(f"\n── Extracting features from {len(df)} rows ──────")

    X = extract_features_df(df)
    y = df["label"].values

    print(f"Feature matrix shape: {X.shape}")
    print(f"Labels — Normal: {(y==0).sum()}, Attack: {(y==1).sum()}")

    # 70 / 15 / 15 split
    X_tr, X_tmp, y_tr, y_tmp = train_test_split(
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

    print(f"Train={len(X_tr)}  Val={len(X_val)}  Test={len(X_te)}")

    # ── Feature Scaling ─────────────────────────────

    scaler = StandardScaler()

    X_tr_s  = scaler.fit_transform(X_tr)
    X_val_s = scaler.transform(X_val)
    X_te_s  = scaler.transform(X_te)

    # ── Random Forest (Supervised) ──────────────────

    print("\n── Random Forest ───────────────────────────")

    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    rf.fit(X_tr_s, y_tr)

    print("Validation metrics:")
    _metrics(y_val, rf.predict(X_val_s), rf.predict_proba(X_val_s)[:,1])

    print("Test metrics:")
    _metrics(y_te, rf.predict(X_te_s), rf.predict_proba(X_te_s)[:,1])

    # ── Isolation Forest (Unsupervised) ─────────────

    print("\n── Isolation Forest ────────────────────────")

    iso = IsolationForest(
        n_estimators=150,
        contamination=0.20,
        random_state=42,
        n_jobs=-1
    )

    # Train only on NORMAL traffic
    iso.fit(X_tr_s[y_tr == 0])

    iso_val = (iso.predict(X_val_s) == -1).astype(int)
    iso_te  = (iso.predict(X_te_s)  == -1).astype(int)

    print("Validation metrics:")
    _metrics(y_val, iso_val)

    print("Test metrics:")
    _metrics(y_te, iso_te)

    # ── Save Models ─────────────────────────────────

    joblib.dump(scaler, MODELS_DIR / "scaler.pkl")
    joblib.dump(rf,     MODELS_DIR / "random_forest.pkl")
    joblib.dump(iso,    MODELS_DIR / "isolation_forest.pkl")

    print(f"\n✅ Models saved to {MODELS_DIR}")


# ── Metrics Helper ───────────────────────────────────────

def _metrics(y_true, y_pred, y_prob=None):

    acc = accuracy_score(y_true, y_pred)
    f1  = f1_score(y_true, y_pred, zero_division=0)

    tn, fp, fn, tp = confusion_matrix(
        y_true,
        y_pred,
        labels=[0,1]
    ).ravel()

    fnr = fn/(fn+tp) if (fn+tp)>0 else 0
    fpr = fp/(fp+tn) if (fp+tn)>0 else 0

    print(
        f"Acc={acc:.4f}  "
        f"F1={f1:.4f}  "
        f"FNR={fnr:.4f}  "
        f"FPR={fpr:.4f}",
        end=""
    )

    if y_prob is not None:
        auc = roc_auc_score(y_true, y_prob)
        print(f"  AUC={auc:.4f}", end="")

    print()

    print(
        classification_report(
            y_true,
            y_pred,
            target_names=["normal","anomalous"],
            zero_division=0
        )
    )


# ── CLI Entry Point ──────────────────────────────────────

if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--csv",
        required=True,
        help="Path to CSIC 2010 CSV dataset"
    )

    args = parser.parse_args()

    df = load_csic_csv(args.csv)

    train(df)
