"""
CSIC 2010 HTTP Dataset Loader — CSV version
Columns: classification, Method, User-Agent, Pragma, Cache-Control,
         Accept, Accept-encoding, Accept-charset, language, host,
         cookie, content-type, connection, length, content, URL
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Tuple


def load_csic_csv(filepath: str) -> pd.DataFrame:
    """
    Load the CSIC 2010 CSV file.
    Returns a cleaned DataFrame with a binary 'label' column.
    """
    df = pd.read_csv(filepath, low_memory=False)

    # Normalise column names
    df.columns = [c.strip().lower().replace("-", "_").replace(" ", "_")
                  for c in df.columns]

    print(f"Columns found: {list(df.columns)}")
    print(f"Loaded {len(df)} rows")

    # Create binary label: 0 = Normal, 1 = Anomalous/Attack
    label_col = _find_label_col(df)
    df["label"] = df[label_col].astype(str).str.strip().str.lower().map(
        lambda x: 1 if "anomalous" in x or "attack" in x or "1" == x else 0
    ).astype(int)

    print(f"Class distribution:")
    print(f"  Normal    : {(df['label']==0).sum()}")
    print(f"  Anomalous : {(df['label']==1).sum()}")

    return df


def _find_label_col(df: pd.DataFrame) -> str:
    """Find the classification column regardless of exact name."""
    candidates = ["classification", "class", "label", "type", "category", "unnamed:_0", "unnamed: 0"]
    for c in candidates:
        if c in df.columns:
            return c
    return df.columns[0]


def get_train_val_test(df: pd.DataFrame,
                       train=0.70, val=0.15, test=0.15,
                       seed=42) -> Tuple:
    """
    Split into 70/15/15 train/val/test preserving class ratio.
    Returns (df_train, df_val, df_test)
    """
    from sklearn.model_selection import train_test_split

    df_train, df_temp = train_test_split(
        df, test_size=(val + test), random_state=seed, stratify=df["label"]
    )
    df_val, df_test = train_test_split(
        df_temp, test_size=test / (val + test),
        random_state=seed, stratify=df_temp["label"]
    )

    print(f"\nSplit — Train: {len(df_train)}, "
          f"Val: {len(df_val)}, Test: {len(df_test)}")
    return df_train, df_val, df_test