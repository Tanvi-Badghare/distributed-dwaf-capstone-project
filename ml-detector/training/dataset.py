"""
CSIC 2010 HTTP Dataset Loader — CSV version

Columns:
classification, Method, User-Agent, Pragma, Cache-Control,
Accept, Accept-encoding, Accept-charset, language, host,
cookie, content-type, connection, length, content, URL
"""

import pandas as pd
import logging
from pathlib import Path
from typing import Tuple

logger = logging.getLogger(__name__)


def load_csic_csv(filepath: str) -> pd.DataFrame:
    """
    Load the CSIC 2010 CSV dataset.

    Returns:
        pd.DataFrame with normalized columns and binary 'label'.
        label: 0 = normal request, 1 = attack
    """

    path = Path(filepath)

    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {filepath}")

    df = pd.read_csv(path, low_memory=False)

    # Normalize column names
    df.columns = [
        c.strip().lower().replace("-", "_").replace(" ", "_")
        for c in df.columns
    ]

    logger.info("Loaded %d rows", len(df))
    logger.info("Columns detected: %s", list(df.columns))

    label_col = _find_label_col(df)

    df["label"] = (
        df[label_col]
        .astype(str)
        .str.strip()
        .str.lower()
        .ne("normal")
        .astype(int)
    )

    logger.info(
        "Class distribution — normal: %d attack: %d",
        (df["label"] == 0).sum(),
        (df["label"] == 1).sum()
    )

    return df


def _find_label_col(df: pd.DataFrame) -> str:
    """Locate the classification column regardless of naming."""

    candidates = ["classification", "class", "label", "type", "category"]

    for col in candidates:
        if col in df.columns:
            return col

    raise ValueError("No classification column found in dataset")


def get_train_val_test(
    df: pd.DataFrame,
    train: float = 0.70,
    val: float = 0.15,
    test: float = 0.15,
    seed: int = 42
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Split dataset into train/validation/test sets with stratification.

    Returns:
        (train_df, val_df, test_df)
    """

    from sklearn.model_selection import train_test_split

    if round(train + val + test, 2) != 1.0:
        raise ValueError("Train/val/test split must sum to 1.0")

    df_train, df_temp = train_test_split(
        df,
        test_size=(val + test),
        random_state=seed,
        stratify=df["label"]
    )

    df_val, df_test = train_test_split(
        df_temp,
        test_size=test / (val + test),
        random_state=seed,
        stratify=df_temp["label"]
    )

    logger.info(
        "Dataset split — train: %d val: %d test: %d",
        len(df_train),
        len(df_val),
        len(df_test)
    )

    return df_train, df_val, df_test
