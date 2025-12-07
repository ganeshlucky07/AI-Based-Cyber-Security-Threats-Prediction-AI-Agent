from typing import List, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from .config import DATASETS, TARGET_COLUMN, NORMAL_LABELS_LOWER


def load_all_datasets() -> pd.DataFrame:
    frames = []
    for name, cfg in DATASETS.items():
        path = cfg["path"]
        df = pd.read_csv(path)
        label_column = cfg["label_column"]
        normal_labels = set(NORMAL_LABELS_LOWER[name])
        df = df.copy()
        df[TARGET_COLUMN] = df[label_column].apply(
            lambda value: 0 if str(value).strip().lower() in normal_labels else 1
        )
        df["dataset_name"] = name
        frames.append(df)
    combined = pd.concat(frames, ignore_index=True)
    return combined


def build_train_test(
    test_size: float = 0.2, random_state: int = 42
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, List[str], StandardScaler]:
    df = load_all_datasets()
    numeric_columns = df.select_dtypes(include=["int64", "float64", "int32", "float32"]).columns.tolist()
    if TARGET_COLUMN in numeric_columns:
        numeric_columns.remove(TARGET_COLUMN)
    X = df[numeric_columns].values
    y = df[TARGET_COLUMN].values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=test_size, random_state=random_state, stratify=y
    )
    return X_train, X_test, y_train, y_test, numeric_columns, scaler
