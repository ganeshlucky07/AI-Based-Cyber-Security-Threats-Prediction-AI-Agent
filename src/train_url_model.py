import joblib
import pandas as pd
from pathlib import Path
from typing import Tuple

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from .config import BASE_DIR


URL_DATA_PATH = BASE_DIR / "data" / "urls" / "urls_labeled.csv"


def _load_url_dataframe() -> pd.DataFrame:
    if not URL_DATA_PATH.exists():
        raise FileNotFoundError(
            f"URL dataset not found at {URL_DATA_PATH}. Prepare a combined CSV with columns 'url' and 'label'."
        )
    df = pd.read_csv(URL_DATA_PATH)
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("URL dataset must contain 'url' and 'label' columns.")
    return df


def _prepare_labels(series: pd.Series) -> pd.Series:
    if series.dtype == "O":
        mapping = {
            "malicious": 1,
            "phishing": 1,
            "spam": 1,
            "botnet": 1,
            "benign": 0,
            "legit": 0,
            "legitimate": 0,
            "good": 0,
        }
        lower = series.astype(str).str.strip().str.lower()
        y = lower.map(mapping)
        if y.isna().any():
            raise ValueError(
                "URL labels contain values outside the expected set. "
                "Normalize them to malicious/benign or 1/0 before training."
            )
        return y.astype(int)
    return series.astype(int)


def train_url_model() -> None:
    df = _load_url_dataframe()
    X = df["url"].astype(str)
    y = _prepare_labels(df["label"])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipeline = Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(3, 5),
                    min_df=2,
                    max_features=200000,
                ),
            ),
            (
                "clf",
                LogisticRegression(max_iter=400, solver="liblinear"),
            ),
        ]
    )

    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    if hasattr(pipeline, "predict_proba"):
        y_proba = pipeline.predict_proba(X_test)[:, 1]
    else:
        y_proba = None

    report = classification_report(y_test, y_pred)
    print(report)

    roc_auc = None
    if y_proba is not None:
        roc_auc = roc_auc_score(y_test, y_proba)
        print(f"ROC-AUC: {roc_auc:.4f}")

    models_dir = BASE_DIR / "trained_models"
    models_dir.mkdir(parents=True, exist_ok=True)

    artifact = {
        "pipeline": pipeline,
        "report": report,
        "roc_auc": roc_auc,
    }
    joblib.dump(artifact, models_dir / "url_model.joblib")


if __name__ == "__main__":
    train_url_model()
