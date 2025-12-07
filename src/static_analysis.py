import argparse
from datetime import datetime
from pathlib import Path
from typing import Tuple

import joblib
import numpy as np
import pandas as pd

from .config import BASE_DIR


def load_artifact() -> Tuple[object, object, list]:
    models_dir = BASE_DIR / "trained_models"
    artifact_path = models_dir / "xgb_classifier.joblib"
    if not artifact_path.exists():
        raise FileNotFoundError(
            f"Trained model artifact not found at {artifact_path}. Train the model first."
        )
    artifact = joblib.load(artifact_path)
    model = artifact["model"]
    scaler = artifact["scaler"]
    features = artifact["features"]
    return model, scaler, features


def analyze_file(input_path: Path, output_path: Path, threshold: float = 0.5) -> None:
    model, scaler, features = load_artifact()
    df = pd.read_csv(input_path)
    missing_features = [name for name in features if name not in df.columns]
    if missing_features:
        raise ValueError(
            "Input file is missing required feature columns: " + ", ".join(missing_features)
        )
    X_raw = df[features].values
    X_scaled = scaler.transform(X_raw)
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X_scaled)[:, 1]
    else:
        scores = model.decision_function(X_scaled)
        probabilities = (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)
    labels = (probabilities >= threshold).astype(int)
    df["threat_probability"] = probabilities
    df["prediction_label"] = labels
    df["prediction_text"] = np.where(labels == 1, "Threat", "Safe")
    def risk_type(prob: float) -> str:
        if prob >= 0.85:
            return "Critical Threat"
        if prob >= 0.7:
            return "High Threat"
        if prob >= 0.5:
            return "Medium Threat"
        if prob >= 0.3:
            return "Low Threat"
        return "Safe"
    df["risk_type"] = df["threat_probability"].apply(risk_type)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    total = len(df)
    threats = int((labels == 1).sum())
    safe = total - threats
    if threats > 0:
        overall_status = "Threats Detected"
    else:
        overall_status = "Safe"
    print("Static Analysis Summary")
    print("-----------------------")
    print(f"Input file: {input_path}")
    print(f"Output report: {output_path}")
    print(f"Overall status: {overall_status}")
    print(f"Total records: {total}")
    print(f"Safe: {safe}")
    print(f"Threat: {threats}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze a static CSV file for threats using the trained model."
    )
    parser.add_argument(
        "--input",
        required=True,
        type=str,
        help="Path to input CSV file with the same features as used for training.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path to save the output report CSV. If not provided, a timestamped file in the reports folder is used.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Probability threshold above which a record is classified as Threat.",
    )
    args = parser.parse_args()
    input_path = Path(args.input)
    if args.output is None:
        reports_dir = BASE_DIR / "reports"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = reports_dir / f"static_analysis_{timestamp}.csv"
    else:
        output_path = Path(args.output)
    analyze_file(input_path, output_path, threshold=args.threshold)


if __name__ == "__main__":
    main()
