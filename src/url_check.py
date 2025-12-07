import argparse
from pathlib import Path
from typing import Dict

import joblib
import numpy as np
import pandas as pd

from .config import BASE_DIR


def _load_url_artifact():
    models_dir = BASE_DIR / "trained_models"
    artifact_path = models_dir / "url_model.joblib"
    if not artifact_path.exists():
        raise FileNotFoundError(
            f"Trained URL model artifact not found at {artifact_path}. Train it first with train_url_model.py."
        )
    return joblib.load(artifact_path)


def _risk_type(prob: float) -> str:
    if prob >= 0.9:
        return "Critical Malicious URL"
    if prob >= 0.75:
        return "High Malicious URL"
    if prob >= 0.5:
        return "Suspicious URL"
    if prob >= 0.3:
        return "Low Risk URL"
    return "Benign URL"


def check_single_url(url: str, threshold: float = 0.5) -> Dict[str, object]:
    artifact = _load_url_artifact()
    pipeline = artifact["pipeline"]
    proba = float(pipeline.predict_proba([url])[0, 1])
    label = int(proba >= threshold)
    return {
        "url": url,
        "malicious_probability": proba,
        "prediction_label": label,
        "prediction_text": "Malicious" if label == 1 else "Benign",
        "risk_type": _risk_type(proba),
    }


def analyze_url_csv(input_csv: Path, output_csv: Path, threshold: float = 0.5) -> None:
    artifact = _load_url_artifact()
    pipeline = artifact["pipeline"]
    df = pd.read_csv(input_csv)
    if "url" not in df.columns:
        raise ValueError("Input CSV must contain a 'url' column.")
    urls = df["url"].astype(str).tolist()
    probabilities = pipeline.predict_proba(urls)[:, 1]
    labels = (probabilities >= threshold).astype(int)
    df["malicious_probability"] = probabilities
    df["prediction_label"] = labels
    df["prediction_text"] = np.where(labels == 1, "Malicious", "Benign")
    df["risk_type"] = df["malicious_probability"].apply(_risk_type)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_csv, index=False)
    total = len(df)
    malicious = int((labels == 1).sum())
    benign = total - malicious
    print("URL Analysis Summary")
    print("--------------------")
    print(f"Input file: {input_csv}")
    print(f"Output report: {output_csv}")
    print(f"Total URLs: {total}")
    print(f"Benign: {benign}")
    print(f"Malicious: {malicious}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check single URLs or CSV files of URLs using the trained URL threat model.",
    )
    parser.add_argument("--url", type=str, help="Single URL to check.")
    parser.add_argument(
        "--input_csv",
        type=str,
        help="Path to CSV file with a 'url' column for batch analysis.",
    )
    parser.add_argument(
        "--output_csv",
        type=str,
        help="Where to save the batch analysis report CSV (required with --input_csv).",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Probability threshold above which a URL is classified as malicious.",
    )
    args = parser.parse_args()

    if args.url is None and args.input_csv is None:
        raise SystemExit("Provide either --url or --input_csv.")

    if args.url is not None:
        result = check_single_url(args.url, threshold=args.threshold)
        print("Single URL Check Result")
        print("-----------------------")
        for key, value in result.items():
            print(f"{key}: {value}")

    if args.input_csv is not None:
        if args.output_csv is None:
            raise SystemExit("--output_csv is required when using --input_csv.")
        analyze_url_csv(Path(args.input_csv), Path(args.output_csv), threshold=args.threshold)


if __name__ == "__main__":
    main()
