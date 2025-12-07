import io
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import streamlit as st

from src.config import BASE_DIR


@st.cache_resource
def load_artifact():
    models_dir = BASE_DIR / "trained_models"
    artifact_path = models_dir / "xgb_classifier.joblib"
    if not artifact_path.exists():
        raise FileNotFoundError(
            f"Trained model artifact not found at {artifact_path}. Train the model first using train_classifier.py."
        )
    artifact = joblib.load(artifact_path)
    return artifact


def inject_cyber_theme() -> None:
    st.markdown(
        """
        <style>
        .stApp {
            background: radial-gradient(circle at 0% 0%, #020617 0, #020617 40%, #000000 100%);
            background-image: linear-gradient(135deg, #020617 0%, #020617 35%, #0f172a 50%, #020617 65%, #020617 100%);
            background-size: 400% 400%;
            animation: gradientMove 24s ease infinite;
            color: #e5e7eb;
        }

        @keyframes gradientMove {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }

        .main .block-container {
            padding-top: 2.5rem;
            padding-bottom: 2.5rem;
            max-width: 1200px;
        }

        .neon-title {
            font-family: 'Segoe UI', system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
            font-weight: 700;
            font-size: 2.2rem;
            text-align: left;
            color: #38bdf8;
            text-shadow: 0 0 12px rgba(56, 189, 248, 0.8),
                         0 0 32px rgba(59, 130, 246, 0.7);
            margin-bottom: 0.35rem;
        }

        .subtitle {
            font-size: 0.95rem;
            color: #9ca3af;
            margin-bottom: 1.7rem;
        }

        div[data-testid="stFileUploader"] > div:first-child {
            background: linear-gradient(135deg, rgba(15,23,42,0.96), rgba(15,23,42,0.85));
            border-radius: 14px;
            border: 1px dashed rgba(56,189,248,0.7);
            padding: 1.25rem;
            box-shadow: 0 0 35px rgba(8, 47, 73, 0.8);
        }

        div[data-testid="stMetric"] {
            background: radial-gradient(circle at 0 0, rgba(56,189,248,0.3), rgba(8,47,73,0.9));
            border-radius: 16px;
            padding: 1rem 1.1rem;
            box-shadow: 0 0 26px rgba(15,118,110,0.7);
            border: 1px solid rgba(45,212,191,0.5);
        }

        div[data-testid="stMetric"] > label {
            color: #a5b4fc;
        }

        div[data-testid="stMetric"] > div {
            color: #e5e7eb;
        }

        .stDataFrame {
            background: rgba(15,23,42,0.98);
            border-radius: 16px;
            border: 1px solid rgba(30,64,175,0.9);
            box-shadow: 0 0 28px rgba(30,64,175,0.75);
        }

        .stDataFrame table {
            color: #e5e7eb;
        }

        .stSlider > div > div > div {
            background: linear-gradient(90deg, #22c55e, #eab308, #f97316, #ef4444);
        }

        .stButton > button, .stDownloadButton > button {
            background: linear-gradient(135deg, #22c55e, #22d3ee, #6366f1);
            border-radius: 999px;
            border: none;
            color: #020617;
            padding: 0.55rem 1.4rem;
            font-weight: 600;
            box-shadow: 0 0 20px rgba(56,189,248,0.65);
            transition: transform 0.15s ease, box-shadow 0.15s ease, filter 0.15s ease;
        }

        .stButton > button:hover, .stDownloadButton > button:hover {
            transform: translateY(-1px) scale(1.02);
            filter: brightness(1.08);
            box-shadow: 0 0 30px rgba(56,189,248,0.95);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def main() -> None:
    st.set_page_config(page_title="AI Cyber Threat Analyzer", layout="wide")
    inject_cyber_theme()

    st.markdown(
        "<h1 class='neon-title'>AI-Based Cyber Security Threats Prediction Agent</h1>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "<p class='subtitle'>Upload a CSV file with network features to analyze potential threats.</p>",
        unsafe_allow_html=True,
    )

    artifact = load_artifact()
    model = artifact["model"]
    scaler = artifact["scaler"]
    features = artifact["features"]

    uploaded_file = st.file_uploader("Upload CSV file", type=["csv"])

    threshold = st.slider(
        "Threat probability threshold", min_value=0.1, max_value=0.9, value=0.5, step=0.05
    )

    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        missing = [f for f in features if f not in df.columns]
        if missing:
            st.error(
                "The uploaded file is missing required feature columns: "
                + ", ".join(missing)
            )
            return

        X_raw = df[features].values
        X_scaled = scaler.transform(X_raw)

        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(X_scaled)[:, 1]
        else:
            scores = model.decision_function(X_scaled)
            probs = (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)

        labels = (probs >= threshold).astype(int)
        df_result = df.copy()
        df_result["threat_probability"] = probs
        df_result["prediction_label"] = labels
        df_result["prediction_text"] = np.where(labels == 1, "Threat", "Safe")

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

        df_result["risk_type"] = df_result["threat_probability"].apply(risk_type)

        total = len(df_result)
        threats = int((labels == 1).sum())
        safe = total - threats
        overall_status = "Threats Detected" if threats > 0 else "Safe"

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Overall Status", overall_status)
        with col2:
            st.metric("Total Records", total)
        with col3:
            st.metric("Threat Records", threats)

        st.subheader("Sample Predictions")
        st.dataframe(df_result.head(50))

        csv_buffer = io.StringIO()
        df_result.to_csv(csv_buffer, index=False)
        st.download_button(
            label="Download Full Report as CSV",
            data=csv_buffer.getvalue(),
            file_name="threat_analysis_report.csv",
            mime="text/csv",
        )


if __name__ == "__main__":
    main()
