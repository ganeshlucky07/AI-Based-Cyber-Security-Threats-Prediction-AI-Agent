import joblib
from xgboost import XGBClassifier
from sklearn.metrics import classification_report

from .data_pipeline import build_train_test
from .config import BASE_DIR


def train_classifier() -> None:
    X_train, X_test, y_train, y_test, feature_names, scaler = build_train_test()
    model = XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="binary:logistic",
        tree_method="hist",
        eval_metric="logloss",
    )
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred)
    print(report)
    models_dir = BASE_DIR / "trained_models"
    models_dir.mkdir(parents=True, exist_ok=True)
    artifact = {
        "model": model,
        "scaler": scaler,
        "features": feature_names,
        "report": report,
    }
    joblib.dump(artifact, models_dir / "xgb_classifier.joblib")


if __name__ == "__main__":
    train_classifier()
