from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split


def train_baseline(csv_path: Path | None = None, artifact_path: Path | None = None) -> None:
    root_dir = Path(__file__).resolve().parent.parent.parent
    if csv_path is None:
        csv_path = root_dir / "dataset.csv"
    if artifact_path is None:
        artifact_path = root_dir / "baseline_model.joblib"

    if not csv_path.exists():
        raise FileNotFoundError(f"dataset.csv not found at {csv_path}. Please run export_dataset.py first.")

    df = pd.read_csv(csv_path)
    print(f"Loaded dataset: {df.shape[0]} rows, {df.shape[1]} columns.")

    severity_map = {"low": 0, "medium": 1, "high": 2}
    df["severity_encoded"] = df["severity"].map(severity_map).fillna(1)

    x_numeric = df[["reputation_score", "hit_count", "is_whitelisted", "severity_encoded"]].copy()
    x_categorical = pd.get_dummies(df[["detector_type", "perimeter_vendor"]], dtype=int)

    x = pd.concat([x_numeric, x_categorical], axis=1)
    y = df["label"]

    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42, stratify=y)

    model = LogisticRegression(max_iter=1000, random_state=42)
    model.fit(x_train, y_train)

    y_pred = model.predict(x_test)
    y_prob = model.predict_proba(x_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)

    print(f"Accuracy: {acc:.4f}")
    print(f"ROC-AUC: {auc:.4f}")

    cm = confusion_matrix(y_test, y_pred)
    print(f"Confusion Matrix: [[TN={cm[0][0]} FP={cm[0][1]}] [FN={cm[1][0]} TP={cm[1][1]}]]")
    print(classification_report(y_test, y_pred, target_names=["Allow/Ignore (0)", "Block (1)"]))

    model_artifact = {
        "model": model,
        "feature_columns": list(x.columns),
        "severity_map": severity_map,
        "trained_date": pd.Timestamp.now().isoformat(),
    }
    joblib.dump(model_artifact, artifact_path)
    print(f"Trained baseline model saved to {artifact_path}")


def main():
    train_baseline()


if __name__ == "__main__":
    main()
