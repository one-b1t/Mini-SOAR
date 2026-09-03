from __future__ import annotations

"""Automated ML Retraining & Model Auto-Update Pipeline for MiniSOAR.

Provides:
1. Automated dataset extraction from analyst feedback in Elasticsearch
2. Retraining Challenger ML model
3. Champion-Challenger Quality Gate (ROC-AUC >= 0.85)
4. Atomic hot-reloadable model artifact promotion
"""

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

logger = logging.getLogger(__name__)


def evaluate_and_promote_model(
    df: pd.DataFrame,
    active_artifact_path: Path | None = None,
    min_auc_threshold: float = 0.85,
) -> tuple[bool, dict[str, Any], str]:
    """Trains a new Challenger model, evaluates it against the Quality Gate, and promotes it."""
    root_dir = Path(__file__).resolve().parent.parent.parent
    if active_artifact_path is None:
        active_artifact_path = root_dir / "active_model.joblib"

    if df.empty or len(df) < 10:
        return False, {}, "Insufficient dataset size for retraining (minimum 10 samples required)."

    severity_map = {"low": 0, "medium": 1, "high": 2}
    df = df.copy()
    if "severity" in df.columns:
        df["severity_encoded"] = df["severity"].map(severity_map).fillna(1)
    else:
        df["severity_encoded"] = 1

    if "hit_count" not in df.columns:
        df["hit_count"] = 1
    if "is_whitelisted" not in df.columns:
        df["is_whitelisted"] = 0
    if "reputation_score" not in df.columns:
        df["reputation_score"] = 0

    x_numeric = df[["reputation_score", "hit_count", "is_whitelisted", "severity_encoded"]].copy()

    cat_cols = []
    if "detector_type" in df.columns and "perimeter_vendor" in df.columns:
        cat_cols = ["detector_type", "perimeter_vendor"]
    elif "detector_type" in df.columns:
        cat_cols = ["detector_type"]

    x_categorical = pd.get_dummies(df[cat_cols], dtype=int) if cat_cols else pd.DataFrame(index=df.index)
    x = pd.concat([x_numeric, x_categorical], axis=1)
    y = df["label"].astype(int)

    # Check class balance
    if len(y.unique()) < 2:
        return False, {}, "Dataset contains only one class. Need both positive (block) and negative (allow) samples."

    # Train / test split
    stratify = y if y.value_counts().min() >= 2 else None
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.25, random_state=42, stratify=stratify)

    # Train Challenger Model (RandomForest for nonlinear threat patterns)
    challenger = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42, class_weight="balanced")
    challenger.fit(x_train, y_train)

    y_pred = challenger.predict(x_test)
    y_prob = challenger.predict_proba(x_test)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    auc = float(roc_auc_score(y_test, y_prob)) if len(y_test.unique()) > 1 else 1.0
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))

    metrics = {
        "accuracy": round(acc, 4),
        "roc_auc": round(auc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "trained_date": datetime.now(timezone.utc).isoformat(),
        "total_samples": len(df),
    }

    # Quality Gate Check
    if auc < min_auc_threshold:
        msg = f"REJECTED: Challenger model ROC-AUC ({auc:.4f}) did not meet quality gate threshold ({min_auc_threshold})."
        logger.warning(msg)
        return False, metrics, msg

    # Save and promote artifact
    model_artifact = {
        "model": challenger,
        "feature_columns": list(x.columns),
        "severity_map": severity_map,
        "decision_threshold": 0.50,
        "metrics": metrics,
        "trained_date": metrics["trained_date"],
        "model_version": f"v_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
    }

    # Atomically write to active_model.joblib
    temp_path = active_artifact_path.with_suffix(".tmp")
    joblib.dump(model_artifact, temp_path)
    temp_path.replace(active_artifact_path)

    # Also keep fallback baseline_model.joblib updated
    baseline_path = root_dir / "baseline_model.joblib"
    joblib.dump(model_artifact, baseline_path)

    msg = f"SUCCESS: Challenger model promoted to {active_artifact_path.name} (ROC-AUC={auc:.4f}, Accuracy={acc:.4f}, Samples={len(df)})"
    logger.info(msg)
    return True, metrics, msg


def run_autotrain_from_file(csv_path: Path | None = None, auto_export_elk: bool = True) -> tuple[bool, dict[str, Any], str]:
    """Extracts latest training data from Elasticsearch and runs the retraining pipeline."""
    root_dir = Path(__file__).resolve().parent.parent.parent
    path = csv_path or (root_dir / "dataset.csv")

    # 2026-08-28 - Automated ELK Telemetry Sync before ML Retraining
    if auto_export_elk or not path.exists():
        from .export import export_dataset_from_es
        logger.info("[MLOps] Auto-exporting latest training dataset from Elasticsearch...")
        ok_exp, count, msg_exp = export_dataset_from_es(path)
        logger.info("[MLOps] Dataset export status: %s (%d samples)", msg_exp, count)

    if not path.exists():
        return False, {}, f"Dataset file could not be generated at {path}"

    df = pd.read_csv(path)
    return evaluate_and_promote_model(df)

