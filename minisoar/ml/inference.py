from __future__ import annotations

from pathlib import Path
import logging

import joblib
import pandas as pd

from ..config import norm_provider
from ..utils import extract_reputation_score

logger = logging.getLogger(__name__)


def load_model_artifact(model_path: Path | None = None):
    path = model_path or (Path.cwd() / "baseline_model.joblib")
    if not path.exists():
        logger.warning("baseline_model.joblib not found. Fallback heuristic will be used.")
        return None
    try:
        artifact = joblib.load(path)
        logger.info("Loaded baseline model trained at %s", artifact.get("trained_date"))
        return artifact
    except Exception as e:
        logger.error("Failed to load baseline model: %s", e)
        return None


def predict_block(event: dict, ip: str, provider: str, whitelisted: bool, rep_str: str, model_artifact=None) -> tuple[int, float]:
    """Predict whether to block the IP.

    Returns: (predicted_label, probability_score)
    """

    rep_score = extract_reputation_score(rep_str)

    if not model_artifact:
        detector_type = (event.get("alert") or {}).get("type") or "alert_generic"
        if detector_type == "alert_webshell_immediate" or rep_score >= 80:
            return 1, 0.95
        return 0, 0.05

    model = model_artifact["model"]
    feature_columns = model_artifact["feature_columns"]
    severity_map = model_artifact.get("severity_map", {"low": 0, "medium": 1, "high": 2})

    hit_count = int((event.get("alert") or {}).get("count") or event.get("count") or 1)
    is_whitelisted = 1 if whitelisted else 0
    severity = (event.get("alert") or {}).get("severity") or (event.get("alert") or {}).get("severity_hint") or "medium"
    severity_encoded = severity_map.get(str(severity).lower(), 1)

    detector_type = (event.get("alert") or {}).get("type") or "alert_generic"
    perimeter_vendor = norm_provider(provider)

    row = {}
    for col in feature_columns:
        if col == "reputation_score":
            row[col] = rep_score
        elif col == "hit_count":
            row[col] = hit_count
        elif col == "is_whitelisted":
            row[col] = is_whitelisted
        elif col == "severity_encoded":
            row[col] = severity_encoded
        elif col.startswith("detector_type_"):
            row[col] = 1 if col == f"detector_type_{detector_type}" else 0
        elif col.startswith("perimeter_vendor_"):
            row[col] = 1 if col == f"perimeter_vendor_{perimeter_vendor}" else 0
        else:
            row[col] = 0

    try:
        df_input = pd.DataFrame([row], columns=feature_columns)
        pred = int(model.predict(df_input)[0])
        prob = float(model.predict_proba(df_input)[0][1])
        return pred, prob
    except Exception as e:
        logger.warning("Inference error, fallback heuristic used: %s", e)
        if detector_type == "alert_webshell_immediate" or rep_score >= 80:
            return 1, 0.95
        return 0, 0.05
