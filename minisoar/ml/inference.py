from __future__ import annotations

from pathlib import Path
import logging

import joblib
import pandas as pd

from ..config import norm_provider
from ..utils import extract_reputation_score

logger = logging.getLogger(__name__)


_CACHED_MODEL_ARTIFACT = None
_CACHED_MODEL_MTIME: float = 0.0


def load_model_artifact(model_path: Path | None = None):
    """Loads model artifact with automatic zero-downtime hot-reloading on file modification."""
    global _CACHED_MODEL_ARTIFACT, _CACHED_MODEL_MTIME

    candidates = [
        model_path,
        Path.cwd() / "active_model.joblib",
        Path.cwd() / "baseline_model.joblib",
        Path(__file__).resolve().parent.parent.parent / "active_model.joblib",
        Path(__file__).resolve().parent.parent.parent / "baseline_model.joblib",
    ]

    target_path: Path | None = None
    for cand in candidates:
        if cand and cand.exists():
            target_path = cand
            break

    if not target_path or not target_path.exists():
        logger.warning("No active_model.joblib or baseline_model.joblib found. Fallback heuristic will be used.")
        return None

    try:
        current_mtime = target_path.stat().st_mtime
        if _CACHED_MODEL_ARTIFACT is not None and current_mtime == _CACHED_MODEL_MTIME:
            return _CACHED_MODEL_ARTIFACT

        artifact = joblib.load(target_path)
        _CACHED_MODEL_ARTIFACT = artifact
        _CACHED_MODEL_MTIME = current_mtime
        logger.info("Loaded/Hot-reloaded model artifact from %s (trained: %s)", target_path.name, artifact.get("trained_date"))
        return artifact
    except Exception as e:
        logger.error("Failed to load model from %s: %s", target_path, e)
        return _CACHED_MODEL_ARTIFACT


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
