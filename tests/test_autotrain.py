import os
from pathlib import Path
import tempfile
import pandas as pd

from minisoar.ml.autotrain import evaluate_and_promote_model
from minisoar.ml.inference import load_model_artifact, predict_block


def test_evaluate_and_promote_model():
    os.environ["MINISOAR_MOCK"] = "1"

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        # Create synthetic dataset with clear separable patterns
        data = {
            "reputation_score": [95, 90, 85, 80, 10, 5, 0, 92, 88, 2, 4, 98, 1, 99],
            "hit_count": [50, 40, 30, 20, 1, 2, 1, 35, 25, 1, 1, 60, 1, 45],
            "is_whitelisted": [0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0],
            "severity": ["high", "high", "medium", "high", "low", "low", "low", "high", "high", "low", "low", "high", "low", "high"],
            "detector_type": ["alert_webshell", "alert_webshell", "alert_sqli", "alert_webshell", "alert_scan", "alert_scan", "alert_scan", "alert_webshell", "alert_webshell", "alert_scan", "alert_scan", "alert_webshell", "alert_scan", "alert_webshell"],
            "perimeter_vendor": ["imperva", "paloalto", "akamai", "cloudflare", "imperva", "paloalto", "akamai", "cloudflare", "imperva", "paloalto", "akamai", "cloudflare", "imperva", "paloalto"],
            "label": [1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1],
        }
        df = pd.DataFrame(data)

        target_artifact = tmp_path / "test_active_model.joblib"
        ok, metrics, msg = evaluate_and_promote_model(df, active_artifact_path=target_artifact, min_auc_threshold=0.80)

        assert ok is True
        assert "SUCCESS" in msg
        assert target_artifact.exists()
        assert metrics["roc_auc"] >= 0.80

        # Test load_model_artifact hot-reloading
        loaded = load_model_artifact(target_artifact)
        assert loaded is not None
        assert "model" in loaded

        # Test predict_block with newly trained artifact
        pred, prob = predict_block(
            event={"alert": {"type": "alert_webshell", "count": 50, "severity": "high"}},
            ip="1.2.3.4",
            provider="imperva",
            whitelisted=False,
            rep_str="🛑 Reputation: 95",
            model_artifact=loaded,
        )
        assert pred == 1
        assert prob >= 0.5
