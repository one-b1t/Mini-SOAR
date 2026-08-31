import sys
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from minisoar.ml.inference import predict_block


event = {
    "alert": {"type": "alert_url_major", "src_ip": "1.2.3.4", "count": 5, "severity": "high"},
    "server_name": "example.com",
}

print("--- Testing ML Prediction ---")
pred_clean, prob_clean = predict_block(event, "1.2.3.4", "none", False, "✅ Clean (0/100)", model_artifact=None)
print("1. Clean IP (0/100)       -> Prediction:", pred_clean, "Prob:", prob_clean)

pred_mal, prob_mal = predict_block(event, "1.2.3.4", "none", False, "🛑 Malicious (95/100, 10 rep)", model_artifact=None)
print("2. Malicious IP (95/100)  -> Prediction:", pred_mal, "Prob:", prob_mal)
