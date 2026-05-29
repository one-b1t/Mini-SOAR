import sys, os, importlib.util
from pathlib import Path

# 2026-05-26 - Add project root to sys.path to resolve dependencies correctly
root_dir = str(Path(__file__).resolve().parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

module_path = str(Path(root_dir) / "14_redis_telegram_alert.py")
spec = importlib.util.spec_from_file_location("alert_module", module_path)
alert = importlib.util.module_from_spec(spec)
spec.loader.exec_module(alert)

event = {
    "alert": {"type": "alert_url_major", "src_ip": "1.2.3.4", "count": 5, "severity": "high"},
    "server_name": "example.com"
}

print("--- Testing ML Prediction ---")
pred_clean, prob_clean = alert.predict_block(event, "1.2.3.4", "none", False, "✅ Clean (0/100)")
print("1. Clean IP (0/100)       -> Prediction:", pred_clean, "Prob:", prob_clean)

pred_mal, prob_mal = alert.predict_block(event, "1.2.3.4", "none", False, "🛑 Malicious (95/100, 10 rep)")
print("2. Malicious IP (95/100)  -> Prediction:", pred_mal, "Prob:", prob_mal)

