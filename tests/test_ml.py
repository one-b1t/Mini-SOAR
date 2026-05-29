from minisoar.ml.inference import predict_block

def test_predict_block_fallback():
    event = {"alert": {"type": "alert_url_major", "count": 5, "severity": "high"}}
    # clean IP -> fallback output: pred=0, prob=0.05
    pred, prob = predict_block(event, "1.2.3.4", "none", False, "✅ Clean (0/100)", model_artifact=None)
    assert pred == 0
    assert prob == 0.05

    # malicious IP -> fallback output: pred=1, prob=0.95 (webshell or high rep)
    pred_mal, prob_mal = predict_block(event, "1.2.3.4", "none", False, "🛑 Malicious (95/100, 10 rep)", model_artifact=None)
    assert pred_mal == 1
    assert prob_mal == 0.95
