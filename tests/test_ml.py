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


def test_predict_block_whitelisted():
    event = {"alert": {"type": "alert_url_major", "count": 5, "severity": "high"}}
    pred, prob = predict_block(event, "10.2.57.246", "imperva", True, "🛑 Malicious (95/100, 10 rep)", model_artifact=None)
    assert pred == 1
    assert prob == 0.95


def test_securesphere_normalization():
    from minisoar.ml.export import (
        estimate_securesphere_reputation,
        normalize_securesphere_detector,
        normalize_securesphere_severity,
    )

    # Test detector normalizations
    assert normalize_securesphere_detector("SQL injection on parameter id", "Web Policy") == "alert_sqli"
    assert normalize_securesphere_detector("Cross-site scripting", "Web Policy") == "alert_xss"
    assert normalize_securesphere_detector("WebShell execution detected", "Web Policy") == "alert_webshell"
    assert normalize_securesphere_detector("Directory traversal attempt", "Web Policy") == "alert_dir_traversal"
    assert normalize_securesphere_detector("Unauthorized Method POST", "Web Profile Policy") == "alert_web_profile"
    assert normalize_securesphere_detector("Generic threat", "Web Correlation Policy") == "alert_web_correlation"
    assert normalize_securesphere_detector("Scanner detected", "Rule") == "alert_url_probe"
    assert normalize_securesphere_detector("Unknown rule", "Custom") == "alert_securesphere_waf"

    # Test severity normalizations
    assert normalize_securesphere_severity("High") == "high"
    assert normalize_securesphere_severity("Critical") == "high"
    assert normalize_securesphere_severity("7") == "high"
    assert normalize_securesphere_severity("Low") == "low"
    assert normalize_securesphere_severity("Medium") == "medium"

    # Test reputation estimation
    assert estimate_securesphere_reputation("high", "Block") >= 80
    assert estimate_securesphere_reputation("low", "None") <= 20


def test_train_baseline_7_steps_workflow():
    import tempfile
    from pathlib import Path
    import pandas as pd
    from minisoar.ml.train import train_baseline

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        csv_file = tmp_path / "test_dataset_7step.csv"
        art_file = tmp_path / "test_baseline_model.joblib"

        # Create balanced dataset mimicking MiniSOAR + SecureSphere data
        rows = []
        for i in range(100):
            # Class 1 (Block)
            rows.append({
                "event_id": f"sec_blk_{i}",
                "detector_type": "alert_sqli" if i % 2 == 0 else "alert_webshell",
                "severity": "high",
                "reputation_score": 90,
                "hit_count": 10,
                "perimeter_vendor": "imperva",
                "is_whitelisted": 0,
                "source_ip": f"1.1.1.{i}",
                "destination_ip": "10.0.0.1",
                "domain": "target.internal",
                "url_path": "/api",
                "source_port": 1234,
                "target_port": 80,
                "label": 1,
            })
            # Class 0 (Allow/None)
            rows.append({
                "event_id": f"sec_alw_{i}",
                "detector_type": "alert_url_probe" if i % 2 == 0 else "alert_web_profile",
                "severity": "low",
                "reputation_score": 10,
                "hit_count": 1,
                "perimeter_vendor": "imperva",
                "is_whitelisted": 0,
                "source_ip": f"2.2.2.{i}",
                "destination_ip": "10.0.0.1",
                "domain": "target.internal",
                "url_path": "/index",
                "source_port": 5678,
                "target_port": 80,
                "label": 0,
            })
        df = pd.DataFrame(rows)
        df.to_csv(csv_file, index=False)

        artifact = train_baseline(csv_path=csv_file, artifact_path=art_file, auto_export_if_missing=False)

        assert artifact is not None
        assert art_file.exists()
        assert "model" in artifact
        assert "decision_threshold" in artifact
        assert "cv_scores" in artifact
        assert artifact["metrics"]["roc_auc"] >= 0.85
        assert artifact["metrics"]["f1_score"] >= 0.85

        # Test inference with the newly trained artifact and decision threshold
        pred_blk, prob_blk = predict_block(
            event={"alert": {"type": "alert_sqli", "count": 10, "severity": "high"}},
            ip="1.1.1.5",
            provider="imperva",
            whitelisted=False,
            rep_str="🛑 Malicious (90/100, 10 rep)",
            model_artifact=artifact,
        )
        assert pred_blk == 1
        assert prob_blk >= artifact["decision_threshold"]

        pred_alw, prob_alw = predict_block(
            event={"alert": {"type": "alert_url_probe", "count": 1, "severity": "low"}},
            ip="2.2.2.5",
            provider="imperva",
            whitelisted=False,
            rep_str="✅ Clean (10/100, 0 rep)",
            model_artifact=artifact,
        )
        assert pred_alw == 0


def test_securesphere_attack_replay_validation():
    from minisoar.ml.replay import (
        build_mimicked_soar_event,
        categorize_attack,
        validate_model_against_attacks,
    )

    # 1. Test Attack Categorization
    assert categorize_attack("SQL injection", "Web Policy", "param id") == "SQL Injection (SQLi)"
    assert categorize_attack("Cross-site scripting", "Web Policy", "<script>") == "Cross-Site Scripting (XSS)"
    assert categorize_attack("HTTP Signature Violation", "Policy", "Distributed Generic protection for php code injection") == "Remote Code Execution / WebShell"
    assert categorize_attack("Directory Traversal", "Policy", "../../../etc/passwd") == "Directory / Path Traversal"
    assert categorize_attack("Unauthorized Method", "Web Profile Policy", "POST") == "Web Profile / Policy Violation"
    assert categorize_attack("Web Leech", "Policy", "Crawler") == "Reconnaissance / Web Leech"
    assert categorize_attack("Illegal Content Length", "Policy", "0") == "HTTP Protocol / Header Violation"

    # 2. Test Mimicked Event Construction
    sample_log = {
        "@timestamp": "2026-09-03T10:00:00.000Z",
        "source": {"ip": "198.51.100.77", "port": 45678},
        "destination": {"ip": "172.30.103.45", "port": 443},
        "message": "SQL injection",
        "rule": {"name": "Web Correlation Policy"},
        "event": {"id": "999888777", "action": "Block", "severity": 7},
        "imperva": {
            "securesphere": {
                "application": {"name": "portal.komdigi.go.id"},
                "violation": {"description": "SQL injection on parameter user in /login"},
                "severity": "High",
            }
        },
    }

    event = build_mimicked_soar_event(sample_log)
    assert event["detector_type"] == "alert_sqli"
    assert event["attack_category"] == "SQL Injection (SQLi)"
    assert event["alert"]["src_ip"] == "198.51.100.77"
    assert event["alert"]["server_name"] == "portal.komdigi.go.id"
    assert event["alert"]["reputation_score"] >= 80

    # 3. Test Attack Validation Runner against Model Artifact
    mock_attacks = [
        sample_log,
        {
            "@timestamp": "2026-09-03T10:01:00.000Z",
            "source": {"ip": "198.51.100.88", "port": 51234},
            "destination": {"ip": "172.30.103.45", "port": 443},
            "message": "Cross-site scripting",
            "rule": {"name": "Web Correlation Policy"},
            "event": {"id": "999888778", "action": "Block", "severity": 7},
            "imperva": {
                "securesphere": {
                    "application": {"name": "data.komdigi.go.id"},
                    "violation": {"description": "Cross-site scripting in /search?q=<script>"},
                    "severity": "High",
                }
            },
        },
    ]

    report = validate_model_against_attacks(mock_attacks, model_artifact=None)
    assert report["total_attacks_tested"] == 2
    assert report["total_detected_blocks"] == 2
    assert report["overall_detection_rate_pct"] == 100.0
    assert "SQL Injection (SQLi)" in report["category_summary"]
    assert "Cross-Site Scripting (XSS)" in report["category_summary"]




# ---------------------------------------------
# Tier 3: Case Management & Ticketing Tests
# ---------------------------------------------
def test_case_lifecycle_and_sla():
    import os
    from minisoar import cases

    os.environ["MINISOAR_MOCK"] = "1"

    # 1. Create a new incident case
    case = cases.create_case(
        title="Suspicious SQL Injection attempt on portal",
        severity="critical",
        description="Detected anomalous query pattern on login endpoint.",
        attacker_ip="185.220.101.5",
        target_asset="portal.internal.gov.id",
        source_event_id="ev-test-9901",
        tags=["sqli", "priority"],
        creator="soc_playbook",
        sync_to_thehive=True,
        sync_to_jira=True,
    )

    assert case.case_id.startswith("CASE-")
    assert case.status == cases.CaseStatus.NEW.value
    assert case.severity == "critical"
    assert case.mttd_seconds > 0
    assert "thehive" in case.external_tickets
    assert "jira" in case.external_tickets

    # 2. Transition status: INVESTIGATING
    ok_inv, msg_inv, case_inv = cases.update_case_status(case.case_id, "INVESTIGATING", actor="@analyst_john", notes="Reviewing server logs.")
    assert ok_inv is True
    assert case_inv.status == cases.CaseStatus.INVESTIGATING.value

    # 3. Transition status: CONTAINED
    ok_cont, msg_cont, case_cont = cases.update_case_status(case.case_id, "CONTAINED", actor="@analyst_john", notes="Attacker IP blocked on Imperva & Cloudflare.")
    assert ok_cont is True
    assert case_cont.status == cases.CaseStatus.CONTAINED.value

    # 4. Resolve case and verify MTTR
    ok_res, msg_res, case_res = cases.update_case_status(case.case_id, "RESOLVED", actor="@lead_soc", notes="Verified patched endpoint.")
    assert ok_res is True
    assert case_res.status == cases.CaseStatus.RESOLVED.value
    assert case_res.closed_at is not None
    assert case_res.mttr_seconds >= 0.0

    # 5. Retrieve case
    fetched = cases.get_case(case.case_id)
    assert fetched is not None
    assert fetched.case_id == case.case_id

    # 6. List cases
    all_cases = cases.list_cases()
    assert len(all_cases) >= 1
    resolved_cases = cases.list_cases(status="RESOLVED")
    assert any(c.case_id == case.case_id for c in resolved_cases)


def test_soc_metrics_calculation():
    from minisoar import cases

    metrics = cases.get_soc_metrics()
    assert "total_cases" in metrics
    assert "status_distribution" in metrics
    assert "severity_distribution" in metrics
    assert "avg_mttd_seconds" in metrics
    assert "avg_mttr_seconds" in metrics


def test_case_report_generators():
    from minisoar import cases

    case = cases.create_case(
        title="SQL Injection attempt on auth portal",
        severity="high",
        description="Union select payload detected.",
        attacker_ip="198.51.100.44",
        target_asset="auth.internal.gov.id",
    )

    md_report = cases.generate_case_markdown_report(case)
    assert "# 🛡️ Incident Investigation Report" in md_report
    assert case.case_id in md_report
    assert "198.51.100.44" in md_report

    html_report = cases.generate_case_html_report(case)
    assert "<!DOCTYPE html>" in html_report
    assert case.case_id in html_report
    assert "MiniSOAR Incident Investigation Report" in html_report


def test_thehive_and_jira_connectors_mock():
    import os
    from minisoar import cases

    os.environ["MINISOAR_MOCK"] = "1"

    # 1. TheHive
    ok_th, msg_th, data_th = cases.create_thehive_case(
        title="TheHive Test Incident",
        description="Test description",
        severity=3,
        observables=[{"type": "ip", "value": "10.10.10.10"}],
    )
    assert ok_th is True
    assert "TheHive case created" in msg_th

    # 2. Jira
    ok_jira, msg_jira, data_jira = cases.create_jira_issue(
        summary="Jira Test Issue",
        description="Test description",
    )
    assert ok_jira is True
    assert "Jira issue created" in msg_jira

    # 3. ServiceNow
    ok_snow, msg_snow, data_snow = cases.create_servicenow_incident(
        short_description="ServiceNow Test Incident",
        description="Test description",
    )
    assert ok_snow is True
    assert "ServiceNow incident created" in msg_snow

    # 4. Generic Webhook
    ok_wh, msg_wh = cases.send_generic_webhook({"test": "data"}, webhook_url="http://mock-webhook")
    assert ok_wh is True

    # 5. Optional Dispatcher (Auto-routed based on TICKETING_PROVIDER)
    os.environ["TICKETING_PROVIDER"] = "servicenow"
    ok_disp, msg_disp, data_disp = cases.dispatch_external_ticket(
        title="Automated Dispatch Test",
        description="Automated description",
        severity="high",
    )
    assert ok_disp is True
    assert data_disp["provider"] == "servicenow"

    # 6. Disabled state (TICKETING_PROVIDER=none)
    os.environ["TICKETING_PROVIDER"] = "none"
    ok_none, msg_none, _ = cases.dispatch_external_ticket(
        title="Disabled Ticketing Test",
        description="Should skip gracefully",
    )
    assert ok_none is False
    assert "disabled or not configured" in msg_none


# ---------------------------------------------
# Tier 5: AI SOC Copilot Tests
# ---------------------------------------------
def test_ai_copilot_mock():
    import os
    from minisoar import ai

    os.environ["MINISOAR_MOCK"] = "1"

    # 1. Payload analysis
    payload = "GET /api/v1/users?search=admin%27%20OR%201=1-- HTTP/1.1"
    analysis = ai.analyze_payload(payload)
    assert len(analysis) > 50
    assert "Threat Classification" in analysis or "AI SOC Copilot" in analysis

    # 2. RCA generation
    rca = ai.generate_rca("185.220.101.5")
    assert len(rca) > 50

    # 3. Mitigation recommendations
    recs = ai.recommend_mitigation({"alert": {"type": "alert_webshell_immediate", "src_ip": "1.2.3.4"}})
    assert len(recs) > 50

    # 4. Interactive Q&A
    ans = ai.ask_copilot("Bagaimana cara menganalisis serangan SQL Injection?")
    assert len(ans) > 50


def test_ai_auth_file_resolution():
    import json
    import os
    from pathlib import Path
    import tempfile
    from minisoar import ai

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Test 1: JSON auth file
        json_file = Path(tmp_dir) / "gemini_auth.json"
        json_file.write_text(json.dumps({"api_key": "ai-secret-key-123456", "provider": "gemini"}))

        os.environ["GEMINI_AUTH_FILE"] = str(json_file)
        os.environ.pop("GEMINI_API_KEY", None)

        tok, source = ai.resolve_auth_credential("gemini")
        assert tok == "ai-secret-key-123456"
        assert "file:" in source

        # Test 2: Raw text file for Claude
        claude_file = Path(tmp_dir) / "claude_token.txt"
        claude_file.write_text("sk-ant-test-token-789")

        os.environ["CLAUDE_AUTH_FILE"] = str(claude_file)
        os.environ.pop("ANTHROPIC_API_KEY", None)

        tok_c, source_c = ai.resolve_auth_credential("claude")
        assert tok_c == "sk-ant-test-token-789"
        assert "file:" in source_c

        # Test 3: Check auth info metadata
        info = ai.get_auth_info()
        assert "provider" in info
        assert "configured" in info

        # Test 4: Dynamic model & provider switching
        ai.set_active_model("gemini-2.0-flash")
        assert os.environ.get("AI_MODEL") == "gemini-2.0-flash"

        ai.set_active_provider("claude")
        assert ai.get_auth_info()["provider"] == "claude"


def test_ai_headless_cli_and_json_output():
    import os
    from minisoar import ai

    os.environ["MINISOAR_MOCK"] = "1"
    os.environ["AI_EXECMODE"] = "headless"

    res_json = ai.call_llm_json("Analisis payload", "System prompt")
    assert isinstance(res_json, dict)
    assert res_json.get("status") == "success"
    assert "threat_classification" in res_json

    payload_res = ai.analyze_payload_json("SELECT * FROM users WHERE 1=1")
    assert isinstance(payload_res, dict)
    assert "severity" in payload_res

    rca_res = ai.generate_rca_json("evt_1001")
    assert isinstance(rca_res, dict)
    assert "status" in rca_res




