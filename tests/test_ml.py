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




