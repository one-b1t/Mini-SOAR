import os
from pathlib import Path
from minisoar.playbook import (
    ExecutionContext,
    PlaybookEngine,
    SafeExpressionEvaluator,
    evaluate_conditions,
    load_playbooks_from_dir,
)


def test_safe_condition_evaluator():
    ctx = {
        "ml_prob": 0.85,
        "reputation_score": 60,
        "whitelisted": False,
        "severity": "critical",
        "alert_type": "alert_webshell_immediate",
        "tags": ["alert_webshell_immediate", "urgent"],
    }

    assert SafeExpressionEvaluator.evaluate("not whitelisted", ctx) is True
    assert SafeExpressionEvaluator.evaluate("ml_prob >= 0.70", ctx) is True
    assert SafeExpressionEvaluator.evaluate("reputation_score >= 50", ctx) is True
    assert SafeExpressionEvaluator.evaluate("severity in ['high', 'critical']", ctx) is True
    assert SafeExpressionEvaluator.evaluate("'webshell' in alert_type", ctx) is True
    assert SafeExpressionEvaluator.evaluate("whitelisted or ml_prob < 0.50", ctx) is False

    # Disallowed syntax/AST safety
    assert SafeExpressionEvaluator.evaluate("__import__('os').system('ls')", ctx) is False


def test_load_default_playbooks():
    playbooks_dir = Path(__file__).parent.parent / "minisoar" / "playbooks"
    playbooks = load_playbooks_from_dir(playbooks_dir)
    assert len(playbooks) >= 4

    pb_ids = [p.id for p in playbooks]
    assert "pb-webshell-immediate" in pb_ids
    assert "pb-bruteforce-probing" in pb_ids
    assert "pb-web-injection" in pb_ids
    assert "pb-default-fallback" in pb_ids


def test_playbook_matching_and_execution(monkeypatch):
    os.environ["MINISOAR_MOCK"] = "1"
    monkeypatch.setattr("minisoar.playbook.actions.send_telegram", lambda *args, **kwargs: None)
    monkeypatch.setattr("minisoar.playbook.actions.store_label", lambda *args, **kwargs: None)
    monkeypatch.setattr("minisoar.utils.enrich_ip", lambda ip: ("🛑 Malicious (75/100)", "Indonesia, Jakarta, Telkom"))

    playbooks_dir = Path(__file__).parent.parent / "minisoar" / "playbooks"
    engine = PlaybookEngine(playbooks_dir=playbooks_dir)

    # 1. Webshell event
    event = {
        "alert": {
            "type": "alert_webshell_immediate",
            "server_name": "target.gov.id",
            "src_ip": "198.51.100.55",
            "severity": "critical",
        },
        "tags": ["alert_webshell_immediate"],
    }

    ctx = ExecutionContext(
        event=event,
        ip="198.51.100.55",
        website="target.gov.id",
        providers=["imperva"],
        mapped=True,
        whitelisted=False,
        bypassed=False,
        ml_prob=0.92,
        ml_label=1,
        reputation_score=75,
        rep_str="🛑 Malicious (75/100)",
        event_id="test_ev_001",
        redis_conn=None,
    )

    pb = engine.select_playbook(ctx)
    assert pb is not None
    assert pb.id == "pb-webshell-immediate"

    ok, pb_id = engine.execute(ctx)
    assert ok is True
    assert pb_id == "pb-webshell-immediate"
    assert "step_block_perimeter" in ctx.executed_steps


def test_playbook_fallback(monkeypatch):
    os.environ["MINISOAR_MOCK"] = "1"
    monkeypatch.setattr("minisoar.playbook.actions.send_telegram", lambda *args, **kwargs: None)
    monkeypatch.setattr("minisoar.playbook.actions.store_label", lambda *args, **kwargs: None)
    monkeypatch.setattr("minisoar.utils.enrich_ip", lambda ip: ("-", "-"))

    playbooks_dir = Path(__file__).parent.parent / "minisoar" / "playbooks"
    engine = PlaybookEngine(playbooks_dir=playbooks_dir)

    # Generic unclassified event
    event = {
        "alert": {
            "type": "alert_unclassified_anomaly",
            "server_name": "test.gov.id",
            "src_ip": "203.0.113.88",
            "severity": "low",
        },
        "tags": ["anomaly"],
    }

    ctx = ExecutionContext(
        event=event,
        ip="203.0.113.88",
        website="test.gov.id",
        providers=["imperva"],
        mapped=True,
        whitelisted=False,
        bypassed=False,
        ml_prob=0.10,
        ml_label=0,
        reputation_score=0,
        rep_str="",
        event_id="test_ev_fallback",
        redis_conn=None,
    )

    pb = engine.select_playbook(ctx)
    assert pb is not None
    assert pb.id == "pb-default-fallback"

    ok, pb_id = engine.execute(ctx)
    assert ok is True
    assert pb_id == "pb-default-fallback"

