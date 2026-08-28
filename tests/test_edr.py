from __future__ import annotations

import os
from pathlib import Path

from minisoar.edr import (
    add_edr_ioc,
    check_all_edr_connectivity,
    isolate_endpoint,
    kaspersky,
    query_endpoint,
    restore_endpoint,
    trendmicro,
)
from minisoar.playbook import ExecutionContext, PlaybookEngine, load_playbooks_from_dir


def test_trendmicro_edr_mock():
    os.environ["MINISOAR_MOCK"] = "1"

    # 1. Connectivity check
    conn = trendmicro.check_connectivity()
    assert conn["ok"] is True
    assert conn["provider"] == "trendmicro"

    # 2. Query endpoint by IP
    hosts, err = trendmicro.find_endpoint_by_ip("192.168.10.50")
    assert err is None
    assert len(hosts) == 1
    assert hosts[0]["endpointId"] == "tm-agent-0012345"

    # 3. Isolate endpoint
    ok_iso, msg_iso, data_iso = trendmicro.isolate_endpoint(ip="192.168.10.50")
    assert ok_iso is True
    assert "isolated successfully" in msg_iso.lower()

    # 4. Restore endpoint
    ok_res, msg_res, data_res = trendmicro.restore_endpoint(ip="192.168.10.50")
    assert ok_res is True
    assert "restored" in msg_res.lower()

    # 5. Add suspicious object
    ok_ioc, msg_ioc = trendmicro.add_suspicious_object("ip", "203.0.113.99")
    assert ok_ioc is True
    assert "trendmicro" in msg_ioc.lower()


def test_trendmicro_cloud_one_mode():
    os.environ["MINISOAR_MOCK"] = "1"
    os.environ["TRENDMICRO_BASE_URL"] = "https://workload.us-1.cloudone.trendmicro.com/api"

    conn = trendmicro.check_connectivity()
    assert conn["ok"] is True
    assert conn["mode"] == "Cloud One Workload Security"

    hosts, err = trendmicro.find_endpoint_by_ip("10.0.1.20")
    assert err is None
    assert len(hosts) == 1
    assert hosts[0]["endpointId"] == "tm-agent-0012345"

    ok_iso, msg_iso, _ = trendmicro.isolate_endpoint(ip="10.0.1.20")
    assert ok_iso is True

    # Reset base URL
    os.environ["TRENDMICRO_BASE_URL"] = "https://api.xdr.trendmicro.com"



def test_kaspersky_edr_mock():
    os.environ["MINISOAR_MOCK"] = "1"

    # 1. Connectivity check
    conn = kaspersky.check_connectivity()
    assert conn["ok"] is True
    assert conn["provider"] == "kaspersky"

    # 2. Query host by IP
    hosts, err = kaspersky.find_host_by_ip("10.10.20.100")
    assert err is None
    assert len(hosts) == 1
    assert hosts[0]["hostId"] == "ksc-host-10928"

    # 3. Isolate host
    ok_iso, msg_iso, data_iso = kaspersky.isolate_host(ip="10.10.20.100")
    assert ok_iso is True
    assert "isolated successfully" in msg_iso.lower()

    # 4. Restore host
    ok_res, msg_res, data_res = kaspersky.restore_host(ip="10.10.20.100")
    assert ok_res is True
    assert "restored" in msg_res.lower()

    # 5. Add IoC
    ok_ioc, msg_ioc = kaspersky.add_ioc("hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert ok_ioc is True
    assert "Kaspersky KSC" in msg_ioc


def test_edr_core_router():
    os.environ["MINISOAR_MOCK"] = "1"

    # 1. Check all connectivity
    conns = check_all_edr_connectivity()
    assert len(conns) == 2
    assert all(c["ok"] is True for c in conns)

    # 2. Query endpoint across both EDRs
    res = query_endpoint("192.168.1.100", provider="all")
    assert len(res["trendmicro"]) == 1
    assert len(res["kaspersky"]) == 1

    # 3. Isolate across all EDRs
    ok_all, msg_all, details = isolate_endpoint("192.168.1.100", provider="all")
    assert ok_all is True
    assert "trendmicro" in details
    assert "kaspersky" in details

    # 4. Restore across all EDRs
    ok_rst, msg_rst, details_rst = restore_endpoint("192.168.1.100", provider="all")
    assert ok_rst is True
    assert "trendmicro" in details_rst
    assert "kaspersky" in details_rst

    # 5. Add IoC across all EDRs
    ok_ioc, msg_ioc = add_edr_ioc("ip", "198.51.100.77", provider="all")
    assert ok_ioc is True
    assert "TrendMicro" in msg_ioc
    assert "Kaspersky" in msg_ioc


def test_edr_playbook_execution(monkeypatch):
    os.environ["MINISOAR_MOCK"] = "1"
    monkeypatch.setattr("minisoar.playbook.actions.send_telegram", lambda *args, **kwargs: None)
    monkeypatch.setattr("minisoar.playbook.actions.store_label", lambda *args, **kwargs: None)

    playbooks_dir = Path(__file__).parent.parent / "minisoar" / "playbooks"
    engine = PlaybookEngine(playbooks_dir=playbooks_dir)

    # Ransomware activity event on internal server
    event = {
        "alert": {
            "type": "alert_ransomware_activity",
            "server_name": "db-prod.internal.gov.id",
            "src_ip": "10.0.5.25",
            "severity": "critical",
        },
        "tags": ["alert_ransomware_activity", "critical"],
    }

    ctx = ExecutionContext(
        event=event,
        ip="10.0.5.25",
        website="db-prod.internal.gov.id",
        providers=["imperva"],
        mapped=True,
        whitelisted=False,
        bypassed=False,
        ml_prob=0.99,
        ml_label=1,
        reputation_score=90,
        rep_str="🛑 Critical Threat",
        event_id="test_ev_edr_001",
        redis_conn=None,
    )

    pb = engine.select_playbook(ctx)
    assert pb is not None
    assert pb.id == "pb-edr-host-compromise"

    ok, pb_id = engine.execute(ctx)
    assert ok is True
    assert pb_id == "pb-edr-host-compromise"
    assert "step_isolate_endpoint" in ctx.executed_steps
    assert "step_add_edr_ioc" in ctx.executed_steps


def test_sync_edr_ioc_if_malicious_filter_clean_ip(monkeypatch):
    os.environ["MINISOAR_MOCK"] = "1"
    from minisoar.daemon import sync_edr_ioc_if_malicious

    # 1. Clean IP with low/medium ML confidence (< 70%) and clean TI -> MUST NOT sync to EDR
    res_clean_1 = sync_edr_ioc_if_malicious(
        r=None,
        ip="198.51.100.50",
        rep_score=0,
        is_permanent=False,
        ml_prob=0.65,
        event_id="ev-clean-1",
        detector_type="alert_webshell_heur",
    )
    assert res_clean_1 is False

    res_clean_2 = sync_edr_ioc_if_malicious(
        r=None,
        ip="198.51.100.51",
        rep_score=20,
        is_permanent=False,
        ml_prob=0.45,
        event_id="ev-clean-2",
        detector_type="alert_rce_heur",
    )
    assert res_clean_2 is False

    # 2. Confirmed Malicious IP (TI >= 50%) -> MUST sync to EDR
    res_mal_ti = sync_edr_ioc_if_malicious(
        r=None,
        ip="198.51.100.52",
        rep_score=85,
        is_permanent=False,
        ml_prob=0.30,
        event_id="ev-mal-ti",
        detector_type="alert_url_probe",
    )
    assert res_mal_ti is True

    # 3. High ML confidence (>= 70%) even if TI clean -> MUST sync to EDR
    res_mal_ml = sync_edr_ioc_if_malicious(
        r=None,
        ip="198.51.100.53",
        rep_score=0,
        is_permanent=False,
        ml_prob=0.88,
        event_id="ev-mal-ml",
        detector_type="alert_webshell_name",
    )
    assert res_mal_ml is True

    # 4. Permanent block -> MUST sync to EDR
    res_perm = sync_edr_ioc_if_malicious(
        r=None,
        ip="198.51.100.54",
        rep_score=0,
        is_permanent=True,
        ml_prob=0.10,
        event_id="ev-perm",
        detector_type="alert_generic",
    )
    assert res_perm is True


def test_webshell_playbook_clean_ip_skips_edr_ioc(monkeypatch):
    os.environ["MINISOAR_MOCK"] = "1"
    monkeypatch.setattr("minisoar.playbook.actions.send_telegram", lambda *args, **kwargs: None)
    monkeypatch.setattr("minisoar.playbook.actions.store_label", lambda *args, **kwargs: None)

    playbooks_dir = Path(__file__).parent.parent / "minisoar" / "playbooks"
    engine = PlaybookEngine(playbooks_dir=playbooks_dir)

    # Webshell event with Clean IP (rep=0, ml_prob=0.55 < 0.70)
    event = {
        "alert": {
            "type": "alert_webshell_heur",
            "src_ip": "198.51.100.88",
            "severity": "high",
        },
        "tags": ["alert_webshell_heur", "high"],
    }

    ctx = ExecutionContext(
        event=event,
        ip="198.51.100.88",
        website="portal.internal.gov.id",
        providers=["imperva"],
        mapped=True,
        whitelisted=False,
        bypassed=False,
        ml_prob=0.55,
        ml_label=1,
        reputation_score=0,
        rep_str="Clean",
        event_id="test_ev_clean_webshell",
        redis_conn=None,
    )

    pb = engine.select_playbook(ctx)
    assert pb is not None
    assert pb.id == "pb-webshell-immediate"

    ok, pb_id = engine.execute(ctx)
    assert ok is True
    assert pb_id == "pb-webshell-immediate"
    assert "step_block_perimeter" in ctx.executed_steps
    assert "step_add_edr_ioc" not in ctx.executed_steps  # MUST BE SKIPPED FOR CLEAN IP (<70% ML & 0% Rep)

