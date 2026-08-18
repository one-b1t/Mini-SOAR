from __future__ import annotations

import os

from minisoar.mitigation import (
    check_perimeter_connectivity,
    cloudflare,
    fortigate,
    trigger_auto_block,
    trigger_auto_unblock,
)


def test_cloudflare_mock():
    os.environ["MINISOAR_MOCK"] = "1"

    # 1. Connectivity check
    conn = cloudflare.check_connectivity()
    assert conn["ok"] is True
    assert conn["provider"] == "cloudflare"

    # 2. Block IP
    ok_blk, msg_blk = cloudflare.block_ip("203.0.113.88")
    assert ok_blk is True
    assert "Cloudflare" in msg_blk

    # 3. Unblock IP
    ok_unblk, msg_unblk = cloudflare.unblock_ip("203.0.113.88")
    assert ok_unblk is True
    assert "Cloudflare" in msg_unblk


def test_fortigate_mock():
    os.environ["MINISOAR_MOCK"] = "1"

    # 1. Connectivity check
    conn = fortigate.check_connectivity()
    assert conn["ok"] is True
    assert conn["provider"] == "fortigate"

    # 2. Block IP
    ok_blk, msg_blk = fortigate.block_ip("198.51.100.12")
    assert ok_blk is True
    assert "FortiGate" in msg_blk

    # 3. Unblock IP
    ok_unblk, msg_unblk = fortigate.unblock_ip("198.51.100.12")
    assert ok_unblk is True
    assert "FortiGate" in msg_unblk


def test_unified_perimeter_orchestration_extended():
    os.environ["MINISOAR_MOCK"] = "1"

    # Block on Cloudflare via orchestrator
    ok_cf, msg_cf = trigger_auto_block("103.20.10.5", "cloudflare")
    assert ok_cf is True
    assert "Cloudflare" in msg_cf

    # Unblock on Cloudflare via orchestrator
    ok_cf_un, msg_cf_un = trigger_auto_unblock("103.20.10.5", "cloudflare")
    assert ok_cf_un is True

    # Block on FortiGate via orchestrator
    ok_fg, msg_fg = trigger_auto_block("103.20.10.5", "fortigate")
    assert ok_fg is True
    assert "FortiGate" in msg_fg

    # Unblock on FortiGate via orchestrator
    ok_fg_un, msg_fg_un = trigger_auto_unblock("103.20.10.5", "fortigate")
    assert ok_fg_un is True

    # Check perimeter connectivity includes all 5 perimeters
    results = check_perimeter_connectivity()
    providers = {r["provider"] for r in results}
    assert "cloudflare" in providers
    assert "fortigate" in providers
    assert "imperva" in providers
    assert "paloalto" in providers
    assert "akamai" in providers
