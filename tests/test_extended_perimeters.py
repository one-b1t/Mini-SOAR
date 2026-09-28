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
    # Mock TIDAK boleh membuat perimeter mati melaporkan sukses. Kalau dijalankan
    # di mode demo dan connector membalas "SUCCESS ... (Mock)", operator
    # mendapat kepastian palsu tentang perimeter yang tidak dimiliki di sini.
    os.environ["MINISOAR_MOCK"] = "1"

    # 1. Connectivity check
    conn = cloudflare.check_connectivity()
    assert conn["ok"] is None
    assert conn["provider"] == "cloudflare"
    assert conn["disabled"] is True

    # 2. Block IP
    ok_blk, msg_blk = cloudflare.block_ip("203.0.113.88")
    assert ok_blk is False
    assert "tidak aktif" in msg_blk.lower()
    assert "Mock" not in msg_blk

    # 3. Unblock IP
    ok_unblk, msg_unblk = cloudflare.unblock_ip("203.0.113.88")
    assert ok_unblk is False
    assert "tidak aktif" in msg_unblk.lower()


def test_fortigate_mock():
    # Sama seperti Cloudflare: guard di dalam connector jalan sebelum cek mock.
    os.environ["MINISOAR_MOCK"] = "1"

    # 1. Connectivity check
    conn = fortigate.check_connectivity()
    assert conn["ok"] is None
    assert conn["provider"] == "fortigate"
    assert conn["disabled"] is True

    # 2. Block IP
    ok_blk, msg_blk = fortigate.block_ip("198.51.100.12")
    assert ok_blk is False
    assert "tidak aktif" in msg_blk.lower()
    assert "Mock" not in msg_blk

    # 3. Unblock IP
    ok_unblk, msg_unblk = fortigate.unblock_ip("198.51.100.12")
    assert ok_unblk is False
    assert "tidak aktif" in msg_unblk.lower()


def test_unified_perimeter_orchestration_extended():
    os.environ["MINISOAR_MOCK"] = "1"

    # Block on Cloudflare via orchestrator
    ok_cf, msg_cf = trigger_auto_block("103.20.10.5", "cloudflare")
    assert ok_cf is False
    assert "tidak aktif" in msg_cf.lower()
    assert "No mitigation action configured" not in msg_cf

    # Unblock on Cloudflare via orchestrator
    ok_cf_un, msg_cf_un = trigger_auto_unblock("103.20.10.5", "cloudflare")
    assert ok_cf_un is False
    assert "tidak aktif" in msg_cf_un.lower()

    # Block on FortiGate via orchestrator
    ok_fg, msg_fg = trigger_auto_block("103.20.10.5", "fortigate")
    assert ok_fg is False
    assert "tidak aktif" in msg_fg.lower()

    # Unblock on FortiGate via orchestrator
    ok_fg_un, msg_fg_un = trigger_auto_unblock("103.20.10.5", "fortigate")
    assert ok_fg_un is False
    assert "tidak aktif" in msg_fg_un.lower()

    # Check perimeter connectivity includes all 5 perimeters
    results = check_perimeter_connectivity()
    providers = {r["provider"] for r in results}
    by_provider = {r["provider"]: r for r in results}
    assert by_provider["cloudflare"]["disabled"] is True
    assert by_provider["fortigate"]["disabled"] is True
    assert "imperva" in providers
    assert "paloalto" in providers
    assert "akamai" in providers
