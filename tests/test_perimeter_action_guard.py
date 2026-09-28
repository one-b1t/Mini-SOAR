"""P1-1: action playbook Cloudflare/FortiGate meng-import connector langsung.

Kenapa file ini terpisah dari tests/test_perimeter_disabled.py: fixture
no_network di sana bergantung pada MINISOAR_MOCK=1 yang dipasang conftest.
Dalam mode mock, connector berhenti sebelum menyentuh jaringan, jadi test itu
lulus karena "tidak error", bukan karena "tidak memanggil API" - persis
kelemahan P1-2.

Di sini mode mock DIMATIKAN dan kredensial palsu dipasang, sehingga connector
benar-benar akan mencoba HTTP kalau sampai dipanggil. Dua kontrol positif di
bawah membuktikan fixture-nya benar-benar armed; tanpa itu, penolakan action
hanya bisa dibuktikan secara vokal.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import requests

from minisoar.config import PERIMETER_NONAKTIF, perimeter_disabled_message
from minisoar.playbook.actions import action_cloudflare_block, action_fortigate_block
from minisoar.playbook.models import ExecutionContext

# Disimpan di message, bukan cuma di exception, karena connector membungkus
# pemanggilan HTTP-nya dengan `except Exception` dan mengubahnya jadi
# (False, "... request failed: <isi exception>"). Kalau sentinel-nya hilang,
# pemanggilan jaringannya berarti tidak terjadi.
SENTINEL = "NETWORK DIBUKA: jalur mati mencoba menghubungi API"

# Kredensial palsu yang PENUH: is_configured() di connector hanya mengecek env,
# jadi tanpa nilai-nilai ini jalur yang seharusnya mati tidak akan pernah
# sampai ke requests dan test-nya jadi tidak berarti.
FAKE_CREDS = {
    "MINISOAR_MOCK": "0",
    "CLOUDFLARE_API_TOKEN": "deadbeef-not-a-real-token",
    "CLOUDFLARE_ZONE_ID": "0" * 32,
    "FORTIGATE_HOST": "192.0.2.1",
    "FORTIGATE_API_TOKEN": "deadbeef-not-a-real-token",
}

_VERBS = ("get", "post", "put", "delete", "patch", "head", "request")


@pytest.fixture
def live_creds_no_network(monkeypatch):
    for key, value in FAKE_CREDS.items():
        monkeypatch.setenv(key, value)
    for key in ("CLOUDFLARE_API_KEY", "CLOUDFLARE_EMAIL", "FORTIGATE_VERIFY_SSL"):
        monkeypatch.delenv(key, raising=False)

    def boom(*args, **kwargs):
        raise AssertionError(SENTINEL)

    for verb in _VERBS:
        monkeypatch.setattr(requests, verb, boom)
        monkeypatch.setattr(requests.sessions.Session, verb, boom)
    return boom


def _ctx() -> ExecutionContext:
    return ExecutionContext(
        event={"alert": {"type": "alert_webshell_immediate", "src_ip": "198.51.100.55"}},
        ip="198.51.100.55",
        website="target.gov.id",
        providers=["cloudflare"],
        mapped=True,
        whitelisted=False,
        bypassed=False,
        ml_prob=0.9,
        ml_label=1,
        reputation_score=80,
        rep_str="malicious",
        event_id="test_ev_p1",
        redis_conn=None,
    )


# --- kontrol positif: fixture-nya benar-benar bisa menyala --------------------

def test_positive_control_cloudflare_connector_would_reach_http(live_creds_no_network):
    from minisoar.mitigation import cloudflare

    assert cloudflare.is_configured() is True, "kredensial palsu harusnya cukup"
    ok, message = cloudflare.block_ip("198.51.100.55")
    assert ok is False
    assert SENTINEL in message, message


def test_positive_control_fortigate_connector_would_reach_http(live_creds_no_network):
    from minisoar.mitigation import fortigate

    assert fortigate.is_configured() is True, "kredensial palsu harusnya cukup"
    ok, message = fortigate.block_ip("198.51.100.55")
    assert ok is False
    assert SENTINEL in message, message


# --- action yang harus menolak -------------------------------------------------

@pytest.mark.parametrize(
    "action,provider",
    [
        (action_cloudflare_block, "cloudflare"),
        (action_fortigate_block, "fortigate"),
    ],
)
def test_block_action_rejects_disabled_perimeter(live_creds_no_network, action, provider):
    ok, message = action(_ctx(), {"ip": "198.51.100.55"})
    assert ok is False
    assert message == perimeter_disabled_message(provider)
    # Bukan "not configured": kredensial sengaja dipasang supaya pesan itu
    # tidak mungkin muncul, dan pesan itu sendiri menyesatkan.
    assert "not configured" not in message
    # Dan tidak ada tanda jaringan tersentuh.
    assert SENTINEL not in message


@pytest.mark.parametrize(
    "action,provider,module",
    [
        (action_cloudflare_block, "cloudflare", "minisoar.mitigation.cloudflare"),
        (action_fortigate_block, "fortigate", "minisoar.mitigation.fortigate"),
    ],
)
def test_block_action_rejects_before_touching_connector(monkeypatch, action, provider, module):
    import importlib

    called = []
    connector = importlib.import_module(module)
    monkeypatch.setattr(connector, "block_ip", lambda *a, **k: called.append(a) or (True, "LOL"))
    ok, message = action(_ctx(), {"ip": "198.51.100.55"})
    assert ok is False
    assert message == perimeter_disabled_message(provider)
    assert called == [], "connector terpanggil padahal perimeter-nya mati"


# --- guard kelas yang sama di seluruh minisoar/ -------------------------------

_IMPORT_RE = re.compile(
    r"^\s*(?:from|import)\s+[\w.]*[\w]*(?:cloudflare|fortigate|kaspersky)\b"
    r"|^\s*from\s+[\w.]*\s+import\s+.*\b(?:cloudflare|fortigate|kaspersky)\b",
    re.M,
)
_GUARD_MARKERS = ("is_perimeter_active", "perimeter_disabled_message", "PERIMETER_NONAKTIF")


def test_no_module_imports_a_disabled_connector_without_a_guard():
    # Import langsung ke connector melewati trigger_auto_block, jadi pengamannya
    # hanya sekuat guard yang ada di file itu sendiri. Tidak ada di file ini
    # berarti tidak ada pengaman.
    offenders = []
    for path in sorted(Path("minisoar").rglob("*.py")):
        # __init__.py hanya re-export modul connector, tidak pernah memanggilnya.
        # Yang berbahaya adalah file yang meng-import lalu memanggil.
        if path.name == "__init__.py":
            continue
        source = path.read_text(encoding="utf-8")
        if not _IMPORT_RE.search(source):
            continue
        if not any(marker in source for marker in _GUARD_MARKERS):
            offenders.append(str(path).replace("\\", "/"))
    assert offenders == [], (
        "file ini meng-import connector provider nonaktif tanpa guard: "
        f"{offenders}. Sumber kebenaran: PERIMETER_NONAKTIF = {sorted(PERIMETER_NONAKTIF)}"
    )
