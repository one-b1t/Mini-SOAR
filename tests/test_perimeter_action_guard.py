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

def test_positive_control_an_active_perimeter_really_reaches_http(live_creds_no_network):
    # Kalau fixture ini tidak armed, semua test di file ini lulus karena
    # "tidak error" saja. Bukti: perimeter yang AKTIF, dengan MOCK=0, memang
    # sampai ke requests. Batasnya jelas - yang diuji adalah fixture-nya, bukan
    # connector yang sedang dimatikan.
    from minisoar.mitigation import paloalto

    resp = paloalto.palo_api_request("192.0.2.1", {"type": "op", "cmd": "<set/>", "key": "k"})
    assert SENTINEL in resp.get("error", ""), resp


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


# --- jalur bypass tanpa guard, dipanggil langsung ----------------------------

@pytest.mark.parametrize("module,provider", [("cloudflare", "cloudflare"),
                                            ("fortigate", "fortigate")])
def test_disabled_connector_refuses_a_direct_call(live_creds_no_network, module, provider):
    # AC: block_ip dipanggil langsung, tanpa lewat bot.py dan tanpa lewat
    # playbook, dengan MOCK=0 dan kredensial yang membuat is_configured() True.
    import importlib

    connector = importlib.import_module(f"minisoar.mitigation.{module}")
    assert connector.is_configured() is True, "kredensial palsu harusnya cukup"

    ok, message = connector.block_ip("198.51.100.55")
    assert ok is False
    assert message == perimeter_disabled_message(provider)
    assert SENTINEL not in message

    ok, message = connector.unblock_ip("198.51.100.55")
    assert ok is False
    assert message == perimeter_disabled_message(provider)
    assert SENTINEL not in message


@pytest.mark.parametrize("module,provider", [("cloudflare", "cloudflare"),
                                            ("fortigate", "fortigate")])
def test_disabled_connector_connectivity_never_probes(live_creds_no_network, module, provider):
    import importlib

    connector = importlib.import_module(f"minisoar.mitigation.{module}")
    conn = connector.check_connectivity()
    assert conn["ok"] is None
    assert conn["configured"] is False
    assert conn["disabled"] is True
    assert conn["hint"] == perimeter_disabled_message(provider)


def test_package_reexport_path_is_guarded(live_creds_no_network):
    # Persis bypass yang jadi bahan task ini: `from minisoar.mitigation import
    # cloudflare` lalu `cloudflare.block_ip(ip)`, tanpa bot.py, tanpa playbook,
    # tanpa trigger_auto_block. Re-export di __init__.py tidak bisa dicabut
    # sebagai pertahanan karena `from minisoar.mitigation.cloudflare import
    # block_ip` menyelesaikan modul lewat path dan tidak pernah menyentuh
    # atribut paket. Satu-satunya tempat yang bisa menutup semua spelasi itu
    # adalah entry point connector itu sendiri.
    from minisoar.mitigation import cloudflare, fortigate

    for connector, provider in ((cloudflare, "cloudflare"), (fortigate, "fortigate")):
        ok, message = connector.block_ip("198.51.100.55")
        assert (ok, message) == (False, perimeter_disabled_message(provider))


def test_bot_handler_does_not_reject_twice(monkeypatch):
    # Guard sekarang ada di dua lapis: handler bot dan connector. Handler
    # menolak lebih dulu lalu return, jadi connector tidak pernah dipanggil
    # dan operator tetap melihat satu penolakan, bukan dua.
    import asyncio

    from minisoar import bot
    from minisoar.mitigation import cloudflare, fortigate

    called = []
    monkeypatch.setattr(cloudflare, "block_ip", lambda *a, **k: called.append("cf") or (True, "LOL"))
    monkeypatch.setattr(fortigate, "block_ip", lambda *a, **k: called.append("fg") or (True, "LOL"))

    class _Msg:
        def __init__(self):
            self.replies = []

        async def reply_text(self, text, **kw):
            self.replies.append(text)
            return self

        async def reply_html(self, *a, **kw):
            return await self.reply_text(*a, **kw)

    class _Update:
        def __init__(self):
            self.message = _Msg()

    class _Ctx:
        def __init__(self, *args):
            self.args = list(args)

    for command, provider in (("blockoncf_cmd", "cloudflare"),
                              ("unblockoncf_cmd", "cloudflare"),
                              ("blockonforti_cmd", "fortigate"),
                              ("unblockonforti_cmd", "fortigate")):
        update = _Update()
        asyncio.run(getattr(bot, command)(update, _Ctx("203.0.113.88")))
        out = " ".join(update.message.replies)
        assert out.count("DIMATIKAN TOTAL") == 1, (command, out)
        assert perimeter_disabled_message(provider) in out, (command, out)

    assert called == [], "connector terpanggil padahal handler sudah menolak"


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
