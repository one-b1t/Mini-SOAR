"""Cloudflare, FortiGate, dan Kaspersky harus mati di SELURUH jalur.

Keputusan user 2026-09-28: ketiga perimeter itu tidak dimiliki di tempat kerja
ini, jadi semua jalur yang bisa memanggil API-nya harus menolak dengan pesan
jelas, bukan diam-diam gagal lalu terlihat seperti "belum dikonfigurasi".

Test-test ini offline. `requests` dipatch supaya kalau ada satu saja jalur
yang menembak ke provider yang dimatikan, `boom` dipanggil dan test gagal.
Tidak ada jaringan, tidak ada kredensial nyata.
"""
import inspect
import os

import pytest
import requests

from minisoar import config
from minisoar.edr import core as edr_core
from minisoar.edr import kaspersky, trendmicro
from minisoar.mitigation import cloudflare, core as mit_core, fortigate

DEAD = ("cloudflare", "fortigate")
ALIASES = {"cf": "cloudflare", "cloudflare": "cloudflare",
           "fortigate": "fortigate", "forti": "fortigate", "fg": "fortigate"}


@pytest.fixture
def no_network(monkeypatch):
    """Pengganti requests: menyentuh jaringan = gagal keras."""

    def boom(*a, **kw):
        raise AssertionError("jalur yang seharusnya mati mencoba menghubungi API")

    for target in (requests, requests.sessions.Session):
        for verb in ("get", "post", "put", "delete", "patch", "request", "head"):
            monkeypatch.setattr(target, verb, boom, raising=False)
    return boom


# --- 1. konstanta sumber kebenaran ------------------------------------------

def test_konstanta_perimeter_nonaktif_ada_dan_tepat():
    assert set(config.PERIMETER_NONAKTIF) == set(DEAD)


def test_konstanta_punya_komentar_alasan_dan_kapan_boleh_dihapus():
    """Komentar harus ada di SOURCE, bukan di __doc__ (frozenset tidak punya docstring)."""
    src = inspect.getsource(config)
    baris = src.splitlines()
    idx = next(
        (i for i, l in enumerate(baris) if l.strip().startswith("PERIMETER_NONAKTIF")),
        None,
    )
    assert idx is not None, "PERIMETER_NONAKTIF tidak ditemukan di source config.py"
    # komentar bisa di atas konstanta
    komentar = []
    j = idx - 1
    while j >= 0 and baris[j].strip().startswith("#"):
        komentar.append(baris[j])
        j -= 1
    teks = "\n".join(komentar).lower()
    assert "alasan" in teks, "konstanta wajib punya komentar soal alasan"


@pytest.mark.parametrize("alias,canonical", sorted(ALIASES.items()))
def test_is_perimeter_active_mengenali_semua_alias(alias, canonical):
    assert config.is_perimeter_active(alias) is False
    assert config.canonical_perimeter(alias) == canonical


@pytest.mark.parametrize("alive", ("paloalto", "pan", "akamai", "ak", "imperva", "trendmicro", "kaspersky", "ksc", "kl"))
def test_perimeter_hidup_tetap_aktif(alive):
    assert config.is_perimeter_active(alive) is True


# --- 2. get_configured_providers memaksa False ------------------------------

def test_get_configured_providers_false_walau_env_terisi(monkeypatch):
    for var in ("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ZONE_ID",
                "FORTIGATE_HOST", "FORTIGATE_API_TOKEN", "FORTIGATE_API_KEY"):
        monkeypatch.setenv(var, "isi-dengan-nilai-palsu")
    got = config.get_configured_providers()
    for dead in DEAD:
        assert got[dead] is False, dead


def test_get_configured_providers_tidak_mematikan_perimeter_hidup(monkeypatch):
    monkeypatch.setenv("PA_HOST", "host-palsu")
    monkeypatch.setenv("AKAMAI_BASEURL", "https://palsu")
    monkeypatch.setenv("TRENDMICRO_API_KEY", "palsu")
    monkeypatch.setenv("KSC_SERVER_URL", "https://ksc-palsu:13299/api/v1.0")
    got = config.get_configured_providers()
    assert got["paloalto"] and got["akamai"] and got["trendmicro"] and got["kaspersky"]


# --- 3. mitigation: block/unblock ditolak dengan pesan jelas ----------------

@pytest.mark.parametrize("provider", DEAD)
def test_trigger_auto_block_menolak_provider_mati(no_network, provider):
    ok, msg = mit_core.trigger_auto_block("203.0.113.88", provider)
    assert ok is False
    assert provider in msg.lower()
    assert "tidak aktif" in msg.lower() or "dimatikan" in msg.lower()
    # bukan jatuh ke "No mitigation action configured" yang generik
    assert "No mitigation action configured" not in msg


@pytest.mark.parametrize("provider", DEAD)
def test_trigger_auto_unblock_menolak_provider_mati(no_network, provider):
    ok, msg = mit_core.trigger_auto_unblock("203.0.113.88", provider)
    assert ok is False
    assert provider in msg.lower()
    assert "No unblock action configured" not in msg


def test_check_perimeter_connectivity_tidak_menyentuh_provider_mati(no_network):
    """Baris provider mati harus ADA dan ditandai disabled."""
    rows = {r["provider"]: r for r in mit_core.check_perimeter_connectivity()}
    for dead in ("cloudflare", "fortigate"):
        assert dead in rows, f"baris {dead} hilang dari check_perimeter_connectivity()"
        assert rows[dead].get("disabled") is True, rows[dead]


# --- 4. EDR: Add IoC Kaspersky dimatikan terisolasi, host isolation/query aktif ---

def test_add_edr_ioc_all_melewati_kaspersky(no_network, monkeypatch):
    called = []
    monkeypatch.setattr(trendmicro, "add_suspicious_object",
                        lambda *a, **kw: (called.append("tm"), (True, "ok"))[1])
    monkeypatch.setattr(kaspersky, "add_ioc",
                        lambda *a, **kw: (called.append("ksc"), (False, "ksc"))[1])
    ok, msg = edr_core.add_edr_ioc("ip", "203.0.113.88", provider="all")
    assert ok is True
    assert called == ["tm"], called


@pytest.mark.parametrize("provider", ("ksc", "kaspersky", "kl"))
def test_pemanggilan_eksplisit_add_ioc_kaspersky_ditolak(no_network, provider):
    ok, msg = edr_core.add_edr_ioc("ip", "203.0.113.88", provider=provider)
    assert ok is False
    assert "kaspersky" in msg.lower()
    assert "dinonaktifkan" in msg.lower()


def test_isolate_endpoint_all_menyertakan_kaspersky(no_network, monkeypatch):
    called = []
    monkeypatch.setattr(trendmicro, "isolate_endpoint",
                        lambda **kw: (called.append("tm"), (True, "ok", {}))[1])
    monkeypatch.setattr(kaspersky, "isolate_host",
                        lambda **kw: (called.append("ksc"), (True, "ok", {}))[1])
    ok, msg, dt = edr_core.isolate_endpoint(target="10.0.0.50", provider="all")
    assert ok is True
    assert set(called) == {"tm", "ksc"}


def test_restore_endpoint_all_menyertakan_kaspersky(no_network, monkeypatch):
    called = []
    monkeypatch.setattr(trendmicro, "restore_endpoint",
                        lambda **kw: (called.append("tm"), (True, "ok", {}))[1])
    monkeypatch.setattr(kaspersky, "restore_host",
                        lambda **kw: (called.append("ksc"), (True, "ok", {}))[1])
    ok, msg, dt = edr_core.restore_endpoint(target="10.0.0.50", provider="all")
    assert ok is True
    assert set(called) == {"tm", "ksc"}


# --- 5. bot: penolakan eksklusif sebelum API --------------------------------

def _make_update():
    """Update palsu secukupnya; handler hanya butuh args + reply_text."""

    class _Msg:
        def __init__(self):
            self.date = None
            self.message_id = 1
            self.replies = []

        async def reply_text(self, text, **kw):
            self.replies.append(text)
            return self

        async def reply_html(self, *a, **kw):
            return await self.reply_text(*a, **kw)

    class _Chat:
        id = 1

    class _User:
        id = 1
        username = "tester"

    class _Update:
        def __init__(self):
            self.message = _Msg()
            self.effective_user = _User()
            self.effective_chat = _Chat()

    return _Update()


class _Ctx:
    def __init__(self, *args):
        self.args = list(args)


@pytest.mark.parametrize("command", ("blockoncf_cmd", "unblockoncf_cmd",
                                    "blockonforti_cmd", "unblockonforti_cmd"))
def test_handler_perimeter_mati_menolak_sebelum_api(no_network, command):
    from minisoar import bot
    import asyncio
    update = _make_update()
    asyncio.run(getattr(bot, command)(update, _Ctx("203.0.113.88")))
    out = " ".join(update.message.replies).lower()
    assert out, f"{command} tidak membalas apa-apa"
    assert "tidak aktif" in out or "dimatikan" in out


@pytest.mark.parametrize("provider", ("ksc", "kl", "kaspersky"))
def test_handler_edr_menolak_add_ioc_kaspersky_eksplisit(no_network, provider):
    from minisoar import bot
    import asyncio
    update = _make_update()
    asyncio.run(bot.addedrioc(update, _Ctx("10.0.0.50", provider)))
    out = " ".join(update.message.replies).lower()
    assert "kaspersky" in out, "addedrioc tidak menyebut kaspersky"
    assert "dinonaktifkan" in out, out


# --- 6. file connector tetap ada, hanya tidak dipanggil --------------------

def test_file_connector_masih_ada():
    # Dimatikan != dihapus. File connector dibiarkan supaya tidak hilang
    # kalau nanti perimeter ini dipakai lagi.
    for mod in (cloudflare, fortigate, kaspersky):
        assert os.path.exists(mod.__file__), mod.__name__
        assert hasattr(mod, "block_ip") or hasattr(mod, "isolate_host"), mod.__name__
