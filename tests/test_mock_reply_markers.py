"""Penanda mode mock wajib ikut di balasan yang dilihat user.

Dengan MINISOAR_MOCK=1 tidak ada aksi nyata yang terjadi, tapi balasan tetap
mengKata "SUCCESS". Operator yang salah baca akan mengira host benar-benar
terisolasi atau IP benar-benar diblokir. Cloudflare/FortiGate/Imperva sudah
menandai, Palo Alto/Akamai/EDR belum.

Kontrak yang diuji: string yang dikembalikan connector/mitigation lalu
dicetak mentah oleh handler bot. Jadi penanda harus ada di string itu, bukan
diformat ulang di lapisan handler.

Dua arah: mock-on wajib bertanda, mock-off wajib tetap polos supaya teks
produksi tidak ikut berubah.
"""

import pytest

from minisoar.edr import kaspersky, trendmicro
from minisoar.mitigation import core, paloalto

CASES = [("1", True), ("0", False)]
IDS = ["mock-on", "mock-off"]

MOCK_RESP = {
    "response": {"@status": "success", "result": "Mocked configuration command successful"}
}


def _marked(msg: str) -> bool:
    """Cek penanya yang benar-benar kita pakai, bukan kata 'mock' seenakanya.

    Pesan error dari conftest juga memuat kata 'Mock' ("Mock pemanggilnya..."),
    jadi pencarian substring longgar akan salah menilai arah mock-off.
    """
    return "(Mock)" in msg or "[MOCK]" in msg


def _check(monkeypatch, value, expected, call):
    monkeypatch.setenv("MINISOAR_MOCK", value)
    ok, msg = call()[:2]
    if value == "1":
        assert ok, msg
    assert _marked(msg) == expected, msg


# --- Palo Alto: /block_palo, /unblock_palo, /commit_palo --------------------


@pytest.mark.parametrize("value,expected", CASES, ids=IDS)
def test_paloalto_response_message_marker(monkeypatch, value, expected):
    monkeypatch.setenv("MINISOAR_MOCK", value)
    msg = paloalto.response_message(MOCK_RESP, "PA: Add address object")
    assert _marked(msg) == expected, msg


# --- Akamai: /block_akamai, /unblock_akamai -------------------------------


@pytest.mark.parametrize("value,expected", CASES, ids=IDS)
def test_akamai_block_reply_marker(monkeypatch, value, expected):
    _check(monkeypatch, value, expected,
           lambda: core.trigger_auto_block("203.0.113.7", "akamai"))


@pytest.mark.parametrize("value,expected", CASES, ids=IDS)
def test_akamai_unblock_reply_marker(monkeypatch, value, expected):
    _check(monkeypatch, value, expected,
           lambda: core.trigger_auto_unblock("203.0.113.7", "akamai"))


# --- EDR: /isolate_host, /restore_host, /add_edr_ioc -----------------------


@pytest.mark.parametrize("value,expected", CASES, ids=IDS)
def test_kaspersky_isolate_reply_marker(monkeypatch, value, expected):
    _check(monkeypatch, value, expected, lambda: kaspersky.isolate_host("HOST-1"))


@pytest.mark.parametrize("value,expected", CASES, ids=IDS)
def test_kaspersky_restore_reply_marker(monkeypatch, value, expected):
    _check(monkeypatch, value, expected, lambda: kaspersky.restore_host("HOST-1"))


def test_kaspersky_add_ioc_disabled_always(monkeypatch):
    ok, msg = kaspersky.add_ioc("sha256", "a" * 64)
    assert ok is False
    assert "dinonaktifkan" in msg.lower()


@pytest.mark.parametrize("value,expected", CASES, ids=IDS)
def test_trendmicro_isolate_reply_marker(monkeypatch, value, expected):
    _check(monkeypatch, value, expected, lambda: trendmicro.isolate_endpoint("EP-1"))


@pytest.mark.parametrize("value,expected", CASES, ids=IDS)
def test_trendmicro_restore_reply_marker(monkeypatch, value, expected):
    _check(monkeypatch, value, expected, lambda: trendmicro.restore_endpoint("EP-1"))


@pytest.mark.parametrize("value,expected", CASES, ids=IDS)
def test_trendmicro_add_ioc_reply_marker(monkeypatch, value, expected):
    _check(monkeypatch, value, expected,
           lambda: trendmicro.add_suspicious_object("sha256", "a" * 64))
