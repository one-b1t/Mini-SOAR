"""Guard MINISOAR_MOCK di utils.py dan database.py.

Dua arah yang diuji untuk TIAP fungsi, terpisah, supaya kalau satu guard bocor
assertion-nya menyebut nama file + fungsinya:

  1. MINISOAR_MOCK=1  → NOL panggilan jaringan / tulisan keluar.
  2. MINISOAR_MOCK unset → perilaku produksi TETAP jalan (guard tidak boleh
     diam-diam mematikan alerting SOC atau penulisan label ML).

Arah kedua sama pentingnya: guard yang terlalu rakus sama berbahayanya dengan
tidak ada guard.
"""

import json
import os
import tempfile

import pytest

import minisoar.database as db
import minisoar.utils as utils


class _SpyResponse:
    status_code = 200
    text = '{"ok": true}'

    def json(self):
        return {"ok": True, "data": {"abuseConfidenceScore": 88, "totalReports": 7}}


@pytest.fixture
def http_spy(monkeypatch):
    """Rekam tiap panggilan HTTP keluar. Tidak ada byte yang benar-benar dikirim."""
    calls = []

    def _record(method):
        def inner(url, *a, **kw):
            calls.append((method, str(url)))
            return _SpyResponse()
        return inner

    import requests
    for name in ("get", "post", "put", "delete", "patch"):
        monkeypatch.setattr(requests, name, _record(name))
    return calls


@pytest.fixture
def mock_on(monkeypatch):
    monkeypatch.setenv("MINISOAR_MOCK", "1")


@pytest.fixture
def mock_off(monkeypatch):
    """Matikan guard supaya jalur produksi yang diuji.

    conftest.py memasang MINISOAR_MOCK=1 untuk semua test non-e2e, jadi harus
    dicabut eksplisit di sini.
    """
    monkeypatch.delenv("MINISOAR_MOCK", raising=False)


# --- utils.send_telegram ------------------------------------------------------

def test_send_telegram_silent_when_mock(mock_on, http_spy, monkeypatch):
    monkeypatch.setenv("TELEGRAM_TOKEN", "123:FAKE")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100999")

    utils.send_telegram("halo", ip="1.2.3.4", show_buttons=False)

    assert http_spy == [], (
        "minisoar/utils.py::send_telegram masih menembak jaringan saat MINISOAR_MOCK=1: "
        f"{http_spy}"
    )


def test_send_telegram_still_sends_when_mock_off(mock_off, http_spy, monkeypatch):
    monkeypatch.setenv("TELEGRAM_TOKEN", "123:FAKE")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100999")

    utils.send_telegram("halo", show_buttons=False)

    assert len(http_spy) == 1, "guard mematikan alerting produksi — ini regresi berbahaya"
    method, url = http_spy[0]
    assert method == "post"
    assert "api.telegram.org" in url and "/sendMessage" in url


# --- utils.notify_action_log --------------------------------------------------

def test_notify_action_log_silent_when_mock(mock_on, http_spy, monkeypatch):
    monkeypatch.setenv("TELEGRAM_TOKEN", "123:FAKE")
    monkeypatch.setenv("TELEGRAM_PROCESS_CHAT_ID", "-100777")

    utils.notify_action_log("📝 tes audit")

    assert http_spy == [], (
        "minisoar/utils.py::notify_action_log masih menembak jaringan saat MINISOAR_MOCK=1: "
        f"{http_spy}"
    )


def test_notify_action_log_still_sends_when_mock_off(mock_off, http_spy, monkeypatch):
    monkeypatch.setenv("TELEGRAM_TOKEN", "123:FAKE")
    monkeypatch.setenv("TELEGRAM_PROCESS_CHAT_ID", "-100777")

    utils.notify_action_log("📝 tes audit")

    assert len(http_spy) == 1, "guard mematikan action-log channel produksi"
    assert "/sendMessage" in http_spy[0][1]


# --- utils.log_user_action ----------------------------------------------------
# Sengaja TIDAK di-guard seluruhnya: fungsi ini punya DUA efek — notifikasi
# Telegram (jaringan) dan audit log ke file lokal (bukan jaringan). Guard
# dipasang di notify_action_log saja, supaya jejak audit lokal tetap tertulis
# walau mode mock aktif. Dua test di bawah mengunci pembagian itu.

def test_log_user_action_sends_nothing_when_mock(mock_on, http_spy, monkeypatch):
    monkeypatch.setenv("TELEGRAM_TOKEN", "123:FAKE")
    monkeypatch.setenv("TELEGRAM_PROCESS_CHAT_ID", "-100777")

    with tempfile.TemporaryDirectory() as tmp:
        logfile = os.path.join(tmp, "actions.log")
        utils.log_user_action("block_imperva", {"id": 1, "username": "tester"},
                              ip="1.2.3.4", target="Imperva", logfile=logfile)

    assert http_spy == [], (
        "minisoar/utils.py::log_user_action masih menembak jaringan saat MINISOAR_MOCK=1 "
        f"(lewat notify_action_log): {http_spy}"
    )


def test_log_user_action_still_writes_local_audit_when_mock(mock_on, http_spy, monkeypatch):
    """Mode mock mematikan JARINGAN, bukan jejak audit lokal."""
    monkeypatch.setenv("TELEGRAM_PROCESS_CHAT_ID", "-100777")

    with tempfile.TemporaryDirectory() as tmp:
        logfile = os.path.join(tmp, "actions.log")
        utils.log_user_action("block_imperva", {"id": 1, "username": "tester"},
                              ip="1.2.3.4", target="Imperva", logfile=logfile)

        assert os.path.exists(logfile), "audit log lokal ikut hilang — guard kelewat rakus"
        entry = json.loads(open(logfile).read().strip())

    assert entry["action"] == "block_imperva"
    assert entry["ip"] == "1.2.3.4"


# --- utils.abuseipdb_lookup ---------------------------------------------------

def test_abuseipdb_lookup_silent_when_mock(mock_on, http_spy, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake-key")

    ip, rep = utils.abuseipdb_lookup("1.2.3.4")

    assert http_spy == [], (
        "minisoar/utils.py::abuseipdb_lookup masih menembak jaringan saat MINISOAR_MOCK=1: "
        f"{http_spy}"
    )
    assert ip == "1.2.3.4"
    assert "MOCK" in rep


def test_abuseipdb_lookup_guard_runs_before_redis(mock_on, monkeypatch):
    """Guard harus jadi statement PERTAMA: sebelum guard ini, fungsi membuka
    koneksi Redis untuk cek cache sebelum sempat mengecek mode mock."""
    def _boom(*a, **kw):
        raise AssertionError("abuseipdb_lookup menyentuh Redis sebelum guard MINISOAR_MOCK")

    monkeypatch.setattr(db, "redis_client", _boom)
    ip, rep = utils.abuseipdb_lookup("8.8.8.8")
    assert "MOCK" in rep


def test_abuseipdb_lookup_still_queries_when_mock_off(mock_off, http_spy, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake-key")

    class _FakeRedis:
        def get(self, k):
            return None

        def setex(self, *a, **kw):
            return True

    monkeypatch.setattr(db, "redis_client", lambda *a, **kw: _FakeRedis())

    ip, rep = utils.abuseipdb_lookup("1.2.3.4")

    assert len(http_spy) == 1, "guard mematikan enrichment reputasi produksi"
    assert "abuseipdb.com" in http_spy[0][1]
    assert "88/100" in rep, f"parsing skor produksi berubah: {rep}"


# --- database.store_label -----------------------------------------------------

class _User:
    id = 12345
    username = "tester"


def test_store_label_silent_when_mock(mock_on, http_spy):
    db.store_label("evt-1", "block", _User(), "telegram_command", ip="1.2.3.4")

    assert http_spy == [], (
        "minisoar/database.py::store_label masih MENULIS ke Elasticsearch saat "
        f"MINISOAR_MOCK=1 — ini yang mencemari dataset ML produksi: {http_spy}"
    )


def test_store_label_still_writes_when_mock_off(mock_off, http_spy, monkeypatch):
    monkeypatch.setenv("ES_HOSTS", "http://localhost:9200")

    db.store_label("evt-1", "block", _User(), "telegram_command", ip="1.2.3.4")

    assert len(http_spy) == 1, "guard mematikan penulisan label ML produksi"
    method, url = http_spy[0]
    assert method == "put"
    assert "minisoar-labels-" in url


# --- konsistensi pola ---------------------------------------------------------

@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "Yes"])
def test_guard_accepts_same_values_as_mitigation(value, http_spy, monkeypatch):
    """Guard baru harus menerima nilai env yang sama persis dengan pola di
    minisoar/mitigation/ — `in {"1","true","yes"}` setelah .lower()."""
    monkeypatch.setenv("MINISOAR_MOCK", value)
    monkeypatch.setenv("TELEGRAM_TOKEN", "123:FAKE")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100999")

    utils.send_telegram("halo", show_buttons=False)
    db.store_label("evt-1", "block", _User(), "telegram_command", ip="1.2.3.4")

    assert http_spy == [], f"MINISOAR_MOCK={value!r} tidak dikenali guard"


@pytest.mark.parametrize("value", ["0", "false", "no", ""])
def test_guard_ignores_falsy_values_like_mitigation(value, http_spy, monkeypatch):
    """Nilai falsy harus TIDAK mengaktifkan mock, sama seperti mitigation/."""
    monkeypatch.setenv("MINISOAR_MOCK", value)
    monkeypatch.setenv("TELEGRAM_TOKEN", "123:FAKE")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100999")

    utils.send_telegram("halo", show_buttons=False)

    assert len(http_spy) == 1, f"MINISOAR_MOCK={value!r} seharusnya TIDAK mengaktifkan mock"
