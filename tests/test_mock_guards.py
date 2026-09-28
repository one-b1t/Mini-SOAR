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
import socket
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


# --- HANDLER TELEGRAM: activateakamai + retrainmodel_cmd (bot.py) ---
#
# Dua handler ini sebelumnya tidak punya guard sama sekali di bot.py, padahal
# keduanya menyentuh batas produksi:
#   * activateakamai  -> API Akamai (list IP 217280_IPBLOCKLIST, network PRODUCTION)
#   * retrainmodel_cmd -> ES index minisoar-labels-* lalu tulis model produksi
#
# Bukti yang diuji di sini BUKAN "flag-nya terbaca" — itu tidak membuktikan apa
# apa. Yang dibuktikan: TIDAK ADA satu pun koneksi socket ke host luar yang
# terbentuk selama handler dijalankan. Lihat _NoEgress di bawah.


class _NoEgress:
    """Blokir DAN catat setiap upaya koneksi socket ke luar.

    Sengaja dipasang di level socket, bukan di level `requests`, karena
    requests bisa dipanggil lewat banyak pintu: requests.get, requests.post,
    requests.request, requests.Session.request, atau langsung socket.
    Menempelkan spy hanya di sebagian pintu itu akan lolos diam-diam — dan
    es_request() memang memakai requests.request(), bukan requests.get().

    Berbeda dengan pemblokir global di conftest.py, yang menolak loopback juga
    (itulah yang membuat asyncio.run() mustahil di suite ini), di sini loopback
    tetap diteruskan ke socket asli supaya self-pipe event loop tetap hidup.
    Yang dilarang adalah host di luar.
    """

    _LOOPBACK = {"127.0.0.1", "::1", "localhost"}

    def __init__(self):
        self.attempts = []

    def check(self, address):
        host = address[0] if isinstance(address, tuple) else address
        if str(host) in self._LOOPBACK:
            return
        self.attempts.append(str(address))
        raise AssertionError(f"EGRESS ke host luar: {address!r}")


# conftest.py memblokir socket.socket.connect di level fixture, yang berjalan
# SESUDAH modul test di-import. Jadi originals harus ditangkap di sini, waktu
# import — kalau diambil di dalam fixture, yang ditangkap sudah versi yang
# dipatch conftest (dan self-pipe asyncio ikut mati).
_REAL_CONNECT = socket.socket.connect
_REAL_CREATE_CONNECTION = socket.create_connection


@pytest.fixture
def no_egress(monkeypatch):
    blocker = _NoEgress()

    def fake_connect(self, address, *a, **kw):
        blocker.check(address)
        return _REAL_CONNECT(self, address, *a, **kw)

    def fake_create(address, *a, **kw):
        blocker.check(address)
        return _REAL_CREATE_CONNECTION(address, *a, **kw)

    monkeypatch.setattr(socket.socket, "connect", fake_connect)
    monkeypatch.setattr(socket, "create_connection", fake_create)
    return blocker


class _Ctx:
    def __init__(self, *args):
        self.args = list(args)


def _fake_update(user_id=12345):
    replies = []

    class _Msg:
        date = "2024-01-01T00:00:00Z"
        message_id = 4242

        async def reply_text(self, *a, **kw):
            replies.append(a[0] if a else "")

    class _Update:
        def __init__(self):
            self.effective_user = type("U", (), {"id": user_id})()
            self.effective_chat = type("C", (), {"id": -100123})()
            self.message = _Msg()
            self.callback_query = None
            self.replies = replies

    return _Update()


def test_activateakamai_makes_no_socket_connection_under_mock(no_egress, monkeypatch):
    """activateakamai tidak boleh membuka koneksi apa pun ke Akamai saat mock aktif."""
    import asyncio
    import minisoar.bot as botmod

    monkeypatch.setenv("MINISOAR_MOCK", "1")
    # Kredensial produksi sengaja dipasang: kalau guard bocor, test ini harus
    # gagal karena socket percobaan, bukan karena credential kosong.
    monkeypatch.setenv("AKAMAI_BASEURL", "https://akxm-xxx.luna.akamaiapis.net")
    monkeypatch.setenv("AKAMAI_CLIENT_TOKEN", "tok")
    monkeypatch.setenv("AKAMAI_CLIENT_SECRET", "sec")
    monkeypatch.setenv("AKAMAI_ACCESS_TOKEN", "acc")
    monkeypatch.setenv("AKAMAI_IPBLOCKLIST_STAGING", "217280_IPBLOCKLIST")
    monkeypatch.setenv("AKAMAI_IPBLOCKLIST_PROD", "217280_IPBLOCKLIST")

    posted = []

    class _Resp:
        status_code = 200

        def json(self):
            return {"activationStatus": "IN_PROGRESS", "activationId": "a-1", "version": "v1"}

    class _Session:
        def post(self, url, headers=None, json=None):
            posted.append((url, json))
            return _Resp()

    monkeypatch.setattr(botmod, "resolve_log_path", lambda *a, **k: "/tmp/x.log")
    monkeypatch.setattr(botmod, "log_user_action", lambda *a, **k: None)
    monkeypatch.setattr(botmod.akamai, "akamai_session", lambda **kw: _Session())
    monkeypatch.setattr(botmod.akamai, "akamai_url", lambda base, path: "https://akamai.test")

    update = _fake_update()
    asyncio.run(botmod.activateakamai(update, _Ctx()))

    assert no_egress.attempts == [], f"activateakamai egress: {no_egress.attempts}"
    assert posted == [], "activateakamai tetap POST meski mode mock aktif"
    assert any("mock" in r.lower() for r in update.replies), (
        f"user tidak diberi tahu aksi di-skip; balasan: {update.replies}"
    )


def test_activateakamai_still_activates_when_mock_off(no_egress, monkeypatch):
    """Arah sebaliknya: guard jangan mematikan jalur produksi yang sah."""
    import asyncio
    import minisoar.bot as botmod

    monkeypatch.delenv("MINISOAR_MOCK", raising=False)
    monkeypatch.setenv("AKAMAI_BASEURL", "https://akxm-xxx.luna.akamaiapis.net")
    monkeypatch.setenv("AKAMAI_IPBLOCKLIST_STAGING", "217280_IPBLOCKLIST")
    monkeypatch.setenv("AKAMAI_IPBLOCKLIST_PROD", "217280_IPBLOCKLIST")

    bodies = []

    class _Resp:
        status_code = 200

        def json(self):
            return {"activationStatus": "IN_PROGRESS", "activationId": "a-1", "version": "v1"}

    class _Session:
        def post(self, url, headers=None, json=None):
            bodies.append(json)
            return _Resp()

    monkeypatch.setattr(botmod, "resolve_log_path", lambda *a, **k: "/tmp/x.log")
    monkeypatch.setattr(botmod, "log_user_action", lambda *a, **k: None)
    monkeypatch.setattr(botmod.akamai, "akamai_session", lambda **kw: _Session())
    monkeypatch.setattr(botmod.akamai, "akamai_url", lambda base, path: "https://akamai.test")

    asyncio.run(botmod.activateakamai(_fake_update(), _Ctx()))

    assert len(bodies) == 2, f"guard terlalu rakus, hanya {len(bodies)} request"


def test_retrainmodel_cmd_makes_no_socket_connection_under_mock(no_egress, monkeypatch):
    """retrainmodel_cmd tidak boleh baca ES / tulis model produksi saat mock aktif."""
    import asyncio
    import minisoar.bot as botmod

    monkeypatch.setenv("MINISOAR_MOCK", "1")

    trained = []
    import minisoar.ml.autotrain as autotrain

    monkeypatch.setattr(
        autotrain,
        "run_autotrain_from_file",
        lambda *a, **kw: (trained.append(1), (False, {}, "dilewati"))[1],
    )

    update = _fake_update()
    asyncio.run(botmod.retrainmodel_cmd(update, _Ctx()))

    assert no_egress.attempts == [], f"retrainmodel_cmd egress: {no_egress.attempts}"
    assert trained == [], "run_autotrain_from_file dipanggil meski mode mock aktif"
    assert any("mock" in r.lower() for r in update.replies), (
        f"user tidak diberi tahu retraining di-skip; balasan: {update.replies}"
    )


def test_retrainmodel_cmd_still_trains_when_mock_off(no_egress, monkeypatch):
    """Arah sebaliknya: tanpa mock, retraining tetap jalan seperti sebelumnya."""
    import asyncio
    import minisoar.bot as botmod

    monkeypatch.delenv("MINISOAR_MOCK", raising=False)

    trained = []
    import minisoar.ml.autotrain as autotrain

    def _fake_train(*a, **kw):
        trained.append(1)
        return True, {"auc": 0.99}, "selesai"

    monkeypatch.setattr(autotrain, "run_autotrain_from_file", _fake_train)

    asyncio.run(botmod.retrainmodel_cmd(_fake_update(), _Ctx()))

    assert trained == [1], "guard terlalu rakus, retraining tidak jalan tanpa mock"


def test_no_egress_fixture_actually_blocks(no_egress):
    """Self-check fixture: kalau _NoEgress tidak memblokir, test di atas
    semuanya jadi tidak bermakna (hanya cek flag). Pastikan ia benar-benar
    MEMPUNGKIR koneksi ke host luar.

    Pakai IP literal dari TEST-NET-3 (203.0.113.0/24, tidak pernah di-routing)
    supaya tidak ada lookup DNS sama sekali — yang diuji adalah penolakan di
    socket layer, bukan kegagalan resolusi nama.
    """
    assert no_egress.attempts == []

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(AssertionError, match="EGRESS"):
            sock.connect(("203.0.113.5", 443))

    assert no_egress.attempts == ["('203.0.113.5', 443)"]
