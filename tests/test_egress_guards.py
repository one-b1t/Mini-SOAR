"""Guard MINISOAR_MOCK pada jalur egress yang belum tercakup test_mock_guards.py.

Cakupan: database.py (ES read/write + health), utils.ipapi_lookup,
ml/export.es_request, imperva.get_blocked_ip_list, replay.inject_attacks_to_redis,
dan penulis artefak ML (dataset.csv, active_model.joblib, baseline_model.joblib).

Dua lapis bukti, sengaja tidak memakai `http_spy` di test_mock_guards.py:
fixture itu hanya menambal requests.get/post/put/delete/patch, sehingga
requests.request() (dipakai es_request) dan requests.Session lolos.

  * `http_spy` di sini menambal requests.sessions.Session.request — SEMUA pintu
    requests (get/post/request/Session) lewat sana.
  * `no_egress` menambal socket.connect, socket.create_connection, DAN
    socket.getaddrinfo. getaddrinfo penting: tanpa itu, kebocoran tetap
    mengirim hostname produksi ke resolver DNS walau connect-nya diblok.

Arah kedua (mock off) diuji juga: guard yang terlalu rakus sama berbahayanya.
"""

import hashlib
import socket
from pathlib import Path

import pandas as pd
import pytest
import requests

import minisoar.database as db
import minisoar.utils as utils
from minisoar.mitigation import imperva
from minisoar.ml import autotrain, export, replay, train

PROD_ES = "https://es.prod.minisoar.test:9200"
ROOT = Path(__file__).resolve().parent.parent
PROD_ARTIFACTS = [ROOT / "dataset.csv", ROOT / "active_model.joblib", ROOT / "baseline_model.joblib"]

# Originals diambil saat import: conftest.py menambal socket di fixture
# autouse, yang berjalan SESUDAH modul ini di-import.
_REAL_CONNECT = socket.socket.connect
_REAL_CREATE_CONNECTION = socket.create_connection
_REAL_GETADDRINFO = socket.getaddrinfo
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class _NoEgress:
    def __init__(self):
        self.attempts = []

    def check(self, host, what):
        if isinstance(host, (bytes, bytearray)):
            host = host.decode("ascii", "replace")
        if host is None or str(host) in _LOOPBACK:
            return
        self.attempts.append(f"{what}:{host}")
        raise OSError(f"EGRESS ke host luar via {what}: {host!r}")


@pytest.fixture
def no_egress(monkeypatch):
    blocker = _NoEgress()

    def fake_connect(self, address, *a, **kw):
        if isinstance(address, tuple) and address:
            blocker.check(address[0], "connect")
        return _REAL_CONNECT(self, address, *a, **kw)

    def fake_create(address, *a, **kw):
        blocker.check(address[0], "create_connection")
        return _REAL_CREATE_CONNECTION(address, *a, **kw)

    def fake_getaddrinfo(host, *a, **kw):
        blocker.check(host, "getaddrinfo")
        return _REAL_GETADDRINFO(host, *a, **kw)

    monkeypatch.setattr(socket.socket, "connect", fake_connect)
    monkeypatch.setattr(socket, "create_connection", fake_create)
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    return blocker


# --- getaddrinfo: DNS tidak boleh jadi celah egress ---------------------------
#
# connect yang diblokir saja tidak cukup: hostname produksi sudah terkirim ke
# resolver DNS pada saat getaddrinfo dipanggil, jauh sebelum connect ditolak.
# Conftest memblokir getaddrinfo; test di sini membuktikan kedua lapisan
# (conftest dan fixture no_egress di modul ini) memakai aturan yang sama, agar
# keduanya tidak bisa berbeda pendapat diam-diam.

# Fixture no_egress modul ini sengaja menambal socket.getaddrinfo di ATAS
# fixture conftest yang autouse. Kalau hanya conftest yang diuji, tidak ada
# yang memastikan fixture lokal ini ikut menutup pintu yang sama.
def test_no_egress_catches_dns_lookup(no_egress):
    with pytest.raises(OSError, match="EGRESS"):
        socket.getaddrinfo("es.prod.minisoar.test", 9200)
    assert no_egress.attempts == ["getaddrinfo:es.prod.minisoar.test"]


def test_no_egress_allows_loopback_dns(no_egress):
    """Arah sebaliknya: resolver untuk loopback harus tetap boleh."""
    infos = socket.getaddrinfo("127.0.0.1", 9200)
    assert infos, "getaddrinfo untuk loopback harus tetap berfungsi"
    assert no_egress.attempts == []


def test_conftest_blocks_external_dns_but_allows_loopback():
    """Meta-test untuk conftest itu sendiri (tanpa fixture no_egress di atas).

    Dua arah, karena pemblokir yang terlalu rakus sama berbahayanya: kalau
    getaddrinfo ikut tertutup, asyncio.run() mati lagi di Windows.
    """
    with pytest.raises(RuntimeError, match="mencoba resolve DNS"):
        socket.getaddrinfo("akxm-xxx.luna.akamaiapis.net", 443)

    # Loopback tetap diizinkan — ini yang membuat asyncio.run() hidup di Windows.
    assert socket.getaddrinfo("127.0.0.1", 80)


class _SpyResponse:
    status_code = 200
    text = "{}"

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


@pytest.fixture
def http_spy(monkeypatch):
    """Rekam tiap request lewat Session.request — pintu bersama semua API requests."""
    calls = []
    payload = {
        "status": "green",
        "hits": {"total": {"value": 3}, "hits": [{"_source": {"event_id": "ev-1", "server_name": "web.test"}}]},
        "entries": [{"type": "single", "ipAddressFrom": "1.2.3.4"}],
        "countryCode": "ID", "country": "Indonesia", "isp": "X",
    }

    def fake_request(self, method, url, *a, **kw):
        calls.append((method.upper(), str(url)))
        return _SpyResponse(payload)

    monkeypatch.setattr(requests.sessions.Session, "request", fake_request)
    return calls


@pytest.fixture
def prod_env(monkeypatch):
    monkeypatch.setenv("ES_HOSTS", PROD_ES)
    monkeypatch.setenv("ES_USER", "elastic")
    monkeypatch.setenv("ES_PASS", "secret")


@pytest.fixture
def mock_on(monkeypatch):
    monkeypatch.setenv("MINISOAR_MOCK", "1")


@pytest.fixture
def mock_off(monkeypatch):
    # conftest.py memasang MINISOAR_MOCK=1 untuk semua test non-e2e.
    monkeypatch.delenv("MINISOAR_MOCK", raising=False)


class _FakeRedis:
    def __init__(self):
        self.store = {}

    def get(self, k):
        return self.store.get(k)

    def setex(self, k, ttl, v):
        self.store[k] = v

    def ping(self):
        return True

    def llen(self, k):
        return 0


# --- Bukti bahwa alatnya sendiri menangkap --------------------------------------

def test_no_egress_catches_requests_request(no_egress, mock_off):
    """Pintu yang lolos dari http_spy lama: requests.request ke hostname."""
    with pytest.raises(requests.exceptions.RequestException):
        requests.request("GET", f"{PROD_ES}/_search", timeout=1)
    assert any("es.prod.minisoar.test" in a for a in no_egress.attempts), no_egress.attempts


def test_no_egress_catches_raw_ip_connect(no_egress, mock_off):
    with pytest.raises(requests.exceptions.RequestException):
        requests.Session().get("http://203.0.113.9:9200/", timeout=1)
    assert any("203.0.113.9" in a for a in no_egress.attempts), no_egress.attempts


@pytest.mark.parametrize("call", [
    lambda: requests.get("http://x.test"),
    lambda: requests.request("GET", "http://x.test"),
    lambda: requests.Session().post("http://x.test"),
])
def test_http_spy_covers_every_requests_door(http_spy, call):
    call()
    assert len(http_spy) == 1


# --- database.py: ES read/write -------------------------------------------------

ES_CASES = [
    ("es_index", lambda: db.es_index("minisoar-events-2026.09.28", "doc-1", {"a": 1}), None),
    ("es_find_latest_event_id_by_ip", lambda: db.es_find_latest_event_id_by_ip("1.2.3.4"), None),
    ("es_get_event_website_by_id", lambda: db.es_get_event_website_by_id("ev-1"), None),
    ("es_get_latest_event_website_by_ip", lambda: db.es_get_latest_event_website_by_ip("1.2.3.4"), None),
    ("es_count_hits_by_ip", lambda: db.es_count_hits_by_ip("1.2.3.4"), (0, None)),
]


@pytest.mark.parametrize("name,call,expected", ES_CASES, ids=[c[0] for c in ES_CASES])
def test_es_functions_silent_when_mock(name, call, expected, mock_on, prod_env, no_egress, http_spy):
    assert call() == expected
    assert http_spy == [], f"minisoar/database.py::{name} menembak ES saat MINISOAR_MOCK=1: {http_spy}"
    assert no_egress.attempts == [], f"minisoar/database.py::{name} egress: {no_egress.attempts}"


@pytest.mark.parametrize("name,call,expected", ES_CASES, ids=[c[0] for c in ES_CASES])
def test_es_functions_still_query_when_mock_off(name, call, expected, mock_off, prod_env, no_egress, http_spy):
    call()
    assert len(http_spy) == 1, f"guard {name} mematikan jalur ES produksi"
    assert http_spy[0][1].startswith(PROD_ES)


def test_get_system_health_skips_es_when_mock(mock_on, prod_env, no_egress, http_spy, monkeypatch):
    monkeypatch.setattr(db, "redis_client", lambda: _FakeRedis())
    h = db.get_system_health()
    assert h["elasticsearch"]["status"] == "MOCK"
    assert http_spy == [] and no_egress.attempts == []


def test_get_system_health_queries_es_when_mock_off(mock_off, prod_env, no_egress, http_spy, monkeypatch):
    monkeypatch.setattr(db, "redis_client", lambda: _FakeRedis())
    h = db.get_system_health()
    assert h["elasticsearch"]["status"] == "GREEN"
    assert http_spy == [("GET", f"{PROD_ES}/_cluster/health")]


# --- utils.ipapi_lookup ---------------------------------------------------------

def test_ipapi_lookup_silent_when_mock(mock_on, no_egress, http_spy, monkeypatch):
    def _no_redis():
        raise AssertionError("guard harus jalan sebelum Redis disentuh")

    monkeypatch.setattr(db, "redis_client", _no_redis)
    ip, geo = utils.ipapi_lookup("1.2.3.4")
    assert ip == "1.2.3.4" and "MOCK" in geo
    assert http_spy == [] and no_egress.attempts == []


def test_ipapi_lookup_still_queries_when_mock_off(mock_off, no_egress, http_spy, monkeypatch):
    monkeypatch.setattr(db, "redis_client", lambda: _FakeRedis())
    utils.ipapi_lookup("1.2.3.4")
    assert len(http_spy) == 1 and "ip-api.com" in http_spy[0][1]


# --- ml/export.es_request -------------------------------------------------------

def test_es_request_silent_when_mock(mock_on, prod_env, no_egress, http_spy):
    res = export.es_request("GET", "minisoar-labels-*/_search", body={"size": 1})
    assert res["hits"]["hits"] == []
    assert http_spy == [] and no_egress.attempts == []


def test_es_request_still_queries_when_mock_off(mock_off, prod_env, no_egress, http_spy, monkeypatch):
    monkeypatch.setattr(export, "load_env", lambda: None)
    export.es_request("GET", "minisoar-labels-*/_search")
    assert http_spy == [("GET", f"{PROD_ES}/minisoar-labels-*/_search")]


def test_replay_fetch_goes_through_guarded_es_request(mock_on, prod_env, no_egress, http_spy):
    replay.fetch_securesphere_attack_traffic(sample_size=5)
    assert http_spy == [] and no_egress.attempts == []


# --- imperva.get_blocked_ip_list ------------------------------------------------

def test_imperva_get_blocked_ip_list_silent_when_mock(mock_on, no_egress, http_spy):
    assert imperva.get_blocked_ip_list("https://mx.prod.test:8083", "grp", {"s": "1"}) == []
    assert http_spy == [] and no_egress.attempts == []


def test_imperva_get_blocked_ip_list_queries_when_mock_off(mock_off, no_egress, http_spy):
    assert imperva.get_blocked_ip_list("https://mx.prod.test:8083", "grp", {"s": "1"}) == ["1.2.3.4"]
    assert len(http_spy) == 1


# --- replay.inject_attacks_to_redis ---------------------------------------------

def test_inject_attacks_to_redis_silent_when_mock(mock_on, no_egress, monkeypatch):
    import redis

    def _no_redis(*a, **kw):
        raise AssertionError("inject_attacks_to_redis membuat koneksi Redis saat mock")

    monkeypatch.setattr(redis, "Redis", _no_redis)
    assert replay.inject_attacks_to_redis([{"a": 1}], redis_host="10.9.9.9") == 0
    assert no_egress.attempts == []


def test_inject_attacks_to_redis_pushes_when_mock_off(mock_off, monkeypatch):
    import redis

    pushed = []

    class _R:
        def __init__(self, *a, **kw):
            pass

        def lpush(self, k, v):
            pushed.append(k)

    monkeypatch.setattr(redis, "Redis", _R)
    assert replay.inject_attacks_to_redis([{"a": 1}, {"b": 2}], limit=5) == 2
    assert pushed == ["logstash_alert_queue"] * 2


# --- Artefak ML produksi di root repo -------------------------------------------

def _fingerprint():
    return {
        p.name: (hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None)
        for p in PROD_ARTIFACTS
    }


def _separable_df():
    n = 20
    return pd.DataFrame({
        "reputation_score": [95] * (n // 2) + [5] * (n // 2),
        "hit_count": [50] * (n // 2) + [1] * (n // 2),
        "is_whitelisted": [0] * (n // 2) + [1] * (n // 2),
        "severity": ["high"] * (n // 2) + ["low"] * (n // 2),
        "detector_type": ["alert_webshell"] * (n // 2) + ["alert_scan"] * (n // 2),
        "label": [1] * (n // 2) + [0] * (n // 2),
    })


def test_ml_default_paths_untouched_when_mock(mock_on, prod_env, no_egress, http_spy):
    before = _fingerprint()

    assert export.export_dataset_from_es()[0] is False
    assert autotrain.run_autotrain_from_file()[0] is False
    assert autotrain.evaluate_and_promote_model(_separable_df(), min_auc_threshold=0.5)[0] is False
    assert train.train_baseline() == {}

    assert _fingerprint() == before, "artefak ML produksi di root repo tertimpa saat MINISOAR_MOCK=1"
    assert http_spy == [] and no_egress.attempts == []


def test_evaluate_and_promote_explicit_path_skips_root_baseline_when_mock(mock_on, tmp_path):
    before = _fingerprint()
    target = tmp_path / "active.joblib"

    ok, _, msg = autotrain.evaluate_and_promote_model(_separable_df(), active_artifact_path=target, min_auc_threshold=0.5)

    assert ok is True, msg
    assert target.exists()
    assert _fingerprint() == before, "baseline_model.joblib di root repo tertimpa saat mock"


def test_evaluate_and_promote_writes_root_baseline_when_mock_off(mock_off, tmp_path, monkeypatch):
    """Arah sebaliknya: baseline_model.joblib tetap di-update di produksi."""
    dumped = []
    monkeypatch.setattr(autotrain.joblib, "dump", lambda obj, path: dumped.append(Path(path).name))
    monkeypatch.setattr(Path, "replace", lambda self, target: None)

    ok, _, msg = autotrain.evaluate_and_promote_model(
        _separable_df(), active_artifact_path=tmp_path / "active.joblib", min_auc_threshold=0.5
    )

    assert ok is True, msg
    assert "baseline_model.joblib" in dumped, f"guard mematikan update baseline produksi: {dumped}"


# --- Whitelist produksi (cwd fallback resolve_log_path) -------------------------
# Tanpa WHITELIST_PATH, resolve_whitelist_path() jatuh ke cwd/minisoar-whitelist.txt.
# pytest jalan dari root repo, jadi itu = whitelist produksi Windows. Test di sini
# chdir ke tmp berisi whitelist "produksi" palsu supaya file asli tidak dipertaruhkan,
# lalu tetap memverifikasi file asli di root tidak berubah.

ROOT_WHITELIST = ROOT / "minisoar-whitelist.txt"


def _sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None


@pytest.fixture
def fake_prod_cwd(tmp_path, monkeypatch):
    monkeypatch.delenv("WHITELIST_PATH", raising=False)
    monkeypatch.chdir(tmp_path)
    wl = tmp_path / "minisoar-whitelist.txt"
    wl.write_text("10.9.9.9  # prod entry\n", encoding="utf-8")
    return wl


def test_whitelist_cwd_fallback_untouched_when_mock(mock_on, fake_prod_cwd):
    root_before = _sha(ROOT_WHITELIST)
    before = fake_prod_cwd.read_bytes()

    ok_add, msg_add = utils.add_to_whitelist("10.2.57.246", "test")
    ok_rm, msg_rm = utils.remove_from_whitelist("10.9.9.9")

    assert (ok_add, ok_rm) == (False, False)
    assert "MOCK" in msg_add and "MOCK" in msg_rm
    assert fake_prod_cwd.read_bytes() == before, "whitelist di cwd tertimpa saat MINISOAR_MOCK=1"
    assert _sha(ROOT_WHITELIST) == root_before, "minisoar-whitelist.txt di root repo tertimpa"


def test_whitelist_explicit_path_still_works_when_mock(mock_on, fake_prod_cwd, tmp_path, monkeypatch):
    explicit = tmp_path / "sub" / "wl.txt"
    monkeypatch.setenv("WHITELIST_PATH", str(explicit))
    before = fake_prod_cwd.read_bytes()

    ok, _ = utils.add_to_whitelist("10.2.57.246", "test")
    assert ok is True
    assert "10.2.57.246" in explicit.read_text(encoding="utf-8")
    ok, _ = utils.remove_from_whitelist("10.2.57.246")
    assert ok is True
    assert "10.2.57.246" not in explicit.read_text(encoding="utf-8")
    assert fake_prod_cwd.read_bytes() == before


def test_whitelist_cwd_fallback_still_writes_when_mock_off(mock_off, fake_prod_cwd):
    """Arah sebaliknya: di produksi Windows fallback cwd tetap dipakai."""
    ok, _ = utils.add_to_whitelist("10.2.57.246", "test")
    assert ok is True
    assert "10.2.57.246" in fake_prod_cwd.read_text(encoding="utf-8")
    ok, _ = utils.remove_from_whitelist("10.9.9.9")
    assert ok is True
    assert "10.9.9.9" not in fake_prod_cwd.read_text(encoding="utf-8")
