"""BUG 5 regression: handler tidak boleh memblokir event loop.

Masalah: handler Telegram meng-`await` fungsi SINKRON yang melakukan I/O blocking
(perimeter API, Elasticsearch, Redis). Satu perimeter yang lambat membekukan SELURUH
bot -- tidak ada user lain yang bisa dilayani. Untuk alat darurat SOC ini persis
kondisi yang paling tidak diinginkan.

Yang diuji di sini bukan "hasilnya benar" (test lain sudah cover itu), tapi:

  1. Event loop tetap responsif selama handler menjalankan I/O blocking.
  2. Dua handler jalan paralel, bukan serial.
  3. I/O di handler dijalankan DI LUAR thread event loop (guard anti-regresi yang
     tidak bergantung timing, jadi tidak flaky).

Catatan: daemon.py dan playbook/ sengaja TIDAK disentuh. Keduanya sinkron dan tidak
punya event loop, jadi asyncio.to_thread tidak ada gunanya di sana.

Semua test pakai asyncio.run() (bukan @pytest.mark.asyncio) karena pytest-asyncio
tidak terpasang di environment ini -- marker hanya akan membuat test diam-diam
di-skip, dan regression test yang diam-diam di-skip sama ruginya dengan tidak ada.
"""

import asyncio
import os
import threading
import time

from minisoar import bot as botmod

# stub I/O blocking: sleep sinkron, persis seperti requests/redis yang memblokir
SLEEP = 0.2

# batas: dua handler serial = ~0.4s, paralel = ~0.2s. Ambil di tengah.
CONCURRENCY_BUDGET = 0.35


class _Msg:
    date = "2024-01-01T00:00:00Z"
    message_id = 4242

    def __init__(self):
        self.replies = []

    async def reply_text(self, *a, **kw):
        self.replies.append(a[0] if a else "")


class _Update:
    def __init__(self, user_id=12345):
        self.effective_user = type("U", (), {"id": user_id})()
        self.effective_chat = type("C", (), {"id": -100123})()
        self.message = _Msg()
        self.callback_query = None


class _Ctx:
    def __init__(self, *args):
        self.args = list(args)


def _slow_block(*a, **kw):
    """I/O blocking: sleep sinkron."""
    time.sleep(SLEEP)
    return True, "ok"


def _stub_blocking_io(monkeypatch):
    """Stub I/O handler blockonimperva supaya blocking + lambat."""
    monkeypatch.setattr(botmod, "log_user_action", lambda *a, **kw: None)
    monkeypatch.setattr(botmod, "resolve_log_path", lambda *a, **kw: "/tmp/x.log")
    monkeypatch.setattr(botmod, "redis_client", lambda: object())
    monkeypatch.setattr(botmod, "register_block_state", lambda *a, **kw: None)
    monkeypatch.setattr(botmod, "es_find_latest_event_id_by_ip", lambda *a, **kw: "evt-1")
    monkeypatch.setattr(botmod, "store_label", lambda *a, **kw: None)
    monkeypatch.setattr(botmod, "trigger_auto_block", _slow_block)


# --- Test 1: bounded time, I/O blocking tidak menggantung bot ---


def test_handler_with_blocking_io_completes_in_bounded_time(monkeypatch):
    """Handler selesai dalam waktu terikat meski I/O-nya blocking."""
    _stub_blocking_io(monkeypatch)

    t0 = time.perf_counter()
    asyncio.run(botmod.blockonimperva(_Update(), _Ctx("10.0.0.1")))
    elapsed = time.perf_counter() - t0

    # batas longgar supaya tidak flaky di CI lambat; tetap menangkap "nge-hang"
    assert elapsed < SLEEP * 10, f"handler menggantung {elapsed:.2f}s"


# --- Test 2: concurrency, dua handler jalan paralel bukan serial ---


def test_two_blocking_handlers_run_concurrently(monkeypatch):
    """Dua handler yang masing-masing sleep 0.2s harus total < 0.35s.

    Test paling bernilai. Kalau offload tidak terjadi (langsung await fungsi sinkron
    di event loop), keduanya serial dan totalnya ~0.4s+.
    """
    _stub_blocking_io(monkeypatch)

    async def _both():
        await asyncio.gather(
            botmod.blockonimperva(_Update(), _Ctx("10.0.0.1")),
            botmod.blockonimperva(_Update(), _Ctx("10.0.0.2")),
        )

    t0 = time.perf_counter()
    asyncio.run(_both())
    elapsed = time.perf_counter() - t0

    assert elapsed < CONCURRENCY_BUDGET, (
        f"dua handler tidak paralel ({elapsed:.2f}s) -- event loop terblokir"
    )


# --- Test 3: event loop tetap bisa melayani task lain (anti-freeze) ---


def test_event_loop_stays_responsive_during_blocking_handler(monkeypatch):
    """Selama handler jalan, task lain di event loop tetap jalan.

    Inilah "user lain bisa dilayani" secara harfiah: kalau handler memblokir loop,
    counter task lain ini tidak bergerak sama sekali.
    """
    _stub_blocking_io(monkeypatch)

    async def _run():
        ticks = 0
        stop = False

        async def _beat():
            nonlocal ticks
            while not stop:
                ticks += 1
                await asyncio.sleep(0.01)

        beater = asyncio.create_task(_beat())
        await botmod.blockonimperva(_Update(), _Ctx("10.0.0.1"))
        stop = True
        await beater
        return ticks

    ticks = asyncio.run(_run())
    assert ticks > 0, "event loop tidak bergerak selama handler -> bot membeku"


# --- Test 4: guard anti-regresi tanpa timing (anti-flaky) ---


def test_blockonimperva_runs_blocking_io_off_event_loop(monkeypatch):
    """Semua I/O di handler ini harus dieksekusi DI LUAR thread event loop.

    Guard ini yang membuat test 1-3 tidak rapuh: kalau offload hilang suatu saat,
    test ini langsung gagal deterministik -- bukan cuma "kebetulan timing meleset".
    """
    seen = []
    main_thread = threading.get_ident()

    def _rec(name, ret):
        def _f(*a, **kw):
            seen.append((name, threading.get_ident()))
            return ret() if callable(ret) else ret
        return _f

    monkeypatch.setattr(botmod, "log_user_action", lambda *a, **kw: None)
    monkeypatch.setattr(botmod, "resolve_log_path", lambda *a, **kw: "/tmp/x.log")
    monkeypatch.setattr(botmod, "redis_client", _rec("redis_client", object))
    monkeypatch.setattr(botmod, "register_block_state", _rec("register_block_state", lambda: None))
    monkeypatch.setattr(botmod, "es_find_latest_event_id_by_ip", _rec("es_find", lambda: "evt-1"))
    monkeypatch.setattr(botmod, "store_label", _rec("store_label", lambda: None))
    monkeypatch.setattr(botmod, "trigger_auto_block", _rec("trigger_auto_block", lambda: (True, "ok")))

    asyncio.run(botmod.blockonimperva(_Update(), _Ctx("10.0.0.1")))

    assert seen, "tidak ada I/O yang tercatat"
    on_loop = sorted(n for n, tid in seen if tid == main_thread)
    assert not on_loop, f"I/O ini jalan di thread event loop (memblokir bot): {on_loop}"

    offloaded = {n for n, tid in seen if tid != main_thread}
    assert {"trigger_auto_block", "redis_client"} <= offloaded, (
        f"I/O ini tidak ter-offload: {sorted({'trigger_auto_block', 'redis_client'} - offloaded)}"
    )

# ---------------------------------------------------------------------------
# BUG 5b: call site berbentuk `mod.f(...)` yang terlewat di BUG 5
#
# Test 1-4 di atas semuanya jalan di MINISOAR_MOCK=1, di mana `cases.*`dsb
# return duluan sebelum menyentuh jaringan. Jadi hijau di situ tidak berarti
# apa-apa. Test di bawah sengaja MEMATIKAN mock dan meny-stub `requests` dengan
# `time.sleep`, supaya jalur blocking yang sebenarnya ikut teruji.
# ---------------------------------------------------------------------------

# Call site yang WAJIB ter-offload. Dihitung manual satu per satu, bukan
# tebakan: lihat test_live_mode_* di bawah untuk yang dibuktikan runtime.
MUST_OFFLOAD = {
    # EDR -> kaspersky/trendmicro HTTP
    "edr.add_edr_ioc", "edr.isolate_endpoint", "edr.restore_endpoint",
    # Cases -> Elasticsearch + ticketing HTTP
    "cases.get_case", "cases.list_cases", "cases.update_case_status",
    "cases.sync_case_to_ticketing", "cases.get_soc_metrics",
    "cases.generate_case_markdown_report",
    # Perimeter HTTP
    "paloalto.partial_commit", "paloalto.query_threat_log",
    "imperva.login_via_api", "imperva.get_violation_by_event_number",
    "akamai.query_siem_events",
    "cloudflare.block_ip", "cloudflare.unblock_ip",
    "fortigate.block_ip", "fortigate.unblock_ip",
    # LLM -> HTTP ke provider AI
    "ai.ask_copilot", "ai.generate_rca",
    # dippinganggil lewat nama variabel lokal, jadi tidak pernah kena modul apa pun
    "session.post", "r.setex",
}

LIVE_CASE_ID = "INC-OFFLOAD-LIVE-0001"


def _go_live(monkeypatch):
    """Matikan MINISOAR_MOCK supaya `cases.*` benar-benar kena HTTP."""
    assert os.getenv("MINISOAR_MOCK") == "1", "conftest QA tidak meng-set mock"
    monkeypatch.delenv("MINISOAR_MOCK", raising=False)
    assert os.getenv("MINISOAR_MOCK") is None


def _stub_slow_requests(mod, monkeypatch, sleep=SLEEP):
    """Stub requests.get/put/post jadi blocking, dan catat thread pemanggilnya."""
    seen = []

    def _mk(name, status=404):
        def _f(url, *a, **kw):
            seen.append((name, url, threading.get_ident()))
            time.sleep(sleep)
            return type("Resp", (), {
                "status_code": status,
                "json": lambda: {"activationStatus": "PROCESSING",
                                 "activationId": "1", "version": "2"},
            })()
        return _f

    for name in ("get", "put", "post"):
        monkeypatch.setattr(mod.requests, name, _mk(name))
    return seen


# --- Test 5: jalur LIVE (mock mati), identitas thread (deterministik) ---

def test_live_mode_blocking_http_runs_off_main_thread(monkeypatch):
    """`requests` yang dipanggil jalur live harus jalan di luar thread event loop.

    Guard deterministik: kalau `cases.get_case` balik lagi jadi panggilan sinkron
    langsung, test ini gagal tanpa bergantung timing sama sekali.
    """
    from minisoar.cases import core as cases_core

    _go_live(monkeypatch)
    monkeypatch.setenv("ES_HOSTS", "http://es.invalid:9200")
    cases_core._LOCAL_CASE_STORE.pop(LIVE_CASE_ID, None)
    seen = _stub_slow_requests(cases_core, monkeypatch)

    main_thread = threading.get_ident()
    asyncio.run(botmod.case_cmd(_Update(), _Ctx(LIVE_CASE_ID)))

    assert seen, "requests.get tidak pernah dipanggil"
    on_loop = [u for _n, u, tid in seen if tid == main_thread]
    assert not on_loop, f"HTTP blocking jalan di thread event loop: {on_loop}"

# --- Test 6: jalur LIVE, 2 POST berurutan (activateakamai) ---

def test_live_mode_activateakamai_posts_off_main_thread(monkeypatch):
    """`session.post` (raw requests) harus ter-offload juga.

    Panggilan ini lewat nama variabel lokal, jadi skrip transformasi BUG 5 yang
    hanya menangkap `f(...)` dan `mod.f(...)` tidak pernah melihatnya — dan
    karena itu juga tidak bisa dikunci oleh guard statis Test 7.
    """
    from minisoar import mitigation as _  # noqa: F401  (pastikan terimport)
    from minisoar.mitigation import akamai as akamai_mod

    _go_live(monkeypatch)
    monkeypatch.setattr(botmod, "log_user_action", lambda *a, **kw: None)
    monkeypatch.setattr(botmod, "resolve_log_path", lambda *a, **kw: "/tmp/x.log")
    seen = _stub_slow_requests(akamai_mod, monkeypatch)

    class _Session:
        post = staticmethod(lambda url, **kw: akamai_mod.requests.post(url, **kw))

    monkeypatch.setattr(botmod.akamai, "akamai_session", lambda **kw: _Session())

    main_thread = threading.get_ident()
    asyncio.run(botmod.activateakamai(_Update(), _Ctx("1.2.3.4")))

    posts = [s for s in seen if s[0] == "post"]
    assert len(posts) == 2, f"sthaling POST = {len(posts)} (STAGING+PRODUCTION)"
    on_loop = [u for _n, u, tid in posts if tid == main_thread]
    assert not on_loop, f"POST blocking jalan di thread event loop: {on_loop}"

# --- Test 8: kunci daftar call site (guard anti-regresi, tanpa timing) ---

def test_every_blocking_module_call_site_is_offloaded():
    """Semua `mod.f(...)` di MUST_OFFLOAD harus jadi `await asyncio.to_thread(mod.f, ...)`.

    Guard statis: menangkap regresi ke sinkron tanpa perlu test timing, dan
    sekaligus mengunci daftar call site yang wajib ter-offload supaya tidak
    ada yang "dilewati diam-diam" seperti di BUG 5.
    """
    import ast
    import pathlib

    src = pathlib.Path(botmod.__file__).read_text()
    tree = ast.parse(src)

    # id() dari argumen pertama setiap asyncio.to_thread(...) yang sudah ada
    wrapped = set()
    for n in ast.walk(tree):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == "to_thread"
                and isinstance(n.func.value, ast.Name)
                and n.func.value.id == "asyncio" and n.args):
            wrapped.add(id(n.args[0]))

    # id() dari setiap await yang membungkus to_thread
    awaited = set()
    for n in ast.walk(tree):
        if (isinstance(n, ast.Await) and isinstance(n.value, ast.Call)
                and n.value.args and id(n.value) in wrapped):
            awaited.add(id(n.value.args[0]))

    offenders = []
    for fn in tree.body:
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            f = getattr(n, "func", None)
            if not (isinstance(n, ast.Call) and isinstance(f, ast.Attribute)
                    and isinstance(f.value, ast.Name)):
                continue
            key = f"{f.value.id}.{f.attr}"
            if key in MUST_OFFLOAD and id(n) not in awaited:
                offenders.append(f"bot.py:{n.lineno} {key} [{fn.name}]")

    assert not offenders, "call site blocking ini TIDAK ter-offload:\n  " + "\n  ".join(offenders)

