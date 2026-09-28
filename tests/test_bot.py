import os
from pathlib import Path

import pytest
from minisoar.bot import _format_usage_html, auth_guard, is_user_allowed


def _fake_update(user_id):
    """Update Telegram palsu: hanya fields yang disentuh auth_guard."""
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


def test_format_usage_html():
    msg = _format_usage_html("block_imperva", "<ip>", "192.168.1.100", desc="Blokir IP di Imperva WAF")
    assert "<b>Format Tidak Valid</b>" in msg
    assert "<code>/block_imperva &lt;ip&gt;</code>" in msg
    assert "<code>/block_imperva 192.168.1.100</code>" in msg
    assert "Blokir IP di Imperva WAF" in msg


def test_is_user_allowed(monkeypatch):
    monkeypatch.setenv("ALLOWED_USERS", "12345,67890")
    assert is_user_allowed(12345) is True
    assert is_user_allowed(99999) is False


def test_auth_guard_blocks_and_allows(monkeypatch):
    import asyncio
    monkeypatch.setenv("ALLOWED_USERS", "12345")
    called = []

    async def handler(update, context):
        called.append(update.effective_user.id)
        return "ran"

    guarded = auth_guard(handler)

    up_blocked = _fake_update(99999)
    assert asyncio.run(guarded(up_blocked, None)) is None
    assert called == []
    assert "tidak punya akses" in up_blocked.replies[0]

    up_ok = _fake_update(12345)
    assert asyncio.run(guarded(up_ok, None)) == "ran"
    assert called == [12345]
    assert up_ok.replies == []


# --- Regresi P0: auth_guard harus benar-benar terpasang di main() ---
#
# Handler python-telegram-bot memakai __slots__ (tidak punya __dict__), jadi
# menandai handler langsung melempar AttributeError. Karena main() hanya
# menangkap KeyboardInterrupt, bot crash saat start. Test auth_guard di atas
# hanya menguji dekoratornya dan tetap hijau saat middleware mati total —
# yang perlu dijaga adalah instalasi pasangannya di main().


def test_main_installs_auth_guard_on_every_handler(monkeypatch):
    import minisoar.bot as botmod

    captured = {}

    class _FakeApp:
        def __init__(self):
            self.handlers = {}
            self.error_handler = None

        def add_handler(self, handler):
            self.handlers.setdefault(type(handler).__name__, []).append(handler)

        def add_error_handler(self, fn):
            self.error_handler = fn

        def run_polling(self, *a, **kw):
            pass

    class _FakeBuilder:
        def token(self, _t):
            return self

        def post_init(self, _fn):
            return self

        def build(self):
            captured["app"] = _FakeApp()
            return captured["app"]

    monkeypatch.setenv("MINISOAR_MOCK", "1")
    monkeypatch.setenv("TELEGRAM_TOKEN", "123456:FAKE")
    monkeypatch.setattr(botmod, "ApplicationBuilder", _FakeBuilder)

    # Melempar AttributeError ke pytest kalau pemasangan guard rusak.
    botmod.main()

    handlers = [h for group in captured["app"].handlers.values() for h in group]
    assert handlers, "tidak ada handler terdaftar -- stub builder tidak terbaca"
    unguarded = [h for h in handlers
                 if not getattr(h.callback, "_minisoar_guarded", False)]
    assert not unguarded, f"{len(unguarded)} handler tanpa auth_guard"


def test_auth_guard_blocks_callback_query(monkeypatch):
    import asyncio
    monkeypatch.setenv("ALLOWED_USERS", "12345")
    alerts = []

    class _Query:
        from_user = type("U", (), {"id": 99999})()

        async def answer(self, text, **kw):
            alerts.append(text)

    class _Update:
        effective_user = None
        message = None
        callback_query = _Query()

    async def handler(update, context):
        raise AssertionError("handler tidak boleh jalan untuk user tak diizinkan")

    asyncio.run(auth_guard(handler)(_Update(), None))
    assert "tidak punya akses" in alerts[0]


def test_auth_guard_preserves_handler_metadata():
    async def health_cmd(update, context):
        pass

    assert auth_guard(health_cmd).__name__ == "health_cmd"


def test_no_handler_has_manual_auth_check():
    """auth_guard jadi satu-satunya pintu auth; blok manual harus dihapus dari handler."""
    import inspect
    import minisoar.bot as botmod

    offenders = [
        name for name, fn in vars(botmod).items()
        if inspect.isfunction(fn) and fn.__module__ == botmod.__name__
        and name not in ("auth_guard", "is_user_allowed") and "is_user_allowed(" in inspect.getsource(fn)
    ]
    assert offenders == [], f"masih ada cek auth manual di: {offenders}"


def test_whitelist_management(monkeypatch):
    import tempfile
    with tempfile.TemporaryDirectory() as tmp_dir:
        wl_file = os.path.join(tmp_dir, "whitelist.txt")
        monkeypatch.setenv("WHITELIST_PATH", wl_file)

        from minisoar.utils import add_to_whitelist, get_whitelist_entries, remove_from_whitelist

        # Add IP
        ok, msg = add_to_whitelist("10.2.57.246", "Internal Server")
        assert ok is True
        assert "10.2.57.246" in msg

        entries = get_whitelist_entries()
        assert len(entries) == 1
        assert "10.2.57.246" in entries[0]

        # Remove IP
        ok, msg = remove_from_whitelist("10.2.57.246")
        assert ok is True
        assert get_whitelist_entries() == []



def test_get_system_health():
    from minisoar.database import get_system_health
    h = get_system_health()
    assert "redis" in h
    assert "elasticsearch" in h
    assert "ai" in h


# --- BUG 1: blok duplikat di unblockonpalo menyebabkan trigger_auto_unblock 2x ---


def _stub_unblock_deps(monkeypatch, calls, labels, ok=True, msg="ok", user_id=12345):
    """Stub semua dependency jaringan/redis/labelling untuk handler unblock."""
    import minisoar.bot as botmod
    monkeypatch.setattr(botmod, "resolve_log_path", lambda *a, **k: "/tmp/x.log")
    monkeypatch.setattr(botmod, "log_user_action", lambda *a, **k: None)
    monkeypatch.setattr(botmod, "es_get_latest_event_website_by_ip", lambda ip: "contoh.co.id")
    monkeypatch.setattr(botmod, "get_perimeter_info", lambda w, p: ([], True, None))
    monkeypatch.setattr(botmod, "redis_client", lambda: object())
    monkeypatch.setattr(botmod, "remove_block_state", lambda *a, **k: None)
    monkeypatch.setattr(botmod, "es_find_latest_event_id_by_ip", lambda ip, approx_dt=None: "evt-1")
    monkeypatch.setattr(
        botmod,
        "store_label",
        lambda event_id, label, user, source, **kw: labels.append((event_id, label, source)),
    )
    monkeypatch.setattr(
        botmod,
        "trigger_auto_unblock",
        lambda ip, perimeter, commit=False: (calls.append((ip, perimeter)), (ok, msg))[1],
    )


class _Ctx:
    def __init__(self, *args):
        self.args = list(args)


def test_unblockonpalo_triggers_auto_unblock_only_once(monkeypatch):
    import asyncio
    import minisoar.bot as botmod

    calls, labels = [], []
    _stub_unblock_deps(monkeypatch, calls, labels)

    update = _fake_update(12345)
    asyncio.run(botmod.unblockonpalo(update, _Ctx("10.0.0.1")))

    assert calls == [("10.0.0.1", "paloalto")], f"trigger_auto_unblock dipanggil {len(calls)}x"
    # blok duplikat juga mengirim 2 balasan "Menghapus ... dari IP group Palo Alto"
    assert sum("IP group Palo Alto" in r for r in update.replies) == 1


def test_unblockonpalo_redirect_unmapped_returns_after_imperva(monkeypatch):
    import asyncio
    import minisoar.bot as botmod

    calls, labels = [], []
    _stub_unblock_deps(monkeypatch, calls, labels)
    monkeypatch.setattr(botmod, "get_perimeter_info", lambda w, p: ([], False, None))

    update = _fake_update(12345)
    asyncio.run(botmod.unblockonpalo(update, _Ctx("10.0.0.1")))

    assert calls == [("10.0.0.1", "imperva")]
    assert "IP group Palo Alto" not in "".join(update.replies)


# --- BUG 2: string literal {network} terkirim apa adanya ke Akamai API ---


def test_activateakamai_interpolates_network_in_comment(monkeypatch):
    import asyncio
    import minisoar.bot as botmod

    bodies = []

    class _Resp:
        status_code = 200

        def json(self):
            return {"activationStatus": "IN_PROGRESS", "activationId": "a-1", "version": "v1"}

    class _Session:
        def post(self, url, headers=None, json=None):
            bodies.append(json)
            return _Resp()

    _stub_unblock_deps(monkeypatch, [], [])
    monkeypatch.setattr(botmod.akamai, "akamai_session", lambda **kw: _Session())
    monkeypatch.setattr(botmod.akamai, "akamai_url", lambda base, path: "https://akamai.test")

    update = _fake_update(12345)
    asyncio.run(botmod.activateakamai(update, _Ctx()))

    assert len(bodies) == 2
    assert bodies[0]["comments"] == "Aktivasi manual ke STAGING via bot"
    assert bodies[1]["comments"] == "Aktivasi manual ke PRODUCTION via bot"


# --- BUG 3: jalur unblock tidak pernah melabeli event sebagai "unblock" ---


def test_unblockonimperva_stores_unblock_label(monkeypatch):
    import asyncio
    import minisoar.bot as botmod

    calls, labels = [], []
    _stub_unblock_deps(monkeypatch, calls, labels)

    asyncio.run(botmod.unblockonimperva(_fake_update(12345), _Ctx("10.0.0.1")))

    assert labels == [("evt-1", "unblock", "telegram_command")]


def test_unblockonpalo_stores_unblock_label(monkeypatch):
    import asyncio
    import minisoar.bot as botmod

    calls, labels = [], []
    _stub_unblock_deps(monkeypatch, calls, labels)

    asyncio.run(botmod.unblockonpalo(_fake_update(12345), _Ctx("10.0.0.1")))

    assert labels == [("evt-1", "unblock", "telegram_command")]


def test_unblockonakamai_stores_unblock_label(monkeypatch):
    import asyncio
    import minisoar.bot as botmod

    calls, labels = [], []
    _stub_unblock_deps(monkeypatch, calls, labels)

    asyncio.run(botmod.unblockonakamai(_fake_update(12345), _Ctx("10.0.0.1")))

    assert labels == [("evt-1", "unblock", "telegram_command")]


def test_unblockoncf_cmd_stores_unblock_label(monkeypatch):
    import asyncio
    import minisoar.bot as botmod

    labels = []
    _stub_unblock_deps(monkeypatch, [], labels)
    monkeypatch.setattr(botmod.cloudflare, "unblock_ip", lambda ip: (True, "sukses"))

    asyncio.run(botmod.unblockoncf_cmd(_fake_update(12345), _Ctx("10.0.0.1")))

    assert labels == [("evt-1", "unblock", "telegram_command")]


def test_unblockonforti_cmd_stores_unblock_label(monkeypatch):
    import asyncio
    import minisoar.bot as botmod

    labels = []
    _stub_unblock_deps(monkeypatch, [], labels)
    monkeypatch.setattr(botmod.fortigate, "unblock_ip", lambda ip: (True, "sukses"))

    asyncio.run(botmod.unblockonforti_cmd(_fake_update(12345), _Ctx("10.0.0.1")))

    assert labels == [("evt-1", "unblock", "telegram_command")]


def test_unblock_failed_does_not_store_label(monkeypatch):
    """Label hanya ditulis kalau unblock benar-benar sukses."""
    import asyncio
    import minisoar.bot as botmod

    calls, labels = [], []
    _stub_unblock_deps(monkeypatch, calls, labels, ok=False, msg="gagal")

    asyncio.run(botmod.unblockonimperva(_fake_update(12345), _Ctx("10.0.0.1")))

    assert labels == []



# --- BUG 4: regresi auth_guard -> `user` undefined -> NameError di happy path ---
#
# Regresi ini tidak ketahuan test lama karena semuanya cuma menguji jalur validasi
# argumen (yang return duluan). Yang bikin meledak baru adalah jalur sukses.
#
# Dua lapis proteksi:
#   1. test static (AST)  -- menangkap handler mana pun yang belum bind `user`
#   2. test runtime E2E   -- bukti nyata jalannya handler sampai selesai

import ast as _ast
import builtins as _builtins

_BOT_PY = _ast.parse((Path(__file__).resolve().parents[1] / "minisoar" / "bot.py").read_text())


def _module_level_names(tree):
    """Nama yang tersedia di module scope.

    PENTING: hanya kumpulkan dari statement module-level (termasuk di dalam
    if/try/while module-level). Kalau ikut masuk ke body function, semua variabel
    lokal tiap handler ikut terhitung dan test ini selalu lolos.
    """
    names = set()
    stop = (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef, _ast.Lambda)

    def walk(stmts):
        for node in stmts:
            if isinstance(node, stop):
                names.add(node.name)  # nama def-nya sendiri ada di module scope
                for d in node.decorator_list:
                    walk([d])
                continue
            if isinstance(node, _ast.Import):
                for a in node.names:
                    names.add(a.asname or a.name.split(".")[0])
            elif isinstance(node, _ast.ImportFrom):
                for a in node.names:
                    names.add(a.asname or a.name)
            elif isinstance(node, (getattr(_ast, "Assign", ()), _ast.AnnAssign)):
                targets = node.targets if isinstance(node, _ast.Assign) else [node.target]
                for t in targets:
                    if isinstance(t, _ast.Name):
                        names.add(t.id)
                    else:
                        names.update(
                            s.id for s in _ast.walk(t)
                            if isinstance(s, _ast.Name) and isinstance(s.ctx, _ast.Store)
                        )
            elif isinstance(node, (_ast.For, _ast.AsyncFor)):
                tgt = node.target
                walk(tgt.elts if isinstance(tgt, _ast.Tuple) else [tgt])
            elif isinstance(node, (_ast.With, _ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        walk([item.optional_vars])
            elif isinstance(node, (_ast.If, _ast.While)):
                walk(node.body + node.orelse)
            elif isinstance(node, _ast.Try):
                walk(node.body + node.orelse + node.finalbody)
                for h in node.handlers:
                    if h.name:
                        names.add(h.name)
                    walk(h.body)

    walk(tree.body)
    return names


def _bound_names(fn):
    """Nama yang ter-bind di body function: assign, arg, walrus, import, except-as, dll."""
    out = set()
    for node in _ast.walk(fn):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef)):
            out.add(node.name)
        elif isinstance(node, _ast.Lambda):
            out.update(a.arg for a in node.args.args + node.args.kwonlyargs)
        elif isinstance(node, _ast.Name) and isinstance(node.ctx, (_ast.Store, _ast.Del)):
            out.add(node.id)
        elif isinstance(node, _ast.arg):
            out.add(node.arg)
        elif isinstance(node, (_ast.Import, _ast.ImportFrom)):
            for a in node.names:
                out.add(a.asname or a.name.split(".")[0])
        elif isinstance(node, _ast.ExceptHandler) and node.name:
            out.add(node.name)
        elif isinstance(node, (_ast.Global, _ast.Nonlocal)):
            out.update(node.names)
    return out


def test_no_undefined_names_in_bot_handlers():
    """BUG 4 regression: tidak boleh ada nama yang dibaca tapi tak ter-bind.

    Menangkap kelas bug yang tidak bisaridden test runtime -- handler yang
    jalurnya tidak pernah dieksekusi unit test tetap akan terdeteksi di sini.
    """
    module_names = _module_level_names(_BOT_PY)
    builtins_set = set(dir(_builtins))

    problems = []
    for fn in _BOT_PY.body:
        if not isinstance(fn, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            continue
        loaded = {
            n.id for n in _ast.walk(fn)
            if isinstance(n, _ast.Name) and isinstance(n.ctx, _ast.Load)
        }
        for name in sorted(loaded - _bound_names(fn) - module_names - builtins_set):
            problems.append(f"{fn.name} (def baris {fn.lineno}): nama tak ter-bind {name!r}")

    assert not problems, (
        "handler memakai nama yang tidak pernah didefinisikan -> NameError saat dipanggil:\n  "
        + "\n  ".join(problems)
    )


def test_every_handler_using_user_binds_it():
    """Fokus: `user` HARUS ter-bind di setiap handler yang memakainya.

    `user` dipakai untuk audit log (log_user_action/store_label), jadi kalau
    hilang, seluruh jalur sukses akan meledak.
    """
    module_names = _module_level_names(_BOT_PY)
    offenders = []
    for fn in _BOT_PY.body:
        if not isinstance(fn, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            continue
        uses_user = any(
            isinstance(n, _ast.Name) and n.id == "user" and isinstance(n.ctx, _ast.Load)
            for n in _ast.walk(fn)
        )
        if not uses_user:
            continue
        if "user" in _bound_names(fn) or "user" in module_names:
            continue
        offenders.append(f"{fn.name} (def baris {fn.lineno})")

    assert not offenders, (
        "handler ini memakai `user` tapi tidak pernah meng-assign-nya -> "
        "NameError di happy path:\n  " + "\n  ".join(offenders)
    )


def test_blockonimperva_happy_path_runs_to_completion(monkeypatch):
    """BUG 4 E2E: handler yang tadinya meledak harus jalan sampai selesai.

    Jalur sukses (bukan jalur validasi arg) dengan user yang sah.
    """
    import asyncio
    import minisoar.bot as botmod

    blocked = []
    labels = []

    monkeypatch.setattr(botmod, "log_user_action", lambda *a, **k: None)
    monkeypatch.setattr(botmod, "resolve_log_path", lambda *a, **k: "/tmp/x.log")
    monkeypatch.setattr(botmod, "redis_client", lambda: object())
    monkeypatch.setattr(botmod, "register_block_state", lambda *a, **k: None)
    monkeypatch.setattr(botmod, "es_find_latest_event_id_by_ip", lambda ip, approx_dt=None: "evt-1")
    monkeypatch.setattr(
        botmod, "store_label",
        lambda eid, label, user, source, **kw: labels.append((eid, label, user.id)),
    )
    monkeypatch.setattr(
        botmod, "trigger_auto_block",
        lambda ip, perimeter: (blocked.append((ip, perimeter)), (True, f"{ip} diblokir"))[1],
    )

    update = _fake_update(12345)
    asyncio.run(botmod.blockonimperva(update, _Ctx("10.0.0.1")))

    # hanya bisa lolos kalau `user` ter-bind: store_label butuh user.id
    assert blocked == [("10.0.0.1", "imperva")]
    assert labels == [("evt-1", "block", 12345)]
