"""Bug produksi whitelist & path audit log.

1. Daemon membaca whitelist dari path berbeda dengan yang ditulis bot
   (WHITELIST_FILE relatif → cwd vs WHITELIST_PATH → /etc/logstash di Linux).
2. Entri dengan "  # alasan" (format yang SELALU ditulis add_to_whitelist)
   tidak cocok di daemon, dan membuat pengecekan duplikat gagal.
3. ExecutionContext.logfile hardcode relatif, tidak lewat resolve_log_path.
"""

import hashlib
import os
from pathlib import Path

import pytest

import minisoar.daemon as daemon
import minisoar.utils as utils
from minisoar.playbook import ExecutionContext

ROOT = Path(__file__).resolve().parent.parent
ROOT_LOG = ROOT / "tele-soar-actions.log"


def _sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None


class _StopDaemon(Exception):
    pass


def _daemon_whitelist_path(monkeypatch):
    """Jalankan daemon.main sampai whitelist dimuat, kembalikan path yang dibacanya."""
    seen = {}

    def fake_load(env_key, file_path):
        if env_key == "WHITELIST_IPS":
            seen["path"] = file_path
            raise _StopDaemon
        return []

    monkeypatch.setattr(daemon, "load_env", lambda *a, **kw: None)
    # Tambal di kedua tempat: daemon bisa memuat langsung atau lewat
    # utils.reload_cidr_list_if_changed. Kalau stop ini tidak kena, daemon.main
    # masuk loop utama dan menggantung di Redis.
    monkeypatch.setattr(daemon, "load_cidr_list_from_env_and_file", fake_load)
    monkeypatch.setattr(utils, "load_cidr_list_from_env_and_file", fake_load)
    with pytest.raises(_StopDaemon):
        daemon.main()
    return seen["path"]


@pytest.fixture
def linux_like(monkeypatch, tmp_path):
    """Simulasikan host Linux produksi: /etc/logstash ada & writable."""
    # Proxy, bukan menambal modul os global: os.name="posix" global membuat
    # pathlib mencoba PosixPath di Windows.
    class _Path:
        def __getattr__(self, n):
            return getattr(os.path, n)

        @staticmethod
        def exists(p):
            return p == "/etc/logstash" or os.path.exists(p)

    class _Os:
        name = "posix"
        path = _Path()

        def __getattr__(self, n):
            return getattr(os, n)

        @staticmethod
        def access(p, mode):
            return p == "/etc/logstash" or os.access(p, mode)

    monkeypatch.setattr(utils, "os", _Os())
    monkeypatch.chdir(tmp_path)
    for k in ("WHITELIST_PATH", "WHITELIST_FILE"):
        monkeypatch.delenv(k, raising=False)


# --- Bug 1: path tulis bot == path baca daemon ----------------------------------

def test_daemon_reads_whitelist_from_same_path_bot_writes_linux(linux_like, monkeypatch):
    bot_path = utils.resolve_whitelist_path()
    daemon_path = _daemon_whitelist_path(monkeypatch)
    assert bot_path == "/etc/logstash/minisoar-whitelist.txt"
    assert daemon_path == bot_path, f"bot menulis ke {bot_path}, daemon membaca {daemon_path}"


def test_daemon_honors_whitelist_path_override(monkeypatch, tmp_path):
    target = str(tmp_path / "wl.txt")
    monkeypatch.setenv("WHITELIST_PATH", target)
    monkeypatch.delenv("WHITELIST_FILE", raising=False)
    assert _daemon_whitelist_path(monkeypatch) == target


def test_legacy_whitelist_file_env_still_honored(monkeypatch, tmp_path):
    """Deployment yang dulu menyetel WHITELIST_FILE tidak boleh kehilangan whitelist."""
    legacy = str(tmp_path / "legacy.txt")
    monkeypatch.delenv("WHITELIST_PATH", raising=False)
    monkeypatch.setenv("WHITELIST_FILE", legacy)
    assert utils.resolve_whitelist_path() == legacy
    assert _daemon_whitelist_path(monkeypatch) == legacy


def test_ip_added_via_bot_is_whitelisted_by_daemon(monkeypatch, tmp_path):
    """End-to-end: add_to_whitelist (format '<ip>  # alasan') → loader daemon → match."""
    monkeypatch.setenv("WHITELIST_PATH", str(tmp_path / "wl.txt"))
    monkeypatch.delenv("WHITELIST_IPS", raising=False)

    ok, _ = utils.add_to_whitelist("10.2.57.246", "Internal Server")
    assert ok is True

    nets = utils.load_cidr_list_from_env_and_file("WHITELIST_IPS", utils.resolve_whitelist_path())
    assert utils.is_ip_whitelisted("10.2.57.246", nets), f"daemon tidak mengenali entri bot: {nets}"


def test_commented_entry_does_not_hide_later_entries(monkeypatch, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("1.1.1.1  # Gateway\n10.0.0.0/8\n", encoding="utf-8")
    monkeypatch.delenv("WHITELIST_IPS", raising=False)

    nets = utils.load_cidr_list_from_env_and_file("WHITELIST_IPS", str(wl))
    assert utils.is_ip_whitelisted("1.1.1.1", nets)
    assert utils.is_ip_whitelisted("10.1.2.3", nets)


# --- Bug 2: duplikat -----------------------------------------------------------

def test_add_to_whitelist_rejects_duplicate_with_reason(monkeypatch, tmp_path):
    wl = tmp_path / "wl.txt"
    monkeypatch.setenv("WHITELIST_PATH", str(wl))

    utils.add_to_whitelist("10.2.57.246", "Internal Server")
    ok, msg = utils.add_to_whitelist("10.2.57.246", "Internal Server")

    assert ok is True and "sudah ada" in msg
    lines = [l for l in wl.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 1, f"entri duplikat: {lines}"


# --- Bug 3: ExecutionContext.logfile --------------------------------------------

def _ctx(**kw):
    return ExecutionContext(
        event={}, ip="1.2.3.4", website="", providers=[], mapped=False, whitelisted=False,
        bypassed=False, ml_prob=0.0, ml_label=0, reputation_score=0, rep_str="", event_id="e", **kw
    )


def test_execution_context_logfile_follows_logfile_env(monkeypatch, tmp_path):
    target = str(tmp_path / "audit.log")
    monkeypatch.setenv("LOGFILE", target)
    assert _ctx().logfile == target


def test_execution_context_logfile_explicit_arg_wins(monkeypatch, tmp_path):
    monkeypatch.setenv("LOGFILE", str(tmp_path / "env.log"))
    assert _ctx(logfile="x.log").logfile == "x.log"


def test_playbook_audit_goes_to_logfile_env_not_repo_root(monkeypatch, tmp_path):
    target = tmp_path / "audit.log"
    monkeypatch.setenv("LOGFILE", str(target))
    before = _sha(ROOT_LOG)

    ctx = _ctx()
    utils.log_user_action("AUTO_BLOCK", {"username": "playbook"}, ip=ctx.ip, logfile=ctx.logfile)

    assert target.exists() and "AUTO_BLOCK" in target.read_text(encoding="utf-8")
    assert _sha(ROOT_LOG) == before, "audit log masuk tele-soar-actions.log di root repo"


# --- ip_in_nets: satu entri rusak tidak boleh mematikan entri lain --------------

def test_invalid_entry_does_not_hide_entries_before_or_after(caplog):
    nets = ["172.30.0.0/24", "BARIS_RUSAK", "10.0.0.0/8", "103.8.77.26"]

    assert utils.ip_in_nets("172.30.0.5", nets), "entri SEBELUM baris rusak"
    assert utils.ip_in_nets("10.1.2.3", nets), "CIDR SESUDAH baris rusak ikut terlewat"
    assert utils.ip_in_nets("103.8.77.26", nets), "IP tunggal SESUDAH baris rusak ikut terlewat"
    assert not utils.ip_in_nets("8.8.8.8", nets)
    assert "BARIS_RUSAK" in caplog.text, "entri rusak harus diberi warning, bukan diam-diam di-skip"


def test_invalid_ip_argument_is_not_whitelisted():
    assert utils.ip_in_nets("bukan-ip", ["10.0.0.0/8"]) is False


# --- Daemon reload whitelist saat file berubah ----------------------------------

def test_reload_cidr_list_only_when_file_changes(monkeypatch, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("10.0.0.1\n", encoding="utf-8")
    monkeypatch.delenv("WHITELIST_IPS", raising=False)

    nets, sig = utils.reload_cidr_list_if_changed("WHITELIST_IPS", str(wl), [], None)
    assert nets == ["10.0.0.1"]

    loads = []
    real = utils.load_cidr_list_from_env_and_file
    monkeypatch.setattr(utils, "load_cidr_list_from_env_and_file", lambda *a: loads.append(a) or real(*a))

    same, sig2 = utils.reload_cidr_list_if_changed("WHITELIST_IPS", str(wl), nets, sig)
    assert same is nets and sig2 == sig and loads == [], "file tidak berubah tapi tetap dimuat ulang"

    wl.write_text("10.0.0.1\n10.0.0.2  # baru\n", encoding="utf-8")
    nets3, _ = utils.reload_cidr_list_if_changed("WHITELIST_IPS", str(wl), nets, sig)
    assert nets3 == ["10.0.0.1", "10.0.0.2"]


def test_reload_cidr_list_initial_load_keeps_env_when_file_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("WHITELIST_IPS", "10.9.9.9")
    nets, _ = utils.reload_cidr_list_if_changed("WHITELIST_IPS", str(tmp_path / "tidak-ada.txt"), [], None)
    assert nets == ["10.9.9.9"]


def test_daemon_picks_up_whitelist_added_after_start(monkeypatch, tmp_path):
    """End-to-end daemon.main: IP di-whitelist lewat bot SETELAH daemon start harus berlaku
    pada event berikutnya, tanpa restart."""
    import json

    wl = tmp_path / "wl.txt"
    wl.write_text("# kosong\n", encoding="utf-8")
    monkeypatch.setenv("WHITELIST_PATH", str(wl))
    monkeypatch.setenv("LOGFILE", str(tmp_path / "audit.log"))
    monkeypatch.setenv("UNMAPPED_LOG_PATH", str(tmp_path / "unmapped.log"))
    for k in ("WHITELIST_IPS", "BYPASS_IPS", "WHITELIST_FILE"):
        monkeypatch.delenv(k, raising=False)

    ip = "203.0.113.77"
    event = json.dumps({"alert": {"src_ip": ip, "server_name": "x.test", "type": "alert_url_probe"}})
    pops = []

    class _Redis:
        def blpop(self, key, timeout=0):
            pops.append(1)
            if len(pops) == 1:
                return (key, event)
            if len(pops) == 2:
                # Analis menambah IP lewat /whitelist_add saat daemon sudah jalan.
                ok, _ = utils.add_to_whitelist(ip, "ditambah saat daemon jalan")
                assert ok
                return (key, event)
            raise KeyboardInterrupt

        def __getattr__(self, name):
            return lambda *a, **kw: None

    seen = []
    real_is_wl = daemon.is_ip_whitelisted

    def spy(ip_, nets):
        res = real_is_wl(ip_, nets)
        seen.append(res)
        return res

    monkeypatch.setattr(daemon, "load_env", lambda *a, **kw: None)
    monkeypatch.setattr(daemon, "redis_client", lambda: _Redis())
    # log_unmapped_site_once_per_day mengambil redis_client dari database.py.
    import minisoar.database as db
    monkeypatch.setattr(db, "redis_client", lambda: _Redis())
    monkeypatch.setattr(daemon, "is_ip_whitelisted", spy)

    daemon.main()

    assert seen[:2] == [False, True], f"daemon tidak memuat ulang whitelist: {seen}"
