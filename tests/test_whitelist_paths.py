"""Bug produksi whitelist & path audit log.

1. Daemon membaca whitelist dari path berbeda dengan yang ditulis bot
   (WHITELIST_FILE relatif → cwd vs WHITELIST_PATH → /etc/logstash di Linux).
2. Entri dengan "  # alasan" (format yang SELALU ditulis add_to_whitelist)
   tidak cocok di daemon, dan membuat pengecekan duplikat gagal.
3. ExecutionContext.logfile hardcode relatif, tidak lewat resolve_log_path.
"""

import os
from pathlib import Path

import pytest

import minisoar.daemon as daemon
import minisoar.utils as utils


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
    monkeypatch.setattr(daemon, "load_cidr_list_from_env_and_file", fake_load)
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
