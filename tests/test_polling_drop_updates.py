"""Tests for drop_pending_updates during Telegram bot polling startup.

Verifies:
1. Default behavior drops pending updates on start (safe, avoids processing stale backlog).
2. Setting TELEGRAM_DROP_PENDING_UPDATES=false (or 0/off/no) disables dropping.
3. Setting TELEGRAM_DROP_PENDING_UPDATES=true (or 1/on/yes) explicitly enables dropping.
4. Error handling for InvalidToken, NetworkError, and KeyboardInterrupt remains intact.
"""
from __future__ import annotations

import logging
import pytest
import telegram.error

import minisoar.bot as botmod
import minisoar.config as cfgmod


def _setup_capturing_app(monkeypatch):
    """Sets up a stub ApplicationBuilder that captures run_polling arguments."""
    captured = {"run_polling_kwargs": None, "run_polling_args": None, "call_count": 0}

    class _FakeApp:
        def __init__(self):
            self.handlers = {}
            self.error_handler = None

        def add_handler(self, handler):
            self.handlers.setdefault(type(handler).__name__, []).append(handler)

        def add_error_handler(self, fn):
            self.error_handler = fn

        def run_polling(self, *args, **kwargs):
            captured["call_count"] += 1
            captured["run_polling_args"] = args
            captured["run_polling_kwargs"] = kwargs

    class _FakeBuilder:
        def token(self, _t):
            return self

        def post_init(self, _fn):
            return self

        def build(self):
            return _FakeApp()

    monkeypatch.setenv("MINISOAR_MOCK", "1")
    monkeypatch.setenv("TELEGRAM_TOKEN", "123456:TEST_TOKEN")
    monkeypatch.setattr(botmod, "ApplicationBuilder", _FakeBuilder)
    return captured


def test_polling_drop_updates_default_is_true(monkeypatch):
    """Secara default (tanpa env var), bot harus memanggil run_polling(drop_pending_updates=True)."""
    monkeypatch.delenv("TELEGRAM_DROP_PENDING_UPDATES", raising=False)
    monkeypatch.delenv("DROP_PENDING_UPDATES", raising=False)

    captured = _setup_capturing_app(monkeypatch)
    botmod.main()

    assert captured["call_count"] == 1
    assert captured["run_polling_kwargs"] is not None
    assert captured["run_polling_kwargs"].get("drop_pending_updates") is True


@pytest.mark.parametrize("val", ["false", "0", "off", "no", "FALSE", "No"])
def test_polling_drop_updates_can_be_disabled(monkeypatch, val):
    """Operator dapat menonaktifkan drop_pending_updates via env var jika perlu memproses antrean lama."""
    monkeypatch.setenv("TELEGRAM_DROP_PENDING_UPDATES", val)

    captured = _setup_capturing_app(monkeypatch)
    botmod.main()

    assert captured["call_count"] == 1
    assert captured["run_polling_kwargs"] is not None
    assert captured["run_polling_kwargs"].get("drop_pending_updates") is False


@pytest.mark.parametrize("val", ["true", "1", "yes", "on", "TRUE"])
def test_polling_drop_updates_explicit_enable(monkeypatch, val):
    """Mengaktifkan secara eksplisit via env var bernilai true/1/yes/on."""
    monkeypatch.setenv("TELEGRAM_DROP_PENDING_UPDATES", val)

    captured = _setup_capturing_app(monkeypatch)
    botmod.main()

    assert captured["call_count"] == 1
    assert captured["run_polling_kwargs"] is not None
    assert captured["run_polling_kwargs"].get("drop_pending_updates") is True


def test_telegram_config_drop_pending_fallback_env(monkeypatch):
    """telegram_config membaca TELEGRAM_DROP_PENDING_UPDATES dan DROP_PENDING_UPDATES sebagai fallback."""
    monkeypatch.setenv("TELEGRAM_TOKEN", "fake_token")
    monkeypatch.delenv("TELEGRAM_DROP_PENDING_UPDATES", raising=False)

    monkeypatch.setenv("DROP_PENDING_UPDATES", "false")
    cfg = cfgmod.telegram_config()
    assert cfg.drop_pending_updates is False

    monkeypatch.setenv("TELEGRAM_DROP_PENDING_UPDATES", "true")
    cfg = cfgmod.telegram_config()
    assert cfg.drop_pending_updates is True


def test_polling_error_handling_preserved_with_flag(monkeypatch, caplog):
    """Error handling startup (InvalidToken, NetworkError) tetap aktif saat run_polling dipanggil."""
    class _FakeAppRaising:
        def __init__(self):
            self.handlers = {}
            self.error_handler = None

        def add_handler(self, handler):
            self.handlers.setdefault(type(handler).__name__, []).append(handler)

        def add_error_handler(self, fn):
            self.error_handler = fn

        def run_polling(self, *a, **kw):
            raise telegram.error.InvalidToken("Token revoked")

    class _FakeBuilder:
        def token(self, _t):
            return self

        def post_init(self, _fn):
            return self

        def build(self):
            return _FakeAppRaising()

    monkeypatch.setenv("MINISOAR_MOCK", "1")
    monkeypatch.setenv("TELEGRAM_TOKEN", "123456:REVOKED")
    monkeypatch.setattr(botmod, "ApplicationBuilder", _FakeBuilder)

    with caplog.at_level(logging.ERROR, logger=botmod.logger.name):
        botmod.main()

    assert "TOKEN TELEGRAM DITOLAK" in caplog.text


def test_polling_keyboard_interrupt_graceful_exit(monkeypatch, capsys):
    """KeyboardInterrupt (Ctrl+C) tetap keluar anggun dengan pesan ramah."""
    class _FakeAppInterrupt:
        def __init__(self):
            self.handlers = {}
            self.error_handler = None

        def add_handler(self, handler):
            self.handlers.setdefault(type(handler).__name__, []).append(handler)

        def add_error_handler(self, fn):
            self.error_handler = fn

        def run_polling(self, *a, **kw):
            raise KeyboardInterrupt()

    class _FakeBuilder:
        def token(self, _t):
            return self

        def post_init(self, _fn):
            return self

        def build(self):
            return _FakeAppInterrupt()

    monkeypatch.setenv("MINISOAR_MOCK", "1")
    monkeypatch.setenv("TELEGRAM_TOKEN", "123456:VALID")
    monkeypatch.setattr(botmod, "ApplicationBuilder", _FakeBuilder)

    botmod.main()  # Tidak boleh melempar
    out = capsys.readouterr().out
    assert "dihentikan oleh pengguna (Ctrl+C)" in out
