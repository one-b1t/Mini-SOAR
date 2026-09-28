"""Regresi: error startup Telegram harus menghasilkan pesan yang berguna.

Sebelum perubahan ini, blok try/except di sekitar app.run_polling() hanya
menangkap KeyboardInterrupt. InvalidToken dan NetworkError karena itu
terlempar keluar apa adanya, jadi user baru setup melihat traceback mentah
("telegram.error.InvalidToken: Not Found") tanpa petunjuk token mana yang
salah checked.

Test di sini memanggil main() dengan ApplicationBuilder yang dipalsukan,
sehingga run_polling() tidak pernah menyentuh jaringan sama sekali. Yang
diuji adalah pesan yang sampai ke user, bukan koneksinya.
"""
import logging

import pytest
import telegram.error

import minisoar.bot as botmod


def _fake_builder_raising(monkeypatch, exc):
    """Pasang stub builder yang run_polling()-nya melempar `exc`."""

    class _FakeApp:
        def __init__(self):
            self.handlers = {}
            self.error_handler = None

        def add_handler(self, handler):
            self.handlers.setdefault(type(handler).__name__, []).append(handler)

        def add_error_handler(self, fn):
            self.error_handler = fn

        def run_polling(self, *a, **kw):
            raise exc

    class _FakeBuilder:
        def token(self, _t):
            return self

        def post_init(self, _fn):
            return self

        def build(self):
            return _FakeApp()

    monkeypatch.setenv("MINISOAR_MOCK", "1")
    monkeypatch.setenv("TELEGRAM_TOKEN", "123456:FAKE")
    monkeypatch.setattr(botmod, "ApplicationBuilder", _FakeBuilder)


def test_invalid_token_gives_actionable_message_instead_of_traceback(monkeypatch, caplog):
    """InvalidToken harus tertangkap dan pesannya menyebut TELEGRAM_TOKEN.

    Kalau exception-nya lolos ke pytest, test ini gagal — itulah bukti bahwa
    penanganan error-nya benar-benar ada, bukan sekadar pesan yang seadanya.
    """
    _fake_builder_raising(monkeypatch, telegram.error.InvalidToken("Not Found"))

    with caplog.at_level(logging.ERROR, logger=botmod.logger.name):
        botmod.main()  # tidak boleh melempar

    text = caplog.text
    assert "TOKEN TELEGRAM DITOLAK" in text
    # Nama env key yang salah harus disebut eksplisit.
    assert "TELEGRAM_TOKEN" in text
    # Petunjuk actionable, bukan sekadar echo dari exception.
    assert "BotFather" in text
    # Tidak boleh membocorkan nilai token ke log.
    assert "123456:FAKE" not in text
    # Bukan traceback mentah.
    assert "Traceback (most recent call last)" not in text


def test_network_error_message_blames_network_not_token(monkeypatch, caplog):
    """NetworkError harus blamed ke jaringan saja, bukan ke token."""
    _fake_builder_raising(monkeypatch, telegram.error.NetworkError("Connection refused"))

    with caplog.at_level(logging.ERROR, logger=botmod.logger.name):
        botmod.main()  # tidak boleh melempar

    text = caplog.text
    assert "TIDAK BISA KONEK" in text
    # Membedakan penyebab: user tidak boleh disuruh memperbaiki token.
    assert "TOKEN TELEGRAM DITOLAK" not in text
    assert "proxy" in text.lower() or "firewall" in text.lower()
    assert "Traceback (most recent call last)" not in text


def test_timed_out_is_covered_by_network_error_handler(monkeypatch, caplog):
    """TimedOut adalah subclass NetworkError, jadi ikut tertutup."""
    assert issubclass(telegram.error.TimedOut, telegram.error.NetworkError)
    _fake_builder_raising(monkeypatch, telegram.error.TimedOut("timed out"))

    with caplog.at_level(logging.ERROR, logger=botmod.logger.name):
        botmod.main()  # tidak boleh melempar

    assert "TIDAK BISA KONEK" in caplog.text


def test_unrelated_exception_still_propagates(monkeypatch):
    """Exception lain harus tetap naik.

    Ini yang membedakan penanganan yang berguna dari `except Exception` telanjang
    yang menutupi bug asli: kalau handlers.py melempar RuntimeError karena
    salah nama variabel, itu harus kelihatan saat development, bukan tenggelam
    jadi "gagal start".
    """
    _fake_builder_raising(monkeypatch, RuntimeError("NameError: typo di handlers.py"))

    with pytest.raises(RuntimeError, match="typo di handlers"):
        botmod.main()


def test_keyboard_interrupt_still_exits_gracefully(monkeypatch, capsys):
    """Penanganan Ctrl+C yang sudah ada harus tetap bekerja."""
    _fake_builder_raising(monkeypatch, KeyboardInterrupt())

    botmod.main()  # tidak boleh melempar

    assert "dihentikan oleh pengguna" in capsys.readouterr().out
