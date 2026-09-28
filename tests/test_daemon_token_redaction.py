"""Regresi: daemon.py tidak boleh membocorkan bot token ke journald.

daemon.main() memakai `logging.basicConfig(level=logging.INFO)` polos, sementara
utils.send_telegram() (dipanggil daemon tiap 60 detik) gagal dengan
`logger.error("Failed to send alert: %s", e)`. Format exception `requests`
memuat URL api.telegram.org/bot<TOKEN>/sendMessage, jadi token produksi ikut
tercetak ke journald justru saat jaringan bermasalah.

Token di bawahini PALSU dan tidak pernah dibaca dari .env. Test yang memuat
token asli justru membuat kebocoran baru.
"""

import ast
import io
import logging
import pathlib

import pytest
import requests

import minisoar.daemon as daemonmod

FAKE_TOKEN = "8009754346:TESTFAKE0000000000000000000000000000"
FAKE_SECRET = FAKE_TOKEN.split(":", 1)[1]
BAD_URL = f"https://api.telegram.org/bot{FAKE_TOKEN}/sendMessage"


@pytest.fixture
def root_log():
    """Handler Stream ke buffer, dipasang di root - meniru basicConfig polos."""
    stream = io.StringIO()
    root = logging.getLogger()
    saved = root.handlers[:]
    root.handlers[:] = [logging.StreamHandler(stream)]
    try:
        yield stream
    finally:
        root.handlers[:] = saved


def _emit_send_telegram_failure():
    """Tiru utils.send_telegram() yang gagal: log exception requests apa adanya."""
    try:
        raise requests.exceptions.ConnectionError(
            "HTTPSConnectionPool(host='api.telegram.org', port=443): "
            f"Max retries exceeded with url: {BAD_URL} "
            "(Caused by NewConnectionError('Connection refused'))"
        )
    except requests.exceptions.ConnectionError as exc:
        logging.getLogger("minisoar.utils").error("Failed to send alert: %s", exc)


def test_daemon_has_token_redacting_logging_setup():
    assert hasattr(daemonmod, "_configure_logging"), (
        "daemon.py belum punya filter redaksi token; logging.basicConfig polos "
        "membocorkan bot<TOKEN>/sendMessage ke journald"
    )


def test_daemon_main_does_not_call_plain_basicconfig():
    """Regresi: main() harus lewat _configure_logging(), bukan basicConfig polos.

    Cuma main() yang diperiksa; _configure_logging() sendiri memang memanggil
    basicConfig, lalu memasang filter-nya.
    """
    tree = ast.parse(pathlib.Path(daemonmod.__file__).read_text(encoding="utf-8"))
    main_fn = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    assert not [
        node
        for node in ast.walk(main_fn)
        if isinstance(node, ast.Attribute) and node.attr == "basicConfig"
    ], "daemon.main() masih memanggil logging.basicConfig -> filter redaksi tidak terpasang"
    assert [
        node
        for node in ast.walk(main_fn)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_configure_logging"
    ], "daemon.main() tidak memanggil _configure_logging()"


def test_send_telegram_failure_redacts_token_under_daemon_logging(root_log):
    """Kontrol negatif + positif dalam satu test.

    Tanpa filter token benar-benar bocor; sesudah setup milik daemon, tidak.
    """
    _emit_send_telegram_failure()
    assert FAKE_SECRET in root_log.getvalue(), (
        "kontrol negatif bocor: test ini tidak membuktikan apa-apa"
    )

    root_log.seek(0)
    root_log.truncate(0)

    daemonmod._configure_logging()
    _emit_send_telegram_failure()

    out = root_log.getvalue()
    assert FAKE_SECRET not in out, out
    assert "bot<REDACTED>/sendMessage" in out, out


def test_token_stays_hidden_in_exception_text(root_log):
    """logger.exception() / exc_info=True bisa menaruh URL token di exc_text."""
    daemonmod._configure_logging()
    try:
        raise requests.exceptions.ConnectionError(f"url: {BAD_URL}")
    except requests.exceptions.ConnectionError:
        logging.getLogger("minisoar.daemon").exception("alert loop mati")

    out = root_log.getvalue()
    assert FAKE_SECRET not in out, out
    assert "bot<REDACTED>/sendMessage" in out, out
