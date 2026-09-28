"""Kredensial di query string (?key=... / &key=...) tidak boleh tertulis ke log.

minisoar/ai/copilot.py (_call_gemini, REST fallback) memanggil
generativelanguage.googleapis.com/...:generateContent?key=<GEMINI_API_KEY>.
Saat request gagal, str(e) dari requests memuat URL lengkap. Palo Alto
(mitigation/paloalto.py) juga mengirim API key sebagai parameter `key`.

Diuji untuk KEDUA salinan filter (bot.py dan daemon.py) supaya tidak
bisa berselisih. Semua kredensial di sini PALSU.
"""

import io
import logging

import pytest

import minisoar.bot as botmod
import minisoar.daemon as daemonmod

FAKE_GEMINI = "AIzaSyFAKEGEMINIKEY1234567890abcdefghij"
FAKE_PA = "LUFRPT1FAKEPALOKEY0123456789=="


@pytest.fixture(params=[botmod, daemonmod], ids=["bot", "daemon"])
def log_out(request):
    """Handler berfilter milik modul yang diuji; kembalikan fungsi log -> output."""
    mod = request.param
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.addFilter(mod._TokenRedactingFilter())
    log = logging.getLogger(f"test.querykey.{mod.__name__}")
    log.propagate = False
    log.setLevel(logging.DEBUG)
    log.addHandler(handler)

    def emit(msg, *args, exc=None):
        stream.seek(0)
        stream.truncate()
        if exc is not None:
            try:
                raise exc
            except Exception:
                log.exception(msg, *args)
        else:
            log.error(msg, *args)
        return stream.getvalue()

    yield emit
    log.removeHandler(handler)


def test_gemini_key_in_requests_error_is_redacted(log_out):
    err = (
        "HTTPSConnectionPool(host='generativelanguage.googleapis.com', port=443): "
        "Max retries exceeded with url: /v1beta/models/gemini-pro:generateContent"
        f"?key={FAKE_GEMINI} (Caused by NewConnectionError('Failed to establish'))"
    )
    out = log_out("AI Copilot call failed (%s): %s", "gemini", err)

    assert FAKE_GEMINI not in out, out
    assert "generateContent?key=<REDACTED> (Caused by" in out, out


def test_query_key_redacted_in_traceback(log_out):
    url = f"https://generativelanguage.googleapis.com/v1beta/models/m:generateContent?key={FAKE_GEMINI}"
    out = log_out("request failed", exc=ConnectionError(f"Max retries exceeded with url: {url}"))

    assert "Traceback" in out and FAKE_GEMINI not in out, out
    assert "?key=<REDACTED>" in out


def test_ampersand_key_redacted_and_other_params_kept(log_out):
    """Palo Alto: ...api/?type=config&action=set&key=<KEY>&xpath=... ; parameter lain utuh."""
    out = log_out("PA error url=https://fw.example/api/?type=config&key=%s&xpath=/config", FAKE_PA)

    assert FAKE_PA not in out, out
    assert "?type=config&key=<REDACTED>&xpath=/config" in out, out


@pytest.mark.parametrize("terminator", [" ", "'", '"', "\\", "&x=1"])
def test_value_stops_at_url_delimiters(log_out, terminator):
    out = log_out("url 'https://a.example/p?key=%s%s' tail", FAKE_GEMINI, terminator)
    assert FAKE_GEMINI not in out
    assert f"?key=<REDACTED>{terminator}" in out, out


def test_short_value_is_still_redacted(log_out):
    """Panjang tidak dijadikan syarat: yang spesifik adalah jangkar [?&]key=,
    bukan panjang nilainya. Ambang panjang hanya membuat key pendek bocor."""
    assert log_out("GET /api?key=ab") == "GET /api?key=<REDACTED>\n"


@pytest.mark.parametrize("msg", [
    "cache key=reputation:abuseipdb:1.2.3.4 miss",
    "monkey=1 keyword=block key: value",
    "GET /search?keyword=sql&monkey=2&hotkey=3",
    "Redis key minisoar:pending_unblocks not found",
    "api_key tidak disetel; key file ~/.gemini/api_key",
    "https://example.com/path/key=abc",
])
def test_unrelated_key_text_untouched(log_out, msg):
    assert log_out(msg) == msg + "\n"


def test_telegram_token_redaction_still_works(log_out):
    out = log_out("POST https://api.telegram.org/bot%s/getMe", "123456789:AAAAfakeTokenForTestsOnly_abcdefg")
    assert "bot<REDACTED>/getMe" in out and "AAAAfake" not in out
