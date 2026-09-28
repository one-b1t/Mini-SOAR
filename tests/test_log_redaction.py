"""Token bot Telegram tidak boleh tertulis ke log (journald produksi).

bot.main() memasang logging.basicConfig(level=INFO); logger `httpx` (dipakai
python-telegram-bot) lalu mencatat tiap request sebagai
"HTTP Request: POST https://api.telegram.org/bot<TOKEN>/getUpdates" - token
utuh, plaintext. Selain itu error jaringan (requests/httpx) sering memuat URL
lengkap di pesan exception/traceback.
"""

import io
import logging

import pytest

import minisoar.bot as botmod

TOKEN = "8001234567:AAHfakeTokenForTestsOnly_abcdefghijk"


@pytest.fixture
def root_stream():
    """Handler root sendiri; dilepas lagi supaya tidak bocor ke test lain."""
    root = logging.getLogger()
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s:%(name)s:%(message)s"))
    root.addHandler(handler)
    levels = {n: logging.getLogger(n).level for n in ("", "httpx", "httpcore")}
    yield stream, handler
    root.removeHandler(handler)
    for n, lvl in levels.items():
        logging.getLogger(n).setLevel(lvl)


def test_httpx_info_request_lines_are_not_logged(root_stream):
    stream, _ = root_stream
    botmod._configure_logging()

    logging.getLogger("httpx").info('HTTP Request: POST https://api.telegram.org/bot%s/getUpdates "HTTP/1.1 200 OK"', TOKEN)
    logging.getLogger("httpcore.http11").info("send_request_headers.started request=<Request [b'POST']>")

    assert stream.getvalue() == "", f"log request httpx/httpcore INFO masih lolos: {stream.getvalue()!r}"


def test_token_redacted_even_when_logged_at_warning(root_stream):
    stream, _ = root_stream
    botmod._configure_logging()

    logging.getLogger("httpx").warning("retry https://api.telegram.org/bot%s/sendMessage", TOKEN)
    logging.getLogger("minisoar.utils").error("Failed to send alert: %s", f"HTTPSConnectionPool(host='api.telegram.org'): url: /bot{TOKEN}/sendMessage")

    out = stream.getvalue()
    assert TOKEN not in out and TOKEN.split(":")[1] not in out, out
    assert out.count("bot<REDACTED>") == 2, out


def test_token_redacted_in_traceback(root_stream):
    stream, _ = root_stream
    botmod._configure_logging()

    try:
        raise ConnectionError(f"Max retries exceeded with url: /bot{TOKEN}/getMe")
    except ConnectionError:
        logging.getLogger("telegram.ext.Updater").exception("Network error")

    out = stream.getvalue()
    assert "Traceback" in out and "Max retries exceeded" in out
    assert TOKEN.split(":")[1] not in out, out


def test_redacted_record_content_not_just_output(root_stream):
    """Record yang sampai ke handler berisi bot<REDACTED> dan tidak memuat token."""
    _, handler = root_stream
    botmod._configure_logging()
    seen = []

    class _Capture(logging.Handler):
        def emit(self, record):
            seen.append((record.getMessage(), record.args))

    cap = _Capture()
    cap.addFilter(botmod._TokenRedactingFilter())
    logging.getLogger().addHandler(cap)
    try:
        logging.getLogger("httpx").warning("POST https://api.telegram.org/bot%s/getMe", TOKEN)
    finally:
        logging.getLogger().removeHandler(cap)

    (msg, args), = seen
    assert "bot<REDACTED>/getMe" in msg and TOKEN not in msg and args is None


def test_child_logger_of_httpcore_is_covered(root_stream):
    """Alasan filter di handler, bukan di logger: httpcore mencatat lewat logger anak."""
    stream, _ = root_stream
    botmod._configure_logging()

    logging.getLogger("httpcore.http11").warning("connect https://api.telegram.org/bot%s/getUpdates", TOKEN)

    assert "bot<REDACTED>" in stream.getvalue() and TOKEN not in stream.getvalue()


def test_normal_messages_untouched(root_stream):
    stream, _ = root_stream
    botmod._configure_logging()

    logging.getLogger("minisoar.bot").info("[MOCK] activateakamai: skip %s %d", "ip=1.2.3.4", 7)
    assert stream.getvalue() == "INFO:minisoar.bot:[MOCK] activateakamai: skip ip=1.2.3.4 7\n"


def test_configure_logging_idempotent(root_stream):
    _, handler = root_stream
    botmod._configure_logging()
    botmod._configure_logging()
    assert sum(isinstance(f, botmod._TokenRedactingFilter) for f in handler.filters) == 1


def test_bot_main_uses_configure_logging(monkeypatch):
    """bot.main() harus memasang sensor sebelum apa pun dicatat. Tanpa token,
    main() berhenti di awal - tidak ada bot yang di-start."""
    calls = []
    monkeypatch.setattr(botmod, "load_env", lambda *a, **kw: None)
    monkeypatch.setattr(botmod, "_configure_logging", lambda: calls.append("configure"), raising=False)
    monkeypatch.setattr(botmod, "telegram_config", lambda: type("C", (), {"token": "", "chat_id": ""})())

    botmod.main()

    assert calls == ["configure"]
