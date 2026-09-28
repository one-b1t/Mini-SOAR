"""Balasan error AI Copilot ke chat Telegram tidak boleh memuat kredensial.

call_llm() menangkap exception provider dan MENGEMBALIKAN teksnya sebagai
balasan /ask_ai dan /rca. REST fallback Gemini memakai
...:generateContent?key=<GEMINI_API_KEY>, dan str(e) dari requests memuat
URL lengkap -> key sampai ke chat. Filter redaksi log (bot.py/daemon.py)
tidak menyentuh jalur ini.

Kredensial di sini PALSU; resolve_auth_credential di-mock supaya test tidak
membaca .env atau ~/.gemini milik mesin.
"""

import pytest
import requests

from minisoar.ai import copilot

FAKE_KEY = "AIzaSyFAKEGEMINIKEY1234567890abcdefghij"


@pytest.fixture
def gemini_rest(monkeypatch):
    """Jalur non-mock, provider gemini, langsung ke SDK/REST (bukan headless CLI)."""
    monkeypatch.delenv("MINISOAR_MOCK", raising=False)
    monkeypatch.setenv("AI_PROVIDER", "gemini")
    monkeypatch.setenv("AI_EXECMODE", "api")
    monkeypatch.setattr(copilot, "resolve_auth_credential", lambda provider=None: (FAKE_KEY, "env:GEMINI_API_KEY"))

    def fail_with(exc):
        def _raise(*a, **kw):
            raise exc
        monkeypatch.setattr(copilot, "_call_gemini", _raise)

    return fail_with


def _requests_error():
    url = f"/v1beta/models/gemini-pro:generateContent?key={FAKE_KEY}"
    return requests.exceptions.ConnectionError(
        "HTTPSConnectionPool(host='generativelanguage.googleapis.com', port=443): "
        f"Max retries exceeded with url: {url} (Caused by NewConnectionError('Failed to establish a new connection'))"
    )


def test_requests_error_url_key_not_sent_to_chat(gemini_rest):
    gemini_rest(_requests_error())

    reply = copilot.call_llm("analisis payload ini")

    assert FAKE_KEY not in reply, reply
    # Diagnosa tetap actionable: provider, jenis error, dan penyebabnya.
    assert "gemini" in reply and "ConnectionError" in reply, reply
    assert "Max retries exceeded" in reply and "generativelanguage.googleapis.com" in reply, reply
    assert "?key=<REDACTED>" in reply, reply


def test_http_status_kept_and_echoed_key_removed(gemini_rest):
    """Error API (HTTP 4xx) tetap menampilkan status; key yang ter-echo di body disensor."""
    gemini_rest(RuntimeError(f'Gemini API error: HTTP 400 {{"error": "API key not valid: {FAKE_KEY}"}}'))

    reply = copilot.call_llm("x")

    assert FAKE_KEY not in reply, reply
    assert "HTTP 400" in reply and "API key not valid" in reply, reply


def test_key_in_non_url_form_removed(gemini_rest):
    """Bukan hanya pola URL: nilai kredensial yang aktif disensor di format apa pun."""
    gemini_rest(RuntimeError(f"auth failed, header x-goog-api-key={FAKE_KEY} rejected"))

    reply = copilot.call_llm("x")

    assert FAKE_KEY not in reply, reply
    assert "auth failed" in reply


def test_call_llm_json_path_also_clean(gemini_rest):
    gemini_rest(_requests_error())

    out = copilot.call_llm_json("x")

    assert FAKE_KEY not in repr(out), out
    assert "ConnectionError" in repr(out)


def test_telegram_token_pattern_also_removed(gemini_rest):
    gemini_rest(RuntimeError("proxy https://api.telegram.org/bot123456789:AAAAfakeTokenForTestsOnly_abcdefg/getMe"))

    reply = copilot.call_llm("x")

    assert "AAAAfakeToken" not in reply and "bot<REDACTED>" in reply, reply
