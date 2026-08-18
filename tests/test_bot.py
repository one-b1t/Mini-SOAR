import os
import pytest
from minisoar.bot import _format_usage_html, is_user_allowed


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

