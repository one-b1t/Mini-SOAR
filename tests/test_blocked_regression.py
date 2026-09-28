import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
import httpx
import telegram.error
import redis

from minisoar.database import redis_client
from minisoar.mitigation.core import get_active_blocklist
from minisoar.bot import blocked_cmd, _safe_reply_text, blockonpalo, restorehost


def test_redis_client_has_configured_timeouts(monkeypatch):
    """Verifies that redis_client configures socket_timeout and socket_connect_timeout."""
    monkeypatch.setenv("REDIS_TIMEOUT", "3.5")
    r = redis_client()
    conn_kwargs = r.connection_pool.connection_kwargs
    assert conn_kwargs.get("socket_timeout") == 3.5
    assert conn_kwargs.get("socket_connect_timeout") == 3.5


def test_get_active_blocklist_redis_down():
    """When Redis is down, get_active_blocklist records redis_error and skips r.keys() to avoid cascading timeouts."""
    mock_redis = MagicMock()
    mock_redis.zrangebyscore.side_effect = redis.ConnectionError("Connection refused")

    data = get_active_blocklist(r=mock_redis)
    assert "redis_error" in data
    assert "Connection refused" in data["redis_error"]
    assert data["perimeters"] == []
    assert data["edr_iocs"] == []
    # Ensure cascading timeout is avoided: r.keys should NOT be called
    mock_redis.keys.assert_not_called()


def test_get_active_blocklist_happy_path():
    """Happy path for get_active_blocklist when Redis is reachable."""
    mock_redis = MagicMock()
    # zrangebyscore returns items: (b'imperva:1.2.3.4', 1700000000.0)
    mock_redis.zrangebyscore.return_value = [("imperva:1.2.3.4", 1700000000.0)]
    mock_redis.keys.return_value = ["minisoar:edr_ioc_synced:10.0.0.1"]
    mock_redis.ttl.return_value = 500

    data = get_active_blocklist(r=mock_redis)
    assert data["redis_error"] is None
    assert len(data["perimeters"]) == 1
    assert data["perimeters"][0]["ip"] == "1.2.3.4"
    assert data["perimeters"][0]["provider"] == "imperva"
    assert len(data["edr_iocs"]) == 1
    assert data["edr_iocs"][0]["ip"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_blocked_cmd_reports_redis_offline(monkeypatch):
    """blocked_cmd should provide an explicit, actionable explanation to the user when Redis is down."""
    update = MagicMock()
    update.effective_user = MagicMock(username="testuser", id=123)
    update.message = MagicMock()
    update.message.reply_text = AsyncMock()
    context = MagicMock(args=[])

    monkeypatch.setattr(
        "minisoar.bot.get_active_blocklist",
        lambda: {"perimeters": [], "edr_iocs": [], "redis_error": "Connection refused (Error 111)"},
    )

    await blocked_cmd(update, context)

    update.message.reply_text.assert_called_once()
    call_args, call_kwargs = update.message.reply_text.call_args
    sent_text = call_args[0]
    assert "Gagal Membaca Block List" in sent_text
    assert "OFFLINE" in sent_text
    assert "Redis" in sent_text


@pytest.mark.asyncio
async def test_blocked_cmd_catches_unhandled_exception(monkeypatch):
    """blocked_cmd catches any unexpected exceptions and warns the user instead of hanging or failing silently."""
    update = MagicMock()
    update.effective_user = MagicMock(username="testuser", id=123)
    update.message = MagicMock()
    update.message.reply_text = AsyncMock()
    context = MagicMock(args=[])

    def _raise():
        raise RuntimeError("Unexpected Redis pool crash")

    monkeypatch.setattr("minisoar.bot.get_active_blocklist", _raise)

    await blocked_cmd(update, context)

    update.message.reply_text.assert_called_once()
    call_args, _ = update.message.reply_text.call_args
    sent_text = call_args[0]
    assert "Gagal Membaca Block List" in sent_text
    assert "Unexpected Redis pool crash" in sent_text


@pytest.mark.asyncio
async def test_blocked_cmd_formats_active_items(monkeypatch):
    """blocked_cmd correctly renders active perimeter and EDR entries when Redis is healthy."""
    update = MagicMock()
    update.effective_user = MagicMock(username="testuser", id=123)
    update.message = MagicMock()
    update.message.reply_text = AsyncMock()
    context = MagicMock(args=[])

    monkeypatch.setattr(
        "minisoar.bot.get_active_blocklist",
        lambda: {
            "perimeters": [{"ip": "192.168.1.50", "provider": "imperva", "ttl_sec": 120, "expires_at": "12:00:00"}],
            "edr_iocs": [{"ip": "10.0.0.99", "provider": "Kaspersky KSC", "ttl_sec": 300}],
            "redis_error": None,
        },
    )

    await blocked_cmd(update, context)

    update.message.reply_text.assert_called_once()
    call_args, _ = update.message.reply_text.call_args
    sent_text = call_args[0]
    assert "192.168.1.50" in sent_text
    assert "10.0.0.99" in sent_text
    assert "1 IP aktif" in sent_text
    assert "1 IP terdaftar" in sent_text


@pytest.mark.asyncio
async def test_safe_reply_text_suppresses_progress_timeouts():
    """A progress message that times out should be safely caught and suppressed so operation is not cancelled."""
    target = MagicMock()
    target.reply_text = AsyncMock(side_effect=httpx.ConnectTimeout("Telegram connection timed out"))

    res = await _safe_reply_text(target, "Working...", is_progress=True)
    assert res is None
    target.reply_text.assert_called_once()


@pytest.mark.asyncio
async def test_safe_reply_text_retries_final_message():
    """A final response retries once if Telegram raises TimedOut or ConnectTimeout."""
    target = MagicMock()
    target.reply_text = AsyncMock(side_effect=[
        telegram.error.TimedOut("Timed out"),
        "success_msg",
    ])

    res = await _safe_reply_text(target, "Result completed", is_progress=False)
    assert res == "success_msg"
    assert target.reply_text.call_count == 2


@pytest.mark.asyncio
async def test_blockonpalo_proceeds_even_if_progress_reply_times_out(monkeypatch):
    """Verifies blockonpalo executes its mitigation and delivers final reply even if progress message times out."""
    update = MagicMock()
    update.effective_chat = MagicMock(id=111)
    update.effective_user = MagicMock(username="admin", id=999)
    update.message = MagicMock()
    update.message.reply_text = AsyncMock(side_effect=[
        httpx.ConnectTimeout("Progress message timeout"),
        "final_reply_ok",
    ])
    context = MagicMock(args=["192.168.10.20"])

    monkeypatch.setattr("minisoar.bot.es_get_latest_event_website_by_ip", lambda ip: "example.com")
    monkeypatch.setattr("minisoar.bot.get_perimeter_info", lambda site, p: (["paloalto"], True, None))
    monkeypatch.setattr("minisoar.bot.trigger_auto_block", lambda ip, target, commit=False: (True, "Blocked on Palo"))
    monkeypatch.setattr("minisoar.bot.register_block_state", lambda r, ip, target, duration=600: None)
    monkeypatch.setattr("minisoar.bot.redis_client", lambda: MagicMock())
    monkeypatch.setattr("minisoar.bot.log_user_action", lambda *args, **kwargs: None)
    monkeypatch.setattr("minisoar.bot.es_find_latest_event_id_by_ip", lambda *args, **kwargs: "ev-1")
    monkeypatch.setattr("minisoar.bot.store_label", lambda *args, **kwargs: None)

    await blockonpalo(update, context)

    # 1st call was progress (which timed out), 2nd call was the final block confirmation
    assert update.message.reply_text.call_count == 2
    final_call_args, _ = update.message.reply_text.call_args_list[1]
    assert "Blocked on Palo" in final_call_args[0]


@pytest.mark.asyncio
async def test_restorehost_proceeds_even_if_progress_reply_times_out(monkeypatch):
    """Verifies restorehost executes un-isolation and delivers final reply even if progress message times out."""
    update = MagicMock()
    update.effective_chat = MagicMock(id=111)
    update.effective_user = MagicMock(username="admin", id=999)
    update.message = MagicMock()
    update.message.reply_text = AsyncMock(side_effect=[
        httpx.ConnectTimeout("Progress message timeout"),
        "final_reply_ok",
    ])
    context = MagicMock(args=["10.0.0.50", "ksc"])

    monkeypatch.setattr("minisoar.bot.edr.restore_endpoint", lambda target, provider: (True, "Host restored", {}))
    monkeypatch.setattr("minisoar.bot.log_user_action", lambda *args, **kwargs: None)

    await restorehost(update, context)

    assert update.message.reply_text.call_count == 2
    final_call_args, _ = update.message.reply_text.call_args_list[1]
    assert "Host restored" in final_call_args[0]
