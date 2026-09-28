"""LAPIS 2 — smoke test terhadap bot Telegram sungguhan (HTTP Bot API).

Butuh TELEGRAM_TOKEN asli. Di-skip otomatis kalau token tidak ada, dan
ditandai marker `e2e` sehingga `pytest` default TIDAK menjalankannya
(lihat pytest.ini: addopts = -m "not e2e").

Cara pakai:
    TELEGRAM_TOKEN=123456:AA... \
    PYTHONPATH=.venv/lib/python3.12/site-packages \
    python3 -m pytest tests/test_telegram_e2e.py -m e2e -q

Tidak ada pesan yang dikirim ke chat manapun di lapis ini — semuanya
panggilan read-only ke Bot API, kecuali delete_webhook yang memang
diperlukan supaya polling bisa jalan.
"""

import asyncio
import os

import pytest


def _resolve_token():
    """Pakai resolusi yang SAMA dengan bot: config/.env lalu
    TELEGRAM_TOKEN dengan fallback TELEGRAM_BOT (lihat config.telegram_config).

    Kalau harness hanya melihat TELEGRAM_TOKEN, deployment yang memakai
    TELEGRAM_BOT — seperti .env di repo ini — akan skip diam-diam dan kita
    mengira sudah teruji padahal belum.
    """
    from minisoar.config import load_env, telegram_config
    load_env()
    return telegram_config().token


_TOKEN = _resolve_token()

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(not _TOKEN, reason="TELEGRAM_TOKEN/TELEGRAM_BOT tidak diset"),
]


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def bot():
    from telegram import Bot
    return Bot(token=_TOKEN)


def test_get_me_token_valid(bot):
    """Token dipakai bot benar-benar hidup dan bisa connect ke api.telegram.org."""
    async def go():
        async with bot:
            return await bot.get_me()

    me = _run(go())
    assert me.is_bot is True
    assert me.username, "bot tidak punya username — token kemungkinan bukan token bot"
    print(f"\n[e2e] bot: @{me.username} (id={me.id})")


def test_commands_registered(bot):
    """post_init() memanggil set_my_commands(). Kalau menu kosong, artinya
    post_init tidak pernah jalan (bot mati / crash saat start)."""
    async def go():
        async with bot:
            return await bot.get_my_commands()

    commands = _run(go())
    names = {c.command for c in commands}
    assert names, "menu command kosong — post_init() belum pernah sukses dijalankan"
    assert "help" in names, f"command /help wajib terdaftar, yang ada: {sorted(names)}"
    print(f"\n[e2e] {len(names)} command terdaftar: {sorted(names)}")


def test_no_webhook_blocking_polling(bot):
    """Penyebab paling umum 'bot tidak merespons': webhook masih terpasang,
    sehingga run_polling() tidak pernah menerima update.

    Default-nya read-only (hanya get_webhook_info). delete_webhook mengubah
    state bot produksi, jadi harus diminta eksplisit lewat
    TELEGRAM_E2E_FIX_WEBHOOK=1.
    """
    fix = os.getenv("TELEGRAM_E2E_FIX_WEBHOOK") == "1"

    async def go():
        async with bot:
            if fix:
                await bot.delete_webhook(drop_pending_updates=False)
            return await bot.get_webhook_info()

    info = _run(go())
    assert not info.url, (
        f"webhook masih terpasang ke {info.url!r} — run_polling() tidak akan menerima update. "
        "Jalankan ulang dengan TELEGRAM_E2E_FIX_WEBHOOK=1 untuk menghapusnya."
    )
    if info.pending_update_count:
        print(f"\n[e2e] ⚠️ {info.pending_update_count} update tertunda di antrian")
    if info.last_error_message:
        print(f"\n[e2e] ⚠️ error webhook terakhir: {info.last_error_message}")


def test_allowed_user_reachable(bot):
    """ALLOWED_USERS[0] harus benar-benar ada di chat yang dipakai bot.
    Butuh TELEGRAM_E2E_CHAT_ID; kalau chat privat, pakai user id itu sendiri.
    """
    from minisoar.config import parse_allowed_users

    allowed = parse_allowed_users(os.getenv("ALLOWED_USERS"))
    if not allowed:
        pytest.skip("ALLOWED_USERS kosong")

    chat_id = os.getenv("TELEGRAM_E2E_CHAT_ID") or allowed[0]

    async def go():
        async with bot:
            return await bot.get_chat_member(chat_id=int(chat_id), user_id=allowed[0])

    member = _run(go())
    assert member.status not in ("left", "kicked"), (
        f"user {allowed[0]} berstatus {member.status} di chat {chat_id} — "
        "dia tidak akan bisa memakai bot walaupun ada di ALLOWED_USERS"
    )
    print(f"\n[e2e] user {allowed[0]} status={member.status} di chat {chat_id}")
