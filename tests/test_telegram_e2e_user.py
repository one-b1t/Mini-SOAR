"""LAPIS 3 — true E2E lewat userbot MTProto (Telethon).

Satu-satunya lapis yang bisa membuktikan auth_guard benar-benar menolak
user sungguhan di server Telegram: login sebagai USER (bukan bot), kirim
command ke bot, lalu baca balasan yang benar-benar dikirim bot.

Telethon TIDAK terpasang di venv proyek ini — file ini importorskip, jadi
kolektor pytest tidak akan error. Pasang manual kalau mau dipakai:
    pip install telethon

Env yang dibutuhkan:
    TELEGRAM_API_ID        dari https://my.telegram.org
    TELEGRAM_API_HASH      dari https://my.telegram.org
    TELEGRAM_SESSION_STRING  StringSession user (lihat cara bikin di bawah)
    TELEGRAM_E2E_BOT       @username bot yang diuji
    TELEGRAM_E2E_CHAT_ID   (opsional) chat tempat mengirim; default: bot itu sendiri

Bikin session string sekali saja, di mesin lokal:
    python3 -c "
    from telethon.sync import TelegramClient
    from telethon.sessions import StringSession
    with TelegramClient(StringSession(), API_ID, 'API_HASH') as c:
        print(c.session.save())"

⚠️ SESSION STRING = kredensial akun Telegram penuh. Simpan di secret store,
jangan commit, jangan taruh di CI yang log-nya publik.

Cara pakai:
    TELEGRAM_API_ID=... TELEGRAM_API_HASH=... TELEGRAM_SESSION_STRING=... \
    TELEGRAM_E2E_BOT=@minisoar_bot \
    PYTHONPATH=.venv/lib/python3.12/site-packages \
    python3 -m pytest tests/test_telegram_e2e_user.py -m e2e -q -s
"""

import asyncio
import os

import pytest

telethon = pytest.importorskip("telethon", reason="telethon tidak terpasang")

from telethon import TelegramClient  # noqa: E402
from telethon.sessions import StringSession  # noqa: E402

REQUIRED_ENV = ("TELEGRAM_API_ID", "TELEGRAM_API_HASH", "TELEGRAM_SESSION_STRING", "TELEGRAM_E2E_BOT")
_missing = [k for k in REQUIRED_ENV if not os.getenv(k)]

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(bool(_missing), reason=f"env userbot belum lengkap: {_missing}"),
]

REPLY_TIMEOUT = float(os.getenv("TELEGRAM_E2E_TIMEOUT", "20"))


def _client():
    return TelegramClient(
        StringSession(os.environ["TELEGRAM_SESSION_STRING"]),
        int(os.environ["TELEGRAM_API_ID"]),
        os.environ["TELEGRAM_API_HASH"],
    )


async def _send_and_wait(client, target, text, timeout=REPLY_TIMEOUT):
    """Kirim satu pesan, kembalikan semua balasan bot dalam jendela `timeout`.

    Bot MiniSOAR sering membalas dua kali (progress + hasil), jadi kita kumpulkan
    semua pesan baru, bukan hanya yang pertama.
    """
    sent = await client.send_message(target, text)
    replies = []
    deadline = asyncio.get_event_loop().time() + timeout

    while asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(1.0)
        async for msg in client.iter_messages(target, min_id=sent.id, reverse=True):
            if not msg.out and msg.text and msg.text not in replies:
                replies.append(msg.text)
        if replies:
            # beri 2 detik ekstra untuk pesan susulan, lalu berhenti
            await asyncio.sleep(2.0)
            async for msg in client.iter_messages(target, min_id=sent.id, reverse=True):
                if not msg.out and msg.text and msg.text not in replies:
                    replies.append(msg.text)
            break

    return replies


def _run_against_bot(text):
    async def go():
        async with _client() as client:
            me = await client.get_me()
            target = os.getenv("TELEGRAM_E2E_CHAT_ID") or os.environ["TELEGRAM_E2E_BOT"]
            if isinstance(target, str) and target.lstrip("-").isdigit():
                target = int(target)
            replies = await _send_and_wait(client, target, text)
            return me, replies

    return asyncio.run(go())


def _user_is_allowed(user_id):
    from minisoar.config import parse_allowed_users
    return user_id in parse_allowed_users(os.getenv("ALLOWED_USERS"))


def test_start_gets_a_reply():
    """Bot hidup dan benar-benar membalas user sungguhan."""
    me, replies = _run_against_bot("/start")
    print(f"\n[e2e-user] as {me.id} (@{me.username}) → {len(replies)} balasan")
    for r in replies:
        print(f"[e2e-user]   {r[:120]!r}")

    assert replies, (
        "bot tidak membalas /start dalam "
        f"{REPLY_TIMEOUT}s — bot mati, atau webhook masih terpasang (cek lapis 2)"
    )

    if _user_is_allowed(me.id):
        assert "tidak punya akses" not in replies[0], \
            f"user {me.id} ADA di ALLOWED_USERS tapi tetap ditolak — auth_guard terlalu ketat"
    else:
        assert "tidak punya akses" in replies[0], \
            f"user {me.id} TIDAK ada di ALLOWED_USERS tapi tidak ditolak — auth_guard bocor"


def test_block_command_respects_auth_guard():
    """Bukti akhir bahwa auth_guard menutup jalur perintah berbahaya.

    Command blokir adalah yang paling perlu dijaga: kalau user asing bisa
    memicunya, dia bisa memblokir IP produksi lewat bot.
    """
    me, replies = _run_against_bot("/block_imperva 1.2.3.4")
    print(f"\n[e2e-user] as {me.id} → {len(replies)} balasan")
    for r in replies:
        print(f"[e2e-user]   {r[:120]!r}")

    assert replies, f"bot tidak membalas /block_imperva dalam {REPLY_TIMEOUT}s"
    joined = " ".join(replies)

    if _user_is_allowed(me.id):
        assert "tidak punya akses" not in joined
        # user sah harus melihat pesan progres, bukan diam atau error internal
        assert "Memproses" in joined or "Imperva" in joined, \
            f"user sah tidak mendapat respons yang bermakna: {replies!r}"
    else:
        assert "tidak punya akses" in joined, \
            f"user {me.id} tidak diizinkan tapi perintah blokir tetap diproses: {replies!r}"
        assert "Memproses" not in joined, \
            "bot sempat memproses blokir sebelum menolak — auth_guard jalan terlalu telat"
