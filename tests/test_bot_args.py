"""LAPIS 1 — unit test handler bot, tanpa jaringan.

File terpisah dari tests/test_bot.py (yang fokus ke auth_guard) supaya dua
pekerjaan tidak saling menimpa. Pola fake Update-nya sama persis: hanya field
yang benar-benar disentuh handler yang dipalsukan, tidak ada objek telegram asli.
"""

import asyncio
from unittest.mock import AsyncMock

import pytest

import minisoar.bot as botmod
from tests.scope_helpers import undefined_names_in_module


def _fake_update(user_id=12345, username="soc_analyst", chat_id=-100123, message_id=555):
    """Update Telegram palsu untuk handler command (bukan callback).

    Menyimpan semua reply ke `update.replies` dan kwargs-nya ke `update.reply_kwargs`.
    """
    replies = []
    reply_kwargs = []

    class _Msg:
        date = None
        message_id = None

        async def reply_text(self, *a, **kw):
            replies.append(a[0] if a else kw.get("text", ""))
            reply_kwargs.append(kw)

    class _Update:
        def __init__(self):
            self.effective_user = type("U", (), {"id": user_id, "username": username})()
            self.effective_chat = type("C", (), {"id": chat_id})()
            self.message = _Msg()
            self.message.message_id = message_id
            self.callback_query = None
            self.replies = replies
            self.reply_kwargs = reply_kwargs

    return _Update()


def _fake_context(*args):
    return type("Ctx", (), {"args": list(args), "bot": AsyncMock()})()


def _run(handler, update, *args):
    return asyncio.run(handler(update, _fake_context(*args)))


# --- validasi argumen: IP malformed ------------------------------------------------

# Perimeter lama: `len(context.args) != 1` — argumen berlebih ditolak.
STRICT_IP_COMMANDS = [
    ("blockonimperva", "block_imperva"),
    ("unblockonimperva", "unblock_imperva"),
    ("blockonpalo", "block_palo"),
    ("unblockonpalo", "unblock_palo"),
    ("blockonakamai", "block_akamai"),
    ("unblockonakamai", "unblock_akamai"),
]

# Perimeter tambahan: `not context.args` — argumen ke-2 dst diam-diam diabaikan.
# Beda perilaku ini disengaja didokumentasikan, bukan diasumsikan benar; lihat
# test_extra_args_behaviour_is_documented di bawah.
LENIENT_IP_COMMANDS = [
    ("blockoncf_cmd", "block_cf"),
    ("unblockoncf_cmd", "unblock_cf"),
    ("blockonforti_cmd", "block_forti"),
    ("unblockonforti_cmd", "unblock_forti"),
]

IP_COMMANDS = STRICT_IP_COMMANDS + LENIENT_IP_COMMANDS


@pytest.mark.parametrize("fn_name,cmd", IP_COMMANDS)
@pytest.mark.parametrize("bad_ip", ["999.999.999.999", "bukan-ip", "192.168.1", "1.2.3.4/24", ""])
def test_ip_command_rejects_malformed_ip(fn_name, cmd, bad_ip):
    """IP ngawur harus berhenti di validasi, tidak boleh nembak API perimeter."""
    update = _fake_update()
    _run(getattr(botmod, fn_name), update, bad_ip)

    assert len(update.replies) == 1, f"{fn_name} harus balas tepat sekali untuk IP invalid"
    assert "Format Tidak Valid" in update.replies[0]
    assert f"/{cmd}" in update.replies[0]
    assert update.reply_kwargs[0].get("parse_mode") == "HTML"


@pytest.mark.parametrize("fn_name,cmd", IP_COMMANDS)
def test_ip_command_rejects_missing_arg(fn_name, cmd):
    """Perintah tanpa argumen sama sekali harus kena usage message, bukan IndexError."""
    update = _fake_update()
    _run(getattr(botmod, fn_name), update)

    assert len(update.replies) == 1
    assert "Format Tidak Valid" in update.replies[0]
    assert f"/{cmd}" in update.replies[0]


@pytest.mark.parametrize("fn_name,cmd", STRICT_IP_COMMANDS)
def test_strict_ip_command_rejects_extra_args(fn_name, cmd):
    """Argumen berlebih ditolak, supaya IP kedua tidak diam-diam diabaikan."""
    update = _fake_update()
    _run(getattr(botmod, fn_name), update, "1.2.3.4", "5.6.7.8")

    assert len(update.replies) == 1
    assert "Format Tidak Valid" in update.replies[0]


@pytest.mark.parametrize("fn_name,cmd", LENIENT_IP_COMMANDS)
def test_lenient_ip_command_ignores_extra_args(fn_name, cmd, monkeypatch):
    """Dokumentasi perilaku, bukan pembenaran: cf/forti hanya cek args[0] jadi
    `/block_cf 1.2.3.4 5.6.7.8` memblokir 1.2.3.4 dan membuang sisanya tanpa
    peringatan. Kalau nanti diseragamkan ke `len(args) != 1`, test ini yang
    pertama merah — pindahkan command-nya ke STRICT_IP_COMMANDS."""
    seen = []
    for mod in (botmod.cloudflare, botmod.fortigate):
        for api in ("block_ip", "unblock_ip"):
            monkeypatch.setattr(mod, api, lambda ip, **kw: seen.append(ip) or (True, "OK"))

    update = _fake_update()
    _run(getattr(botmod, fn_name), update, "1.2.3.4", "5.6.7.8")

    assert seen == ["1.2.3.4"], "hanya argumen pertama yang dipakai, sisanya dibuang diam-diam"
    assert "Format Tidak Valid" not in " ".join(update.replies)


# --- validasi argumen: command non-IP ----------------------------------------------

@pytest.mark.parametrize("fn_name,cmd", [
    ("case_cmd", "case"),
    ("exportcase_cmd", "export_case"),
    ("syncticket_cmd", "sync_ticket"),
    ("whitelist_add_cmd", "whitelist_add"),
    ("whitelist_remove_cmd", "whitelist_remove"),
    ("askai_cmd", "ask_ai"),
    ("rca_cmd", "rca"),
    ("intel_cmd", "intel"),
    ("isolatehost", "isolate_host"),
    ("restorehost", "restore_host"),
    ("queryhost", "query_host"),
    ("addedrioc", "add_edr_ioc"),
])
def test_command_requires_args(fn_name, cmd):
    update = _fake_update()
    _run(getattr(botmod, fn_name), update)

    assert len(update.replies) == 1, f"{fn_name} harus balas usage saat argumen kosong"
    assert "Format Tidak Valid" in update.replies[0]
    assert f"/{cmd}" in update.replies[0]


def test_updatecase_requires_two_args():
    """update_case butuh case_id DAN status; satu argumen saja harus ditolak."""
    update = _fake_update()
    _run(botmod.updatecase_cmd, update, "INC-20260818-001")

    assert len(update.replies) == 1
    assert "Format Tidak Valid" in update.replies[0]
    assert "/update_case" in update.replies[0]


def test_trace_imperva_rejects_zero_and_three_args():
    for args in ([], ["1", "2", "3"]):
        update = _fake_update()
        _run(botmod.tracev, update, *args)
        assert len(update.replies) == 1
        assert "/trace_imperva" in update.replies[0]


# --- format pesan reply -------------------------------------------------------------

def test_usage_message_escapes_html_metachars():
    """Syntax placeholder <ip> harus di-escape, kalau tidak Telegram menolak parse HTML."""
    msg = botmod._format_usage_html("block_imperva", "<ip>", "192.168.1.100")
    assert "<code>/block_imperva &lt;ip&gt;</code>" in msg
    assert "<ip>" not in msg.replace("&lt;ip&gt;", "")


def test_usage_message_omits_description_when_absent():
    msg = botmod._format_usage_html("commit_palo", "", "")
    assert "<i>" not in msg


def test_usage_message_strips_leading_slash():
    """Pemanggil boleh kirim 'block_imperva' atau '/block_imperva', hasilnya sama."""
    assert botmod._format_usage_html("/block_imperva", "<ip>", "1.2.3.4") == \
           botmod._format_usage_html("block_imperva", "<ip>", "1.2.3.4")


def test_parse_callback_payload():
    assert botmod._parse_callback_payload("1.2.3.4|evt-99") == ("1.2.3.4", "evt-99")
    assert botmod._parse_callback_payload("1.2.3.4") == ("1.2.3.4", None)
    # event_id yang sendirinya mengandung '|' tidak boleh terpotong lagi
    assert botmod._parse_callback_payload("1.2.3.4|a|b") == ("1.2.3.4", "a|b")


# --- regresi statis -----------------------------------------------------------------

def test_bot_module_has_no_undefined_names():
    """Regresi refactor auth_guard (BUG 4): blok auth lama yang dihapus juga
    men-set `user = update.effective_user`, tapi 17 handler masih membacanya
    → NameError di happy path. Jalur validasi arg return duluan, jadi test
    validasi di atas TIDAK menangkapnya.

    Sengaja dibuat umum, bukan khusus nama `user`: satu test ini menjaga
    seluruh bot.py dari kelas bug yang sama di refactor berikutnya.
    """
    offenders = undefined_names_in_module(botmod)
    assert offenders == [], (
        "nama dibaca tapi tidak pernah terikat (NameError saat runtime) — "
        f"format fungsi:baris:nama → {offenders}"
    )


def test_block_imperva_happy_path_reaches_mitigation(monkeypatch):
    """Bukti runtime untuk test statis di atas: perintah valid dari user sah
    harus sampai ke trigger_auto_block, bukan meledak duluan."""
    calls = []
    monkeypatch.setattr(botmod, "log_user_action", lambda *a, **kw: None)
    monkeypatch.setattr(botmod, "redis_client", lambda *a, **kw: None)
    monkeypatch.setattr(botmod, "register_block_state", lambda *a, **kw: None)
    monkeypatch.setattr(botmod, "es_find_latest_event_id_by_ip", lambda *a, **kw: "evt-1")
    monkeypatch.setattr(botmod, "store_label", lambda *a, **kw: calls.append(("label",) + a[:2]))
    monkeypatch.setattr(botmod, "trigger_auto_block",
                        lambda ip, target: calls.append(("block", ip, target)) or (True, "OK"))

    update = _fake_update()
    _run(botmod.blockonimperva, update, "1.2.3.4")

    assert ("block", "1.2.3.4", "imperva") in calls
